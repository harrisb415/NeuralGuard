// ORT_API_MANUAL_INIT: don't bind OrtGetApiBase at link time. We resolve it at
// runtime from a dynamically-loaded onnxruntime.dll, so the engine has no static
// dependency on the ML runtime (see scorer.h).
#define ORT_API_MANUAL_INIT
#include "core/scorer.h"

#include "core/util.h"
#include "onnxruntime_cxx_api.h"

#include <windows.h>

#include <cmath>
#include <cstdio>
#include <exception>
#include <vector>

namespace ng {

namespace {

// Load onnxruntime.dll once and initialize the C++ API against it. Returns false
// if the DLL isn't present next to the exe. We load by FULL PATH (exe dir), not
// bare name: Windows ships its own onnxruntime.dll for OS ML features, and a
// bare-name load could grab that instead - a different version whose API won't
// match our headers (ORT_API_VERSION). Full path = always our vendored build.
bool EnsureOrt() {
    static const OrtApi* api = nullptr;
    static bool tried = false;
    if (tried) return api != nullptr;
    tried = true;

    wchar_t exePath[MAX_PATH]{};
    if (!GetModuleFileNameW(nullptr, exePath, MAX_PATH)) return false;
    std::wstring dir(exePath);
    size_t sep = dir.find_last_of(L"\\/");
    std::wstring dll = (sep == std::wstring::npos ? L"." : dir.substr(0, sep)) + L"\\onnxruntime.dll";

    HMODULE h = LoadLibraryW(dll.c_str());
    if (!h) return false;
    using GetBaseFn = const OrtApiBase*(ORT_API_CALL*)();
    auto getBase = reinterpret_cast<GetBaseFn>(GetProcAddress(h, "OrtGetApiBase"));
    if (!getBase) return false;
    const OrtApiBase* base = getBase();
    if (!base) return false;
    api = base->GetApi(ORT_API_VERSION);
    if (!api) return false;
    Ort::InitApi(api);
    return true;
}

bool FileExists(const std::string& p) {
    DWORD a = GetFileAttributesW(util::Widen(p).c_str());
    return a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY);
}

}  // namespace

struct AnomalyScorer::Impl {
    std::unique_ptr<Ort::Env> env;
    std::unique_ptr<Ort::Session> session;
    std::string inputName;
    std::string scoreOutput;   // the float 'scores' output (decision_function)
};

AnomalyScorer::AnomalyScorer() : p_(std::make_unique<Impl>()) {}
AnomalyScorer::~AnomalyScorer() = default;

bool AnomalyScorer::load(const std::string& onnxPath) {
    p_->session.reset();
    if (!FileExists(onnxPath)) return false;
    if (!EnsureOrt()) return false;
    try {
        p_->env = std::make_unique<Ort::Env>(ORT_LOGGING_LEVEL_WARNING, "ngd-anomaly");
        Ort::SessionOptions opts;
        opts.SetIntraOpNumThreads(1);
        opts.SetInterOpNumThreads(1);
        p_->session = std::make_unique<Ort::Session>(*p_->env, util::Widen(onnxPath).c_str(), opts);

        Ort::AllocatorWithDefaultOptions alloc;
        p_->inputName = p_->session->GetInputNameAllocated(0, alloc).get();

        // skl2onnx IsolationForest emits label(int64) + scores(float); take the
        // first float output as the anomaly score.
        p_->scoreOutput.clear();
        size_t nout = p_->session->GetOutputCount();
        for (size_t i = 0; i < nout; ++i) {
            auto info = p_->session->GetOutputTypeInfo(i);
            if (info.GetTensorTypeAndShapeInfo().GetElementType() ==
                ONNX_TENSOR_ELEMENT_DATA_TYPE_FLOAT) {
                p_->scoreOutput = p_->session->GetOutputNameAllocated(i, alloc).get();
                break;
            }
        }
        if (p_->scoreOutput.empty()) { p_->session.reset(); return false; }
        return true;
    } catch (const std::exception& e) {
        fprintf(stderr, "anomaly model load failed: %s\n", e.what());
        p_->session.reset();
        return false;
    }
}

bool AnomalyScorer::loaded() const { return p_ && p_->session != nullptr; }

float AnomalyScorer::score(const FlowFeatureInput& in) {
    if (!loaded()) return 0.0f;
    const long long total = in.bytesIn + in.bytesOut;
    float feats[8] = {
        std::log1p(static_cast<float>(in.durationMs)),
        std::log1p(static_cast<float>(in.bytesIn)),
        std::log1p(static_cast<float>(in.bytesOut)),
        static_cast<float>(static_cast<double>(in.bytesOut) / static_cast<double>(total + 1)),
        in.remotePort == 443 ? 1.0f : 0.0f,
        in.remotePort == 80 ? 1.0f : 0.0f,
        in.isSigned ? 1.0f : 0.0f,
        static_cast<float>(in.hour),
    };
    try {
        Ort::MemoryInfo mem = Ort::MemoryInfo::CreateCpu(OrtDeviceAllocator, OrtMemTypeCPU);
        int64_t shape[2] = { 1, 8 };
        Ort::Value input = Ort::Value::CreateTensor<float>(mem, feats, 8, shape, 2);
        const char* inNames[1]  = { p_->inputName.c_str() };
        const char* outNames[1] = { p_->scoreOutput.c_str() };
        auto out = p_->session->Run(Ort::RunOptions{ nullptr }, inNames, &input, 1, outNames, 1);
        const float* s = out[0].GetTensorData<float>();
        return s[0];
    } catch (const std::exception&) {
        return 0.0f;
    }
}

}  // namespace ng
