// Phase 4 - on-device ONNX model scoring (shadow mode).
//
// Loads an ONNX model and runs it on a feature vector. Deliberately generic: the
// caller builds the right vector (matching the trainer's FEATURE_NAMES) and
// interprets the output. Used for both the anomaly model (train_anomaly.py, 8
// features, output = one score) and the supervised classifier
// (train_supervised.py, 6 features, output = [P(benign), P(malicious)]).
//
// ONNX Runtime is an OPTIONAL runtime dependency: the DLL is loaded dynamically
// by full path, so if it (or the model) is missing, load() just returns false
// and the rest of ngd - enforce, record, feature collection, panic - is
// unaffected. Nothing in the engine's core path links against it. (pImpl keeps
// the Ort:: types out of every other translation unit.)
#pragma once

#include <memory>
#include <string>
#include <vector>

namespace ng {

class OnnxModel {
public:
    OnnxModel();
    ~OnnxModel();
    OnnxModel(const OnnxModel&) = delete;
    OnnxModel& operator=(const OnnxModel&) = delete;

    // Returns false if onnxruntime.dll can't be loaded or the model file is
    // missing/invalid; the model then stays unloaded and the caller carries on.
    bool load(const std::string& onnxPath);
    bool loaded() const;

    // Runs the model on `feats` (one row) and returns the first float output's
    // values: [score] for the anomaly model, [P(benign), P(malicious)] for the
    // classifier. Empty if not loaded or on error.
    std::vector<float> run(const std::vector<float>& feats);

private:
    struct Impl;
    std::unique_ptr<Impl> p_;
};

}  // namespace ng
