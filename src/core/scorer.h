// Phase 4b - on-device anomaly scorer (shadow mode).
//
// Loads an ONNX Isolation Forest (from scripts/train_anomaly.py) and scores a
// completed flow's feature vector with ONNX Runtime. It produces a number, not
// a verdict - shadow mode only, off the decision path.
//
// ONNX Runtime is an OPTIONAL runtime dependency: the scorer loads
// onnxruntime.dll dynamically, so if it (or the model) is missing, scoring is
// simply disabled and the rest of ngd - enforce, record, feature collection,
// panic - is unaffected. Nothing in the engine's core path links against it.
//
// The feature order below is the contract with scripts/train_anomaly.py's
// FEATURE_NAMES; the two must match exactly or scores are garbage.
#pragma once

#include <memory>
#include <string>

namespace ng {

struct FlowFeatureInput {
    int       durationMs = 0;
    long long bytesIn = 0;
    long long bytesOut = 0;
    int       remotePort = 0;
    bool      isSigned = false;   // process_key starts with "sig:"
    int       hour = 0;           // UTC hour-of-day 0-23
};

class AnomalyScorer {
public:
    AnomalyScorer();
    ~AnomalyScorer();
    AnomalyScorer(const AnomalyScorer&) = delete;
    AnomalyScorer& operator=(const AnomalyScorer&) = delete;

    // Returns false if onnxruntime.dll can't be loaded or the model file is
    // missing/invalid; scoring is then disabled and the caller carries on.
    bool  load(const std::string& onnxPath);
    bool  loaded() const;
    float score(const FlowFeatureInput& f);   // lower = more anomalous; 0 if !loaded

private:
    struct Impl;                 // hides the Ort:: types from every other TU
    std::unique_ptr<Impl> p_;
};

}  // namespace ng
