// Phase 4b - native on-device Isolation Forest for the anomaly tier.
//
// Replaces the Python-trained ONNX anomaly model (train_anomaly.py + skl2onnx)
// so the app can train on its OWN behavior with no external toolchain - the
// whole point being an end user has no Python/scikit-learn. Isolation Forest is
// simple enough to implement directly: random binary trees, and the anomaly
// score is a point's average path length across them (short path = isolated =
// anomalous). No linear algebra, no ONNX, no runtime DLL for this tier.
//
// score() is on scikit-learn's decision_function scale under auto contamination
// (returns 0.5 - s, where s in [0,1] is the standard IF anomaly score): LOWER =
// more anomalous, ~0 = borderline. That's the same convention the rest of the
// engine already assumes, so ml_anomaly_threshold (-0.15), the ml_flags gate,
// and the Insights display all keep working unchanged.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace ng {

class IsolationForest {
public:
    static constexpr int kFeatures = 8;   // must match train_anomaly.py FEATURE_NAMES

    // Train on `nRows` rows of `kFeatures` floats each, row-major in `rowsFlat`.
    // Returns false if there's nothing to train on. sampleSize is the per-tree
    // subsample (Isolation Forest's psi; 256 is the canonical default).
    bool train(const std::vector<float>& rowsFlat, std::size_t nRows,
               int nTrees = 200, int sampleSize = 256, std::uint64_t seed = 0x9E3779B97F4A7C15ULL);

    // decision_function-equivalent for one row (kFeatures floats). Lower = more
    // anomalous. Returns 0 if the forest isn't loaded.
    float score(const float* x) const;
    float score(const std::vector<float>& x) const { return score(x.data()); }

    bool loaded() const { return !trees_.empty(); }

    // Binary model file (magic + version + params + flat node arrays).
    bool save(const std::string& path) const;
    bool load(const std::string& path);

    std::size_t treeCount() const { return trees_.size(); }
    unsigned long long rowsTrained() const { return rowsTrained_; }

private:
    // Flat node. Leaf when feature < 0 (then `size` = points that reached it, used
    // for the c(size) path-length correction). Internal: split on feature at value
    // `split`, recurse to child indices `left`/`right`.
    struct Node { int feature; float split; int left; int right; int size; };
    struct Tree { std::vector<Node> nodes; };

    std::vector<Tree> trees_;
    int sampleSize_ = 256;
    float cPsi_ = 0.0f;                 // c(sampleSize): path-length normalization
    unsigned long long rowsTrained_ = 0;
};

// The single definition of the 8-feature anomaly vector, shared by the collector
// (scoring, flowstats.cpp) and the trainer so the two can never drift. Order is
// the contract with train_anomaly.py FEATURE_NAMES.
std::vector<float> anomalyFeatures(long long durationMs, long long bytesIn, long long bytesOut,
                                   int remotePort, bool signedProc, int hourUtc);

}  // namespace ng
