#include "core/iforest.h"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <functional>

namespace ng {
namespace {

// Small deterministic PRNG (xorshift64*), so training is reproducible from a seed
// and we don't drag in <random>'s weight for a couple of uniforms per split.
struct Rng {
    std::uint64_t s;
    explicit Rng(std::uint64_t seed) : s(seed ? seed : 0x9E3779B97F4A7C15ULL) {}
    std::uint64_t next() { s ^= s << 13; s ^= s >> 7; s ^= s << 17; return s; }
    int below(int n) { return n > 0 ? (int)(next() % (std::uint64_t)n) : 0; }
    float unit() { return (float)((next() >> 11) * (1.0 / 9007199254740992.0)); }  // [0,1)
};

// c(n): expected path length of an unsuccessful search in a binary search tree of
// n points - the standard Isolation Forest normalization / leaf correction.
double cFactor(int n) {
    if (n <= 1) return 0.0;
    if (n == 2) return 1.0;
    const double H = std::log((double)(n - 1)) + 0.5772156649015329;  // + Euler-Mascheroni
    return 2.0 * H - 2.0 * (double)(n - 1) / (double)n;
}

constexpr char kMagic[4] = { 'N', 'G', 'I', 'F' };
constexpr std::uint32_t kVersion = 1;

}  // namespace

bool IsolationForest::train(const std::vector<float>& X, std::size_t nRows,
                            int nTrees, int sampleSize, std::uint64_t seed) {
    trees_.clear();
    rowsTrained_ = nRows;
    if (nRows == 0) return false;

    sampleSize_ = std::min<int>(sampleSize, (int)nRows);
    if (sampleSize_ < 1) sampleSize_ = 1;
    cPsi_ = (float)cFactor(sampleSize_);
    const int maxDepth = std::max(1, (int)std::ceil(std::log2((double)sampleSize_)));
    const float* data = X.data();

    // Persistent index buffer; each tree partial-shuffles the first sampleSize_
    // entries to the front (sampling without replacement, O(sampleSize) per tree).
    std::vector<int> idx(nRows);
    for (std::size_t i = 0; i < nRows; ++i) idx[i] = (int)i;

    trees_.resize(nTrees);
    for (int t = 0; t < nTrees; ++t) {
        Rng rng(seed + (std::uint64_t)t * 0x9E3779B97F4A7C15ULL);
        for (int i = 0; i < sampleSize_; ++i) {
            int j = i + rng.below((int)nRows - i);
            std::swap(idx[i], idx[j]);
        }
        std::vector<int> sample(idx.begin(), idx.begin() + sampleSize_);

        Tree& tree = trees_[t];
        tree.nodes.reserve(sampleSize_ * 2);

        // Build recursively, writing nodes into the flat array by stable index
        // (indices stay valid across the vector's reallocations; references would not).
        std::function<int(std::vector<int>&, int)> build =
            [&](std::vector<int>& rows, int depth) -> int {
            const int self = (int)tree.nodes.size();
            if (depth >= maxDepth || rows.size() <= 1) {
                tree.nodes.push_back({ -1, 0.0f, -1, -1, (int)rows.size() });
                return self;
            }
            const int q = rng.below(IsolationForest::kFeatures);
            float lo = data[(std::size_t)rows[0] * kFeatures + q], hi = lo;
            for (int r : rows) {
                float v = data[(std::size_t)r * kFeatures + q];
                if (v < lo) lo = v; if (v > hi) hi = v;
            }
            if (hi <= lo) {   // feature constant here - can't split
                tree.nodes.push_back({ -1, 0.0f, -1, -1, (int)rows.size() });
                return self;
            }
            const float split = lo + rng.unit() * (hi - lo);
            std::vector<int> left, right;
            left.reserve(rows.size()); right.reserve(rows.size());
            for (int r : rows)
                (data[(std::size_t)r * kFeatures + q] < split ? left : right).push_back(r);
            if (left.empty() || right.empty()) {
                tree.nodes.push_back({ -1, 0.0f, -1, -1, (int)rows.size() });
                return self;
            }
            tree.nodes.push_back({ q, split, -1, -1, 0 });   // placeholder; children set below
            const int l = build(left, depth + 1);
            const int r = build(right, depth + 1);
            tree.nodes[self].left = l;
            tree.nodes[self].right = r;
            return self;
        };
        build(sample, 0);
    }
    return true;
}

float IsolationForest::score(const float* x) const {
    if (trees_.empty() || cPsi_ <= 0.0f) return 0.0f;
    double sumPath = 0.0;
    for (const Tree& tree : trees_) {
        int n = 0;          // node index
        double pathLen = 0.0;
        for (;;) {
            const Node& nd = tree.nodes[n];
            if (nd.feature < 0) { pathLen += cFactor(nd.size); break; }  // leaf
            pathLen += 1.0;
            n = (x[nd.feature] < nd.split) ? nd.left : nd.right;
        }
        sumPath += pathLen;
    }
    const double avg = sumPath / (double)trees_.size();
    const double s = std::pow(2.0, -avg / (double)cPsi_);   // standard IF score in [0,1]
    return (float)(0.5 - s);   // sklearn decision_function (auto contamination): lower = more anomalous
}

bool IsolationForest::save(const std::string& path) const {
    FILE* f = nullptr;
    if (fopen_s(&f, path.c_str(), "wb") != 0 || !f) return false;
    auto wr = [&](const void* p, std::size_t n) { fwrite(p, 1, n, f); };
    std::uint32_t nTrees = (std::uint32_t)trees_.size();
    std::int32_t feats = kFeatures, psi = sampleSize_;
    wr(kMagic, 4); wr(&kVersion, 4); wr(&feats, 4); wr(&psi, 4);
    wr(&rowsTrained_, 8); wr(&nTrees, 4);
    for (const Tree& tree : trees_) {
        std::uint32_t nn = (std::uint32_t)tree.nodes.size();
        wr(&nn, 4);
        wr(tree.nodes.data(), tree.nodes.size() * sizeof(Node));
    }
    fclose(f);
    return true;
}

bool IsolationForest::load(const std::string& path) {
    trees_.clear();
    FILE* f = nullptr;
    if (fopen_s(&f, path.c_str(), "rb") != 0 || !f) return false;
    auto rd = [&](void* p, std::size_t n) { return fread(p, 1, n, f) == n; };
    char magic[4]; std::uint32_t ver = 0, nTrees = 0; std::int32_t feats = 0, psi = 0;
    bool ok = rd(magic, 4) && std::memcmp(magic, kMagic, 4) == 0 &&
              rd(&ver, 4) && ver == kVersion &&
              rd(&feats, 4) && feats == kFeatures &&
              rd(&psi, 4) && rd(&rowsTrained_, 8) && rd(&nTrees, 4);
    if (ok) {
        sampleSize_ = psi;
        cPsi_ = (float)cFactor(sampleSize_);
        trees_.resize(nTrees);
        for (std::uint32_t t = 0; ok && t < nTrees; ++t) {
            std::uint32_t nn = 0;
            if (!rd(&nn, 4)) { ok = false; break; }
            trees_[t].nodes.resize(nn);
            if (nn && !rd(trees_[t].nodes.data(), (std::size_t)nn * sizeof(Node))) ok = false;
        }
    }
    fclose(f);
    if (!ok) trees_.clear();
    return ok;
}

std::vector<float> anomalyFeatures(long long durationMs, long long bytesIn, long long bytesOut,
                                   int remotePort, bool signedProc, int hourUtc) {
    if (durationMs < 0) durationMs = 0;
    if (bytesIn < 0) bytesIn = 0;
    if (bytesOut < 0) bytesOut = 0;
    const long long total = bytesIn + bytesOut;
    return {
        std::log1p((float)durationMs),
        std::log1p((float)bytesIn),
        std::log1p((float)bytesOut),
        (float)((double)bytesOut / (double)(total + 1)),   // out_ratio (exfil signal)
        remotePort == 443 ? 1.0f : 0.0f,                   // is_https
        remotePort == 80 ? 1.0f : 0.0f,                    // is_http
        signedProc ? 1.0f : 0.0f,                          // is_signed
        (float)hourUtc,                                    // UTC hour-of-day
    };
}

}  // namespace ng
