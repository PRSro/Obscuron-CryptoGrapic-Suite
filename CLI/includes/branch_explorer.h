#pragma once
#include "detector.h"
#include <vector>

struct BranchResult {
    std::string parent_name;
    std::string parent_key;
    double parent_confidence;
    std::string decoded;
    std::vector<CipherCandidate> sub_candidates;
};

class BranchExplorer {
public:
    explicit BranchExplorer(int max_threads = 2, int timeout_sec = 3);
    std::vector<BranchResult> explore(
        const std::string &input,
        const std::vector<CipherCandidate> &candidates,
        int top_n);
    static bool should_branch(const std::vector<CipherCandidate> &candidates,
                               double threshold = 0.15);
private:
    int max_threads_;
    int timeout_sec_;
};
