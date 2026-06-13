#include "../includes/branch_explorer.h"
#include "../includes/detector.h"
#include <future>
#include <chrono>
#include <algorithm>
#include <cmath>

BranchExplorer::BranchExplorer(int max_threads, int timeout_sec)
    : max_threads_(max_threads), timeout_sec_(timeout_sec) {}

bool BranchExplorer::should_branch(
    const std::vector<CipherCandidate> &candidates, double threshold)
{
    if (candidates.size() < 2) return false;
    if (candidates[0].confidence >= 0.85) return false;
    double gap = candidates[0].confidence - candidates[1].confidence;
    return gap < threshold;
}

static double compute_branch_score(
    const CipherCandidate &original,
    const std::vector<CipherCandidate> &sub)
{
    if (sub.empty()) {
        for (auto &s : sub)
            if (s.confidence >= 0.25) return original.confidence * 0.85;
        return original.confidence * 0.85;
    }

    double best_sub = sub[0].confidence;
    std::string best_decrypted = sub[0].decrypted;

    if (best_sub > 0.70 && score_english(best_decrypted) < 30.0)
        return std::min(original.confidence * 1.3, 0.96);

    static const char *encoding_names[] = {
        "hex", "base64", "base32", "binary", "octal", "base58",
        "base85", "large-base", nullptr
    };
    bool sub_is_encoding = false;
    for (const char **p = encoding_names; *p; p++) {
        if (sub[0].cipher_name == *p) {
            sub_is_encoding = true;
            break;
        }
    }
    if (sub_is_encoding)
        return original.confidence * 1.1;

    if (best_decrypted == original.decrypted)
        return original.confidence * 0.80;

    return original.confidence * 0.95;
}

std::vector<BranchResult> BranchExplorer::explore(
    const std::string &,
    const std::vector<CipherCandidate> &candidates,
    int top_n)
{
    std::vector<BranchResult> results;
    if (!should_branch(candidates)) return results;

    int num = std::min(max_threads_, (int)candidates.size());

    std::vector<std::future<std::vector<CipherCandidate>>> futures;
    for (int i = 0; i < num; i++) {
        std::string decoded = candidates[i].decrypted;
        futures.push_back(std::async(std::launch::async, [decoded, top_n]() {
            return detect_cipher(decoded, top_n);
        }));
    }

    for (int i = 0; i < num; i++) {
        BranchResult br;
        br.parent_name = candidates[i].cipher_name;
        br.parent_key = candidates[i].key;
        br.parent_confidence = candidates[i].confidence;
        br.decoded = candidates[i].decrypted;

        auto status = futures[i].wait_for(
            std::chrono::seconds(timeout_sec_));
        if (status == std::future_status::ready) {
            br.sub_candidates = futures[i].get();
            for (auto &sub : br.sub_candidates) {
                sub.was_branched = true;
                sub.confidence = compute_branch_score(candidates[i], br.sub_candidates);
            }
        }
        results.push_back(br);
    }

    return results;
}
