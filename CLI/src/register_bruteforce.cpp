#include "../includes/register_handlers.h"
#include "../includes/bruteforce_ciphers.h"
#include "../includes/detector.h"
#include "../includes/thread_pool.h"
#include <algorithm>
#include <thread>

void register_bruteforce_handlers(HandlerMap &map) {
    map["brute-rotate"] = [](const Context &ctx) {
        for (int shift = 0; shift < 26; shift++) {
            std::string out;
            custom_rot(ctx.input, shift, out);
            std::cout << shift << ": " << out << "\n";
        }
    };

    map["brute-caesar"] = [](const Context &ctx) {
        const int total = 25;
        int nthreads = ctx.opt_int_flag("--threads",
            (int)std::thread::hardware_concurrency());
        if (nthreads < 1) nthreads = 1;
        nthreads = std::min(nthreads, total);
        ThreadPool pool(nthreads);
        int chunk = (total + nthreads - 1) / nthreads;
        std::vector<std::future<std::vector<std::pair<int,std::string>>>> futures;
        for (int start = 0; start < total; start += chunk) {
            int end = std::min(start + chunk, total);
            futures.push_back(pool.enqueue([start, end, &ctx]() {
                std::vector<std::pair<int,std::string>> part;
                part.reserve(end - start);
                for (int s = start; s < end; s++) {
                    std::string out;
                    custom_rot(ctx.input, s + 1, out);
                    part.push_back({s, out});
                }
                return part;
            }));
        }
        std::vector<std::pair<int,std::string>> all;
        for (auto &f : futures) {
            auto part = f.get();
            all.insert(all.end(), part.begin(), part.end());
        }
        std::sort(all.begin(), all.end());
        for (auto &p : all)
            std::cout << (p.first + 1) << ": " << p.second << "\n";
    };

    map["brute-railfence"] = [](const Context &ctx) {
        int max_k = ctx.opt_int_flag("--max", 10);
        std::vector<std::pair<int,int>> work;
        for (int key = 2; key <= max_k; key++)
            for (int offset = 0; offset < 2 * (key - 1); offset++)
                work.push_back({key, offset});
        int nthreads = ctx.opt_int_flag("--threads",
            (int)std::thread::hardware_concurrency());
        if (nthreads < 1) nthreads = 1;
        nthreads = std::min(nthreads, (int)work.size());
        ThreadPool pool(nthreads);
        int chunk = ((int)work.size() + nthreads - 1) / nthreads;
        std::vector<std::future<std::vector<std::string>>> futures;
        for (int start = 0; start < (int)work.size(); start += chunk) {
            int end = std::min(start + chunk, (int)work.size());
            futures.push_back(pool.enqueue([start, end, &work, &ctx]() {
                std::vector<std::string> part;
                part.reserve(end - start);
                for (int i = start; i < end; i++) {
                    std::string out;
                    railfence(ctx.input, out, work[i].first, work[i].second);
                    part.push_back(out);
                }
                return part;
            }));
        }
        std::vector<std::string> all;
        for (auto &f : futures) {
            auto part = f.get();
            all.insert(all.end(), part.begin(), part.end());
        }
        for (size_t j = 0; j < all.size(); j++)
            std::cout << (j + 1) << ": " << all[j] << "\n";
    };

    map["brute-xor"] = [](const Context &ctx) {
        const int total = 256;
        int nthreads = ctx.opt_int_flag("--threads",
            (int)std::thread::hardware_concurrency());
        if (nthreads < 1) nthreads = 1;
        nthreads = std::min(nthreads, total);
        ThreadPool pool(nthreads);
        int chunk = (total + nthreads - 1) / nthreads;
        std::vector<std::future<std::vector<std::pair<int,std::string>>>> futures;
        for (int start = 0; start < total; start += chunk) {
            int end = std::min(start + chunk, total);
            futures.push_back(pool.enqueue([start, end, &ctx]() {
                std::vector<std::pair<int,std::string>> part;
                part.reserve(end - start);
                for (int k = start; k < end; k++) {
                    std::string out;
                    str_xor(ctx.input, std::string(ctx.input.length(), (char)k), out);
                    part.push_back({k, out});
                }
                return part;
            }));
        }
        std::vector<std::pair<int,std::string>> all;
        for (auto &f : futures) {
            auto part = f.get();
            all.insert(all.end(), part.begin(), part.end());
        }
        std::sort(all.begin(), all.end());
        for (auto &p : all)
            std::cout << p.first << ": " << p.second << "\n";
    };

    map["brute-vigenere"] = [](const Context &ctx) {
        int max_len = ctx.opt_int_flag("--max", 10);
        std::vector<int> lengths;
        find_key_lengths(ctx.input, lengths, max_len);
        if (lengths.empty()) {
            for (int len = 2; len <= max_len; len++)
                lengths.push_back(len);
        }
        int nthreads = ctx.opt_int_flag("--threads",
            (int)std::thread::hardware_concurrency());
        if (nthreads < 1) nthreads = 1;
        nthreads = std::min(nthreads, (int)lengths.size());
        ThreadPool pool(nthreads);
        static const double eng_freq[26] = {
            8.167, 1.492, 2.782, 4.253, 12.702, 2.228, 2.015, 6.094,
            6.966, 0.153, 0.772, 4.025, 2.406, 6.749, 7.507, 1.929,
            0.095, 5.987, 6.327, 9.056, 2.758, 0.978, 2.360, 0.150,
            1.974, 0.074
        };
        double eng_sum = 0;
        for (int i = 0; i < 26; i++) eng_sum += eng_freq[i];
        double eng_prob[26];
        for (int i = 0; i < 26; i++) eng_prob[i] = eng_freq[i] / eng_sum;
        int chunk = ((int)lengths.size() + nthreads - 1) / nthreads;
        std::vector<std::future<std::vector<std::string>>> futures;
        for (int start = 0; start < (int)lengths.size(); start += chunk) {
            int end = std::min(start + chunk, (int)lengths.size());
            futures.push_back(pool.enqueue([start, end, &lengths, &ctx, eng_prob]() {
                std::vector<std::string> part;
                for (int li = start; li < end; li++) {
                    int keylen = lengths[li];
                    if (keylen < 2) continue;
                    std::string clean;
                    for (char c : ctx.input) {
                        if (c >= 'a' && c <= 'z') clean += c;
                        else if (c >= 'A' && c <= 'Z')
                            clean += (char)(c - 'A' + 'a');
                    }
                    if ((int)clean.length() < keylen * 2) continue;
                    std::string key;
                    for (int pos = 0; pos < keylen; pos++) {
                        int counts[26] = {0};
                        int total = 0;
                        for (int j = pos; j < (int)clean.length(); j += keylen) {
                            counts[clean[j] - 'a']++;
                            total++;
                        }
                        if (total == 0) { key += 'a'; continue; }
                        double best_score = -1e9;
                        int best_shift = 0;
                        for (int shift = 0; shift < 26; shift++) {
                            double score = 0.0;
                            for (int pt = 0; pt < 26; pt++) {
                                int ct = (pt + shift) % 26;
                                score += eng_prob[pt] * counts[ct];
                            }
                            if (score > best_score) {
                                best_score = score;
                                best_shift = shift;
                            }
                        }
                        key += (char)('a' + best_shift);
                    }
                    std::string out;
                    vigenere(ctx.input, key, out, false);
                    part.push_back(out);
                }
                return part;
            }));
        }
        std::vector<std::string> all;
        for (auto &f : futures) {
            auto part = f.get();
            all.insert(all.end(), part.begin(), part.end());
        }
        for (size_t j = 0; j < all.size(); j++)
            std::cout << (j + 1) << ": " << all[j] << "\n";
    };
}
