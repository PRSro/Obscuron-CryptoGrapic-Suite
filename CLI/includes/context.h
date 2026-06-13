#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <functional>
#include <stdexcept>
#include <iostream>
#include <sstream>
#include <fstream>
#include <cstdlib>
#include <cstring>
#include <cctype>
#include <unistd.h>
#include <algorithm>
#include "basic_ciphers.h"

class CipherError : public std::runtime_error {
public:
    explicit CipherError(const std::string &msg) : std::runtime_error(msg) {}
};

struct Context {
    std::string mode;
    std::string input;
    bool raw = false;
    bool hex_output = false;

    std::vector<std::string> args;

    static std::string alt_flag(const std::string &n) {
        if (n.size() >= 2 && n[0] == '-' && n[1] != '-') return "-" + n;
        if (n.size() >= 3 && n[0] == '-' && n[1] == '-') return n.substr(1);
        return "";
    }

    static bool match_flag_arg(const std::string &arg, const std::string &name) {
        if (arg == name) return true;
        std::string alt = alt_flag(name);
        return !alt.empty() && arg == alt;
    }

    static bool match_flag_value(const std::string &arg, const std::string &name, std::string &value) {
        if (arg.size() > name.size() + 1 && arg[name.size()] == '='
            && arg.substr(0, name.size()) == name) {
            value = arg.substr(name.size() + 1);
            return true;
        }
        std::string alt = alt_flag(name);
        if (!alt.empty() && arg.size() > alt.size() + 1 && arg[alt.size()] == '='
            && arg.substr(0, alt.size()) == alt) {
            value = arg.substr(alt.size() + 1);
            return true;
        }
        return false;
    }

    std::string flag(const std::string &name) const {
        for (size_t j = 0; j + 1 < args.size(); j++)
            if (match_flag_arg(args[j], name)) return args[j + 1];
        for (const auto &a : args) {
            std::string v;
            if (match_flag_value(a, name, v)) return v;
        }
        throw CipherError("missing value for " + name);
    }

    bool has(const std::string &name) const {
        for (const auto &a : args)
            if (match_flag_arg(a, name)) return true;
        for (const auto &a : args) {
            std::string v;
            if (match_flag_value(a, name, v)) return true;
        }
        return false;
    }

    std::string opt_flag(const std::string &name, const std::string &def = "") const {
        for (size_t j = 0; j + 1 < args.size(); j++)
            if (match_flag_arg(args[j], name)) return args[j + 1];
        for (const auto &a : args) {
            std::string v;
            if (match_flag_value(a, name, v)) return v;
        }
        return def;
    }

    int int_flag(const std::string &name) const {
        return std::atoi(flag(name).c_str());
    }

    int opt_int_flag(const std::string &name, int def = 0) const {
        return has(name) ? std::atoi(flag(name).c_str()) : def;
    }

    double opt_double_flag(const std::string &name, double def = 0.0) const {
        if (!has(name)) return def;
        std::string val = flag(name);
        char *end = nullptr;
        double result = std::strtod(val.c_str(), &end);
        if (end == val.c_str()) return def;
        return result;
    }
};

using HandlerMap = std::unordered_map<std::string, std::function<void(const Context&)>>;

inline std::string hex_encode_str(const std::string &bytes) {
    std::string out;
    for (unsigned char ch : bytes) {
        std::string part;
        base_convert((long long)ch, part, 16);
        if (part.size() == 1) out += '0';
        out += part;
    }
    return out;
}

inline std::string hex_decode_str(const std::string &hex) {
    std::string clean;
    for (unsigned char ch : hex)
        if (!std::isspace(ch)) clean += ch;
    if (clean.size() >= 2 && clean[0] == '0' && (clean[1] == 'x' || clean[1] == 'X'))
        clean = clean.substr(2);
    if (clean.size() % 2 == 1)
        clean = "0" + clean;
    std::string out;
    for (size_t i = 0; i < clean.size(); i += 2) {
        std::string pair = {clean[i], clean[i + 1]};
        long long val;
        base_deconvert(pair, val, 16);
        out += (char)(unsigned char)val;
    }
    return out;
}

inline std::string format_output(const std::string &data, bool hex_output) {
    if (hex_output) return hex_encode_str(data);
    return data;
}

inline void print_result(const Context &ctx, const std::string &out) {
    std::cout << format_output(out, ctx.hex_output);
    if (!ctx.raw) std::cout << "\n";
}

std::string read_file(const std::string &path);
std::string read_stdin();
Context parse_args(int argc, char *argv[]);
