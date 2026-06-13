#include "../includes/register_handlers.h"
#include "../includes/bytes.h"

void register_bytes_handlers(HandlerMap &map) {
    map["little-endian"] = [](const Context &ctx) {
        long long val = std::atoll(ctx.input.c_str());
        int bytes = ctx.opt_int_flag("--len", 4);
        std::string out;
        little_endian_encode(val, out, bytes);
        print_result(ctx, out);
    };

    map["big-endian"] = [](const Context &ctx) {
        long long val = std::atoll(ctx.input.c_str());
        int bytes = ctx.opt_int_flag("--len", 4);
        std::string out;
        big_endian_encode(val, out, bytes);
        print_result(ctx, out);
    };

    map["proper-base"] = [](const Context &ctx) {
        int bits = ctx.int_flag("--bits");
        std::string alpha = ctx.opt_flag("-k",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/");
        std::string out;
        proper_base_convert(ctx.input, out, bits, alpha);
        print_result(ctx, out);
    };
}
