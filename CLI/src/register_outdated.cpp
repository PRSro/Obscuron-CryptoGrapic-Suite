#include "../includes/register_handlers.h"
#include "../includes/outdated_ciphers.h"

void register_outdated_handlers(HandlerMap &map) {
    map["rc4"] = [](const Context &ctx) {
        std::string out;
        rc4(ctx.input, out, ctx.flag("-k"));
        print_result(ctx, out);
    };

    map["des"] = [](const Context &ctx) {
        std::string k = hex_decode_str(ctx.flag("-k"));
        std::string out;
        des_ecb(ctx.input, out, k, ctx.has("--decrypt"));
        print_result(ctx, out);
    };

    map["des3"] = [](const Context &ctx) {
        std::string k = hex_decode_str(ctx.flag("-k"));
        std::string out;
        des3_ecb(ctx.input, out, k, ctx.has("--decrypt"));
        print_result(ctx, out);
    };

    map["blowfish"] = [](const Context &ctx) {
        std::string out;
        blowfish_ecb(ctx.input, out, ctx.flag("-k"), ctx.has("--decrypt"));
        print_result(ctx, out);
    };
}
