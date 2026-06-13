#include "../includes/register_handlers.h"
#include "../includes/standard_ciphers.h"

void register_standard_handlers(HandlerMap &map) {
    map["rot47"] = [](const Context &ctx) {
        std::string out;
        rot47(ctx.input, out);
        print_result(ctx, out);
    };

    map["keyword"] = [](const Context &ctx) {
        std::string out;
        keyword_cipher(ctx.input, out, ctx.flag("-k"), !ctx.has("--decrypt"));
        print_result(ctx, out);
    };

    map["substitution"] = [](const Context &ctx) {
        std::string out;
        if (ctx.has("--decrypt"))
            substitution_decrypt(ctx.input, out, ctx.flag("-k"));
        else
            substitution_encrypt(ctx.input, out, ctx.flag("-k"));
        print_result(ctx, out);
    };

    map["substitution-solve"] = [](const Context &ctx) {
        std::string out, mapping;
        substitution_solve(ctx.input, out, mapping);
        std::cout << "mapping: " << mapping << "\n";
        std::cout << out;
        if (!ctx.raw) std::cout << "\n";
    };
}
