#ifndef NTL_BRIDGE_H
#define NTL_BRIDGE_H

#include <string>
#include <vector>

bool ntl_rsa_decrypt(const std::string &c_hex, const std::string &d_hex,
                     const std::string &n_hex, std::string &m_hex,
                     std::string &error_msg);

bool ntl_rsa_wiener(const std::string &e_hex, const std::string &n_hex,
                    std::string &d_hex, std::string &error_msg);

bool ntl_rsa_hastad(const std::vector<std::string> &c_hex_list,
                    const std::vector<std::string> &n_hex_list, int e,
                    std::string &m_hex, std::string &error_msg);

bool ntl_ec_add(const std::string &x1_hex, const std::string &y1_hex,
                const std::string &x2_hex, const std::string &y2_hex,
                const std::string &a_hex, const std::string &p_hex,
                std::string &xr_hex, std::string &yr_hex,
                std::string &error_msg);

bool ntl_ec_scalar_mul(const std::string &k_hex,
                       const std::string &x_hex, const std::string &y_hex,
                       const std::string &a_hex, const std::string &p_hex,
                       std::string &xr_hex, std::string &yr_hex,
                       std::string &error_msg);

bool ntl_bsgs(const std::string &g_hex, const std::string &h_hex,
              const std::string &p_hex, std::string &x_hex,
              std::string &error_msg);

bool ntl_pohlig_hellman(const std::string &g_hex, const std::string &h_hex,
                        const std::string &p_hex, std::string &x_hex,
                        std::string &error_msg);

bool ntl_lll(const std::vector<std::vector<std::string>> &rows_hex,
             std::vector<std::vector<std::string>> &out_hex,
             std::string &error_msg);

#endif
