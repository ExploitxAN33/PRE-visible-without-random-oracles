// crypto_utils.h
#include <pbc/pbc.h>

class CryptoUtils {
public:
    static void init_pairing(pairing_t& pairing, const char* param_path);
    static void generate_keys(element_t& sk, element_t& pk, element_t g, pairing_t pairing);
    static void re_key_gen(element_t& rk, element_t sk_owner, element_t pk_user, pairing_t pairing);
    static void encrypt_second_level(element_t& c1, element_t& c2, element_t m, element_t pk, element_t g, pairing_t pairing);
    static void re_encrypt(element_t& c1_re, element_t& c2_re, element_t c1, element_t c2, element_t rk, pairing_t pairing);
    static void decrypt(element_t& m, element_t c1, element_t c2, element_t sk, pairing_t pairing);
};
