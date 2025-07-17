#ifndef PRE_SCHEME_H
#define PRE_SCHEME_H

#include <pbc/pbc.h>
#include <string>

class PREContext {
public:
    PREContext(const char* param_path);
    ~PREContext();

    // Key generation for user (i or j)
    void generate_user_keys();
    
    void generate_owner_keys();
    // Encryption: outputs (C1, C2, C3, C4, C5)
    void encrypt(element_t& C1, element_t& C2, element_t& C3, element_t& C4, element_t& C5,
                 element_t m, element_t alpha, element_t beta);

    // Re-encryption key generation: rk_{i->j}
    void generate_rekey(element_t& rk, element_t pk1i,element_t  beta_i, element_t pk3j, element_t alpha_i);
    // Re-encryption: outputs (C1', C2', C3')
    void re_encrypt(element_t& C1p, element_t& C2p, element_t& C3p,
                    element_t C1, element_t C2, element_t C3, element_t C4, element_t C5, element_t rk);

    // Decryption (for direct ciphertext)
    void decrypt_delegate( element_t& m1, element_t C2,          // Ciphertext component
    element_t C3,          // Ciphertext componen           // Generator
    element_t pk_i,    // User's secret key alpha
    element_t sk_beta,     // User's secret key beta
    pairing_t pairing
    );

    // Decryption (for re-encrypted ciphertext)
    void decrypt_re(element_t& m2, element_t C1p, element_t C2p, element_t C3p, element_t gamma , pairing_t pairing);

    // Hash function H: G1 x GT x G1 -> G1
    void hash_function(element_t& out, element_t C1, element_t C2, element_t C3);

    // Getters
    element_t& get_alpha() { return alpha; }
    element_t& get_beta() { return beta; }
    element_t& get_gamma() { return gamma; }
    element_t& get_sk_beta() { return sk_beta; }
    element_t& get_sk_gamma() { return sk_gamma; }
    element_t& get_sk_alpha() { return sk_alpha; }
    element_t& get_g() { return g; }
    element_t& get_rk() { return rk; }
    pairing_ptr get_pairing() { return pairing; }

private:
    pairing_t pairing;
    element_t g ;
    element_t alpha, beta, gamma; // public key: (g^alpha, g^beta, g^gamma)
    element_t sk_alpha, sk_beta, sk_gamma;  // secret key: (beta, gamma)
    element_t rk;

};

#endif
