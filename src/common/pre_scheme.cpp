#include "pre_scheme.h"
#include <openssl/sha.h>
#include <iostream>
#include <cstring>

PREContext::PREContext(const char* param_path) {
    FILE* fp = fopen(param_path, "r");
    if (!fp) { perror("Error opening param file"); exit(1); }
    char param[4096];
    size_t count = fread(param, 1, 4096, fp);
    fclose(fp);
    pairing_init_set_buf(pairing, param, count);
        
    element_init_G1(g, pairing);
    element_init_G1(alpha, pairing);
    element_init_G1(beta, pairing);
    element_init_G1(gamma, pairing);
    element_init_Zr(sk_beta, pairing);
    element_init_Zr(sk_gamma, pairing);
    element_init_Zr(sk_alpha, pairing);
    element_init_G1(rk, pairing);
    // Fixed generator for g
    const char* fixed_seed = "fixed_generator_seed_for_project";
    element_from_hash(g, (void*)fixed_seed, strlen(fixed_seed));

}

PREContext::~PREContext() {
    element_clear(g);
    element_clear(alpha);
    element_clear(beta);
    element_clear(gamma);
    element_clear(sk_beta);
    element_clear(sk_gamma);
    element_clear(sk_alpha);
    element_clear(rk);
    pairing_clear(pairing);
}

void PREContext::generate_user_keys() {
    element_t alpha_exp, beta_exp, gamma_exp;
    element_init_Zr(alpha_exp, pairing);
    element_init_Zr(beta_exp, pairing);
    element_init_Zr(gamma_exp, pairing);

    element_random(alpha_exp);
    element_random(beta_exp);
    element_random(gamma_exp);

    element_pow_zn(alpha, g, alpha_exp);
    element_pow_zn(beta, g, beta_exp);
    element_pow_zn(gamma, g, gamma_exp);

    element_set(sk_beta, beta_exp);
    element_set(sk_gamma, gamma_exp);
    element_set(sk_alpha, alpha_exp);

    element_clear(alpha_exp);
    element_clear(beta_exp);
    element_clear(gamma_exp);
}

void PREContext::generate_owner_keys() {
    element_t alpha_exp, beta_exp, gamma_exp;
    element_init_Zr(alpha_exp, pairing);
    element_init_Zr(beta_exp, pairing);
    element_init_Zr(gamma_exp, pairing);

    element_random(alpha_exp);
    element_random(beta_exp);
    element_random(gamma_exp);

    element_pow_zn(alpha, g, alpha_exp);
    element_pow_zn(beta, g, beta_exp);
    element_pow_zn(gamma, g, gamma_exp);

    element_set(sk_beta, beta_exp);
    element_set(sk_gamma, gamma_exp);
    element_set(sk_alpha, alpha_exp);

    element_clear(alpha_exp);
    element_clear(beta_exp);
    element_clear(gamma_exp);
}


void PREContext::hash_function(element_t& out, element_t C1, element_t C2, element_t C3) {
    int len1 = element_length_in_bytes(C1);
    int len2 = element_length_in_bytes(C2);
    int len3 = element_length_in_bytes(C3);
    unsigned char* buf1 = new unsigned char[len1];
    unsigned char* buf2 = new unsigned char[len2];
    unsigned char* buf3 = new unsigned char[len3];

    element_to_bytes(buf1, C1);
    element_to_bytes(buf2, C2);
    element_to_bytes(buf3, C3);

    int total_len = len1 + len2 + len3;
    unsigned char* combined = new unsigned char[total_len];
    memcpy(combined, buf1, len1);
    memcpy(combined + len1, buf2, len2);
    memcpy(combined + len1 + len2, buf3, len3);

    element_from_hash(out, combined, total_len);

    delete[] buf1;
    delete[] buf2;
    delete[] buf3;
    delete[] combined;
}

void PREContext::encrypt(
    element_t& C1, element_t& C2, element_t& C3, element_t& C4, element_t& C5,
    element_t m, element_t alpha, element_t beta
) {
    element_t r, s, rs, temp1, temp2, temp3;
    element_init_Zr(r, pairing);
    element_init_Zr(s, pairing);
    element_init_Zr(rs, pairing);
    element_init_GT(temp1, pairing);
    element_init_GT(temp2, pairing);
    element_init_G1(temp3, pairing);

    element_random(r);
    element_random(s);
    element_mul(rs, r, s);

    // C1 = (public_key1)^r
    element_pow_zn(C1, alpha , r);

    // C3 = g^{rs}
    element_pow_zn(C3, g, rs);

    // C2 = m * e(g^alpha, g^beta)^{rs}
    pairing_apply(temp1, alpha, beta, pairing);
    element_pow_zn(temp2, temp1, rs);
    element_mul(C2, m, temp2);

    // C4 = g^{r * H(C1,C2,C3)}
    

    // 1. Hash (C1, C2, C3) to Zr
       element_t hash_val;
       element_init_Zr(hash_val, pairing);
       hash_function(hash_val, C1, C2, C3); // hash_val = H(C1, C2, C3) in Zr

    // 2. Compute temp3 = r * hash_val (in Zr)
       element_t exp;
       element_init_Zr(exp, pairing);
       element_mul(exp, r, hash_val); // exp = r * H(C1, C2, C3)

    // 3. C4 = g^{exp}
       element_pow_zn(C4, g, exp);

    // 4. Clear temporaries
       element_clear(hash_val);
       element_clear(exp);


    // C5 = g^alpha
    element_set(C5, alpha);

    element_clear(r);
    element_clear(s);
    element_clear(rs);
    element_clear(temp1);
    element_clear(temp2);
    element_clear(temp3);
}

// Direct decryption for delegate (Bob)
// C2: GT, C3: G1, pk_i: Bob's public key (G1), gamma: Bob's private key (Zr)
// Bob's direct decryption function
void PREContext::decrypt_delegate(
    element_t& m1,          // Output: decrypted message (GT)
    element_t C2,          // Ciphertext component (GT)
    element_t C3,          // Ciphertext component (G1)
    element_t pk_i,        // Bob's public key (G1)
    element_t sk_beta,     // Bob's secret key beta_i (Zr)
    pairing_t pairing      // Pairing context
) {
    element_t pairing_res, neg_beta, pairing_pow;
    element_init_GT(pairing_res, pairing);
    element_init_Zr(neg_beta, pairing);
    element_init_GT(pairing_pow, pairing);

    // pairing_res = e(C3, pk_i)
    pairing_apply(pairing_res, C3, pk_i, pairing);

    // neg_beta = -beta_i
    element_neg(neg_beta, sk_beta);

    // pairing_pow = pairing_res^{-beta_i}
    element_pow_zn(pairing_pow, pairing_res, neg_beta);

    // m = C2 * pairing_pow
    element_mul(m1, C2, pairing_pow);

    // Clear temporaries
    element_clear(pairing_res);
    element_clear(neg_beta);
    element_clear(pairing_pow);
}





void PREContext::generate_rekey(element_t& rk, element_t pk1_i, element_t sk_beta_i, element_t pk3_j, element_t sk_alpha_i) {
    // Temporary variables
    element_t temp1, temp2, neg_beta_i;
    element_init_G1(temp1, pairing);
    element_init_G1(temp2, pairing);
    element_init_Zr(neg_beta_i, pairing);

    // temp1 = (pk1_i)^{-beta_i}
    element_neg(neg_beta_i, sk_beta_i);           // neg_beta_i = -beta_i
    element_pow_zn(temp1, pk1_i, neg_beta_i);     // temp1 = (g^alpha_i)^{-beta_i}

    // temp2 = (pk3_j)^{alpha_i}
    element_pow_zn(temp2, pk3_j, sk_alpha_i);     // temp2 = (g^gamma_j)^{alpha_i}

    // rk = temp1 * temp2
    element_mul(rk, temp1, temp2);                // rk = (g^alpha_i)^{-beta_i} * (g^gamma_j)^{alpha_i}

    // Clear temporaries
    element_clear(temp1);
    element_clear(temp2);
    element_clear(neg_beta_i);
}




void PREContext::re_encrypt(
    element_t& C1p, element_t& C2p, element_t& C3p,
    element_t C1, element_t C2, element_t C3, element_t C4, element_t C5, element_t rk
) {
    element_t temp;
    element_init_GT(temp, pairing);

    // C1' = C2 * e(rk, C3)
    pairing_apply(temp, rk, C3, pairing);
    element_mul(C1p, C2, temp);

    // C2' = C1
    element_set(C2p, C1);

    // C3' = C3
    element_set(C3p, C3);

    element_clear(temp);
}

void PREContext::decrypt_re(
    element_t& m2,         // Output: decrypted message (GT)
    element_t C1p,         // C1' (GT) = C2 * e(rk_{i→j}, C3)
    element_t C2p,         // C2' (G1)
    element_t C3p,         // C3' (G1)
    element_t gamma_j,     // Delegate's secret key Tj (Zr)
    pairing_t pairing
) {
    // Initialize elements
    element_t pairing_res, exponentiated, neg_exp;
    element_init_GT(pairing_res, pairing);
    element_init_Zr(neg_exp, pairing);
    element_init_GT(exponentiated, pairing);

    // Step 1: Compute pairing e(C2', C3')
    pairing_apply(pairing_res, C2p, C3p, pairing);

    // Step 2: Compute -Tj
    element_neg(neg_exp, gamma_j);

    // Step 3: Raise pairing result to -Tj → (e(C2', C3'))^{-Tj}
    element_pow_zn(exponentiated, pairing_res, neg_exp);

    // Step 4: m = C1' * (e(C2', C3')^{-Tj})
    element_mul(m2, C1p, exponentiated);

    // Clear temp variables
    element_clear(pairing_res);
    element_clear(neg_exp);
    element_clear(exponentiated);
}

