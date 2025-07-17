#include "pre_scheme.h"
#include "network_utils.h"
#include <iostream>
#include <cstring>

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] << " <server_ip> <owner_id> <user_id>" << std::endl;
        return 1;
    }
    PREContext pre("params/a.param");
    const char* server_ip = argv[1];
    const char* owner_id = argv[2];
    const char* user_id = argv[3];
    clock_t start, close;
    double cpu_time_used;

    // Generate Alice's keys
    start = clock();
    pre.generate_owner_keys();
    close = clock();
    cpu_time_used = ((double)(close - start)) / CLOCKS_PER_SEC;
    printf("Owner key generate %lf time\n", cpu_time_used);
    std::cout << "-------------------------------------Data Owner (Alice) ---------------------------------------------\n" << std::endl;
    std::cout << "Owner α_i: "; element_printf("%B\n", pre.get_alpha());
    std::cout << "Owner β_i: "; element_printf("%B\n", pre.get_beta());
    std::cout << "Owner γ_i: "; element_printf("%B\n", pre.get_gamma());
    std::cout << "User secret key 1 : "; element_printf("%B\n", pre.get_sk_alpha());
    std::cout << "User secret key 2 : "; element_printf("%B\n", pre.get_sk_beta());
    std::cout << "User secret key 3 : "; element_printf("%B\n", pre.get_sk_gamma());

    // Get Bob's public key
    TCPClient client(server_ip, 8080);
    client.connect_to_server();
    client.send_data("GET_PK", 7);
    client.send_data(user_id, strlen(user_id) + 1);

    element_t alpha_j, beta_j, gamma_j;
    element_init_G1(alpha_j, pre.get_pairing());
    element_init_G1(beta_j, pre.get_pairing());
    element_init_G1(gamma_j, pre.get_pairing());
    recv_element(client.get_sock(), alpha_j, pre.get_pairing());
    recv_element(client.get_sock(), beta_j, pre.get_pairing());
    recv_element(client.get_sock(), gamma_j, pre.get_pairing());
    client.close_connection();

    std::cout << "--------------------------------------Data User's public key fetching (Bob) ------------------------------\n" << std::endl;
    std::cout << "User public key (α): "; element_printf("%B\n", alpha_j);
    std::cout << "User public key (β): "; element_printf("%B\n", beta_j);
    std::cout << "User public key (γ): "; element_printf("%B\n", gamma_j);

    // Encrypt message for Bob
    element_t m, C1, C2, C3, C4, C5;
    element_init_GT(m, pre.get_pairing());
    element_init_G1(C1, pre.get_pairing());
    element_init_GT(C2, pre.get_pairing());
    element_init_G1(C3, pre.get_pairing());
    element_init_G1(C4, pre.get_pairing());
    element_init_G1(C5, pre.get_pairing());

    start = clock();
    const char* fixed_msg = "HelloPRE123!";
    element_from_hash(m, (void*)fixed_msg, strlen(fixed_msg));
    close = clock();
    cpu_time_used = ((double)(close - start)) / CLOCKS_PER_SEC;
    printf("\nfixed message generate %lf time", cpu_time_used);

    std::cout << "\n----------------------------------------Fixed Message Generate-----------------------------------------\n"; element_printf("%B\n", m);
    std::cout << "\n";

    start = clock();
    pre.encrypt(C1, C2, C3, C4, C5, m, alpha_j, beta_j);
    close = clock();
    cpu_time_used = ((double)(close - start)) / CLOCKS_PER_SEC;
    printf("Encryption  %lf time\n", cpu_time_used);

    std::cout << "---------------------------------Encrypted 5-component ciphertext-----------------------------------------\n" << std::endl;
    std::cout << "C1: "; element_printf("%B\n", C1);
    std::cout << "C2: "; element_printf("%B\n", C2);
    std::cout << "C3: "; element_printf("%B\n", C3);
    std::cout << "C4: "; element_printf("%B\n", C4);
    std::cout << "C5: "; element_printf("%B\n", C5);
    std::cout << "\n";


    // Generate re-encryption key
    element_t rk;
    element_init_G1(rk, pre.get_pairing());
    start = clock();
    pre.generate_rekey(rk, pre.get_alpha(), pre.get_sk_beta(), gamma_j, pre.get_sk_alpha());
    close = clock();
    cpu_time_used = ((double)(close - start)) / CLOCKS_PER_SEC;
    printf(" Re Encryption key generate %lf time\n", cpu_time_used);
    std::cout << "------------------------------------Re Encryption key generated(rk)------------------------------------------\n "; element_printf("%B\n", rk);

    // Upload re-encryption key
    TCPClient client_key(server_ip, 8080);
    client_key.connect_to_server();
    client_key.send_data("UPLOAD_KEY", 11);
    client_key.send_data(user_id, strlen(user_id) + 1);
    send_element(client_key.get_sock(), rk);
    client_key.close_connection();


    // Upload ciphertext
    TCPClient client_ct(server_ip, 8080);
    client_ct.connect_to_server();
    client_ct.send_data("UPLOAD_CT", 10);
    client_ct.send_data(user_id, strlen(user_id) + 1);
    send_element(client_ct.get_sock(), C1);
    send_element(client_ct.get_sock(), C2);
    send_element(client_ct.get_sock(), C3);
    send_element(client_ct.get_sock(), C4);
    send_element(client_ct.get_sock(), C5);
    client_ct.close_connection();

    element_clear(alpha_j);
    element_clear(beta_j);
    element_clear(gamma_j);
    element_clear(rk);
    element_clear(m);
    element_clear(C1);
    element_clear(C2);
    element_clear(C3);
    element_clear(C4);
    element_clear(C5);

    return 0;
}
