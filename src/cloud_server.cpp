#include "pre_scheme.h"
#include "network_utils.h"
#include <iostream>
#include <cstring>
#include <ctime>
#include <unistd.h>

// Global variables for a single user's data
element_t pk_alpha, pk_beta, pk_gamma;
element_t rk;
element_t ct_C1, ct_C2, ct_C3, ct_C4, ct_C5;
bool has_ct = false;
bool has_rk = false;

int main() {
    PREContext pre("params/a.param");
    element_init_G1(pk_alpha, pre.get_pairing());
    element_init_G1(pk_beta, pre.get_pairing());
    element_init_G1(pk_gamma, pre.get_pairing());
    element_init_G1(rk, pre.get_pairing());
    element_init_G1(ct_C1, pre.get_pairing());
    element_init_GT(ct_C2, pre.get_pairing());
    element_init_G1(ct_C3, pre.get_pairing());
    element_init_G1(ct_C4, pre.get_pairing());
    element_init_G1(ct_C5, pre.get_pairing());

    clock_t start, close;
    double cpu_time_used;

    TCPServer server(8080);
    server.start();
    std::cout << "Cloud Server listening on port 8080..." << std::endl;

    while (true) {
        int client_fd = server.accept_connection();
        char command[20] = {0};
        server.recv_data(client_fd, command, 20);

        if (strcmp(command, "UPLOAD_PK") == 0) {
            char user_id[50] = {0};
            start = clock();
            server.recv_data(client_fd, user_id, 50);
            recv_element(client_fd, pk_alpha, pre.get_pairing());
            recv_element(client_fd, pk_beta, pre.get_pairing());
            recv_element(client_fd, pk_gamma, pre.get_pairing());
            close = clock();
            cpu_time_used = ((double)(close - start)) / CLOCKS_PER_SEC;
            printf("Stored Public key %lf time\n", cpu_time_used);
            std::cout << "-----------------------------------Stored public key for user---------------------- " << user_id << std::endl;
            std::cout << "User public key (α): "; element_printf("%B\n", pk_alpha);
            std::cout << "User public key (β): "; element_printf("%B\n", pk_beta);
            std::cout << "User public key (γ): "; element_printf("%B\n", pk_gamma);
        }
        else if (strcmp(command, "GET_PK") == 0) {
            char user_id[50] = {0};
            start = clock();
            server.recv_data(client_fd, user_id, 50);
            close = clock();
            cpu_time_used = ((double)(close - start)) / CLOCKS_PER_SEC;
            printf("send public key to data_owner %lf  time\n", cpu_time_used);
            send_element(client_fd, pk_alpha);
            send_element(client_fd, pk_beta);
            send_element(client_fd, pk_gamma);
            std::cout << "Sent user public key to requester" << std::endl;
            std::cout << "Waiting  seconds for data owner..." << std::endl;
            sleep(2);
        }
        else if (strcmp(command, "UPLOAD_KEY") == 0) {
            char user_id[50] = {0};
            std::cout << "\n\n" << std::endl;
            start = clock();
            server.recv_data(client_fd, user_id, 50);
            recv_element(client_fd, rk, pre.get_pairing());
            close = clock();
            has_rk = true;
            cpu_time_used = ((double)(close - start)) / CLOCKS_PER_SEC;
            printf("Received Reencryption %lf time \n", cpu_time_used);
            std::cout << "---------------------------------Received re-encryption key from data_owner-------------------------------\n";
            std::cout << "Re-encryption key: "; element_printf("%B\n", rk);
        }
        else if (strcmp(command, "UPLOAD_CT") == 0) {
            char user_id[50] = {0};
            std::cout << "\n\n" << std::endl;
            start = clock();
            server.recv_data(client_fd, user_id, 50);  // Receive user ID first!
            recv_element(client_fd, ct_C1, pre.get_pairing());
            recv_element(client_fd, ct_C2, pre.get_pairing());
            recv_element(client_fd, ct_C3, pre.get_pairing());
            recv_element(client_fd, ct_C4, pre.get_pairing());
            recv_element(client_fd, ct_C5, pre.get_pairing());
            close = clock();
            has_ct = true;
            cpu_time_used = ((double)(close - start)) / CLOCKS_PER_SEC;
            printf("Received ciphertext %lf  time  \n", cpu_time_used);
            std::cout << "--------------------------------------Received ciphertext-----------------------------------------\n" << std::endl;
            std::cout << "C1: "; element_printf("%B\n", ct_C1);
            std::cout << "C2: "; element_printf("%B\n", ct_C2);
            std::cout << "C3: "; element_printf("%B\n", ct_C3);
            std::cout << "C4: "; element_printf("%B\n", ct_C4);
            std::cout << "C5: "; element_printf("%B\n", ct_C5);

        }
        else if (strcmp(command, "GET_CT") == 0) {
             if (!has_ct) {
                  std::cerr << "Error: Ciphertext not received yet!" << std::endl;
                 // Optionally send error to client
                  continue;
              }
              // Send C1 to C5 to delegate
            send_element(client_fd, ct_C1);
            send_element(client_fd, ct_C2);
            send_element(client_fd, ct_C3);
            send_element(client_fd, ct_C4);
            send_element(client_fd, ct_C5);
            std::cout << "Sent original ciphertext C1-C5 to delegate." << std::endl;
        }

        else if (strcmp(command, "REQUEST_CT") == 0) {
             if (!has_ct || !has_rk) {
               std::cerr << "Error: Ciphertext or re-encryption key not received yet!" << std::endl;
               // Optionally send error to client
               continue;
            }
            std::cout << "\n" << std::endl;
            element_t hash_val, g_hash, left, right;
            element_init_Zr(hash_val, pre.get_pairing());
            element_init_G1(g_hash, pre.get_pairing());
            element_init_GT(left, pre.get_pairing());
            element_init_GT(right, pre.get_pairing());

            pre.hash_function(hash_val, ct_C1, ct_C2, ct_C3);
            element_pow_zn(g_hash, pre.get_g(), hash_val);
            pairing_apply(left, ct_C1, g_hash, pre.get_pairing());
            pairing_apply(right, ct_C4, pk_alpha, pre.get_pairing());

            if (element_cmp(left, right) == 0) {
               std::cout << "[Cloud] Ciphertext verification PASSED, proceeding to re-encryption." << std::endl;
                  element_t C1p, C2p, C3p;
                  element_init_GT(C1p, pre.get_pairing());
                  element_init_G1(C2p, pre.get_pairing());
                  element_init_G1(C3p, pre.get_pairing());
                  std::cout << "\n\n" << std::endl;

                 start = clock();
                 pre.re_encrypt(C1p, C2p, C3p, ct_C1, ct_C2, ct_C3, ct_C4, ct_C5, rk);
                 close = clock();
                 cpu_time_used = ((double)(close - start)) / CLOCKS_PER_SEC;
                 printf("Re-encrypted cipher text %lf  time  \n", cpu_time_used);
                 std::cout << "=============================== Cloud Server through generation of re-key CT =====================" << std::endl;
                 std::cout << "Re-encrypted c1': "; element_printf("%B\n", C1p);
                 std::cout << "Re-encrypted c2': "; element_printf("%B\n", C2p);
                 std::cout << "Re-encrypted c3': "; element_printf("%B\n", C3p);

                 send_element(client_fd, C1p);
                 send_element(client_fd, C2p);
                 send_element(client_fd, C3p);

                 element_clear(C1p); element_clear(C2p); element_clear(C3p);


            } else {
                std::cerr << "[Cloud] Ciphertext verification FAILED! Rejecting ciphertext." << std::endl;
            }
              element_clear(hash_val);
              element_clear(g_hash);
              element_clear(left);
              element_clear(right);
        }
        else {
            std::cerr << "Unknown command received: " << command << std::endl;
        }
        server.close_connection(client_fd);
    }
    return 0;
}
