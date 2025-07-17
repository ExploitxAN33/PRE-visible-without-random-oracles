#include "pre_scheme.h"
#include "network_utils.h"
#include <iostream>
#include <cstring>
#include <unistd.h>

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <server_ip> <user_id>" << std::endl;
        return 1;
    }
    PREContext pre("params/a.param");
    const char* server_ip = argv[1];
    const char* user_id = argv[2];
    
    clock_t start, close;
    double cpu_time_used;
    element_t m1, m2;

    // Generate Bob's keys
    start = clock();
    pre.generate_user_keys();
    close = clock();
    cpu_time_used = ((double)(close - start)) / CLOCKS_PER_SEC;
    printf("User keys generate  %lf  time \n", cpu_time_used);
    printf("-------------------------------------User (BOB)-------------------------------------------------------------------\n");
    std::cout << "User public key 1 : "; element_printf("%B\n", pre.get_alpha());
    std::cout << "User public key 2 : "; element_printf("%B\n", pre.get_beta());
    std::cout << "User public key 3 : "; element_printf("%B\n", pre.get_gamma());
    std::cout << "User secret key 1 : "; element_printf("%B\n", pre.get_sk_alpha());
    std::cout << "User secret key 2 : "; element_printf("%B\n", pre.get_sk_beta());
    std::cout << "User secret key 3 : "; element_printf("%B\n", pre.get_sk_gamma());

    // Upload Bob's public key
    TCPClient client_pk(server_ip, 8080);
    client_pk.connect_to_server();
    client_pk.send_data("UPLOAD_PK", 10);
    client_pk.send_data(user_id, strlen(user_id) + 1);
    send_element(client_pk.get_sock(), pre.get_alpha());
    send_element(client_pk.get_sock(), pre.get_beta());
    send_element(client_pk.get_sock(), pre.get_gamma());
    client_pk.close_connection();

    // Wait for ciphertext and rekey to be uploaded by data owner
    sleep(10);
    // Connect to the cloud server
    TCPClient client_ct(server_ip, 8080);
    client_ct.connect_to_server();
    client_ct.send_data("GET_CT", 7);
    client_ct.send_data(user_id, strlen(user_id) + 1);

     // Prepare elements to receive
    element_t C1, C2, C3, C4, C5;
    element_init_G1(C1, pre.get_pairing());
    element_init_GT(C2, pre.get_pairing());
    element_init_G1(C3, pre.get_pairing());
    element_init_G1(C4, pre.get_pairing());
    element_init_G1(C5, pre.get_pairing());

     // Receive elements
    start = clock();
    recv_element(client_ct.get_sock(), C1, pre.get_pairing());
    recv_element(client_ct.get_sock(), C2, pre.get_pairing()); 
    recv_element(client_ct.get_sock(), C3, pre.get_pairing());
    recv_element(client_ct.get_sock(), C4, pre.get_pairing());
    recv_element(client_ct.get_sock(), C5, pre.get_pairing());
    close = clock();
    cpu_time_used = ((double)(close - start)) / CLOCKS_PER_SEC;
    printf("\n\n");
    printf("Received original ciphertext  %lf time \n", cpu_time_used);
    client_ct.close_connection();

    std::cout << "----------------------------------Received original ciphertext from cloud-------------------------------\n" << std::endl;
    std::cout << "C1: "; element_printf("%B\n", C1);
    std::cout << "C2: "; element_printf("%B\n", C2);
    std::cout << "C3: "; element_printf("%B\n", C3);
    std::cout << "C4: "; element_printf("%B\n", C4);
    std::cout << "C5: "; element_printf("%B\n", C5);

    // Request re-encrypted ciphertext
    TCPClient client2(server_ip, 8080);
    client2.connect_to_server();
    client2.send_data("REQUEST_CT", 11);
    client2.send_data(user_id, strlen(user_id) + 1);

    element_t C1p, C2p, C3p;
    element_init_GT(C1p, pre.get_pairing());
    element_init_G1(C2p, pre.get_pairing());
    element_init_G1(C3p, pre.get_pairing());
    element_init_GT(m1, pre.get_pairing());
    element_init_GT(m2, pre.get_pairing());
    start = clock();
    recv_element(client2.get_sock(), C1p, pre.get_pairing());
    recv_element(client2.get_sock(), C2p, pre.get_pairing());
    recv_element(client2.get_sock(), C3p, pre.get_pairing());
    close = clock();
    cpu_time_used = ((double)(close - start)) / CLOCKS_PER_SEC;
    printf("\n\n Received Re-encrypted  %lf time \n", cpu_time_used);
    client2.close_connection();

    std::cout << "--------------------------------------Received re-encrypted ciphertext----------------------------------\n" << std::endl;
    std::cout << "C1': "; element_printf("%B\n", C1p);
    std::cout << "C2': "; element_printf("%B\n", C2p);
    std::cout << "C3': "; element_printf("%B\n", C3p);

     // Decrypt
    std::cout << "\n------------------------------------------Decryption------------------------------------------------------\n" ;
    start = clock();
    pre.decrypt_delegate(m1, C2, C3 , pre.get_alpha() , pre.get_sk_beta() , pre.get_pairing());
    close = clock();
    cpu_time_used = ((double)(close - start)) / CLOCKS_PER_SEC;
    printf("Direct Decryption  %lf time \n", cpu_time_used);

    std::cout << "Direct Ciphertext : Decryption m1 : "; element_printf("%B\n", m1);
    std::cout << "\n";

    start = clock();
    pre.decrypt_re(m2 , C1p , C2p , C3p , pre.get_sk_gamma() , pre.get_pairing());
    close = clock();
    cpu_time_used = ((double)(close - start)) / CLOCKS_PER_SEC;
    printf("Received Reencryption's Decryption  %lf time \n", cpu_time_used);

    std::cout << "Re-Encrypted Decryption  m2 : "; element_printf("%B\n", m2);


    element_clear(C1p);
    element_clear(C2p);
    element_clear(C3p);
    element_clear(m2);
    element_clear(m1);
    element_clear(C1);
    element_clear(C2);
    element_clear(C3);
    element_clear(C4);
    element_clear(C5);



    return 0;
}
