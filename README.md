# 🔐 PRE-visible-without-random-oracles

**Proxy Visible Re-Encryption (PRE)** provides secure, auditable delegation of decryption rights in the cloud **without relying on random oracles**.  
This C++ project demonstrates **pairing-based PRE** with clear role separation, robust cryptographic operations, and a complete TCP-based communication flow.

---

## 📌 Features

- 🔐 Pairing-based Proxy Re-Encryption using the PBC library
- 👥 Roles: Data Owner (Alice), Delegatee (Bob), Proxy Cloud Server
- 🔑 Secure, auditable key generation and element serialization
- 📦 Message encryption, re-encryption key generation, and proxy-side re-encryption
- 🧰 CLI utilities for each role (`data_owner`, `data_user`, `cloud_server`)
- 🛠️ Robust network + element debugging (hex output, logging)
- 🚫 No random oracles, no black-box crypto — fully visible and auditable


---

## ⚙️ Build Instructions

### ✅ Prerequisites

- Linux or Unix-based shell (Ubuntu preferred)
- C++17 compiler (e.g., `g++`, `clang++`)
- [PBC library](https://crypto.stanford.edu/pbc/) (`libpbc-dev`)
- [OpenSSL](https://www.openssl.org/) development libraries
- `make` (already included on most Unix systems)


## Installation

1. **Clone the repository:**
    ```
    git clone https://github.com/ExploitxAN33/PRE-visible-without-random-oracles.git
    cd PRE-visible-without-random-oracles
    ```

2. **Install dependencies:**
    On Ubuntu/Debian:
   ```
     sudo apt-get update
     sudo apt-get install build-essential cmake libssl-dev
   ```

3. **Build the project:**
    ```
    cd build
    cmake ..
    make
    ```
    Binaries for `cloud_server`, `data_owner`, and `data_user` will be generated in the `build` directory.

---

## How to Run

**Order of Execution (with TCP connections):**

1. **Start the Cloud Server** (must be running before other modules):
    ```
    cd ..
    ./Build/cloud_server 
    ```
    - The server listens for TCP connections from data users and data owners.

2. **Run Data User** (connects to the cloud server via TCP):
    ```
    ./Build/data_user 127.0.0.1 alice
    ```
    - Initiates a TCP connection to the cloud server.
    - Requests files and handles decryption keys.

3. **Run Data Owner** (connects to the cloud server via TCP):
    ```
    ./Build/data_owner 127.0.0.1 alice bob
    ```
    - Initiates a TCP connection to the cloud server.
    - Uploads and manages encrypted files.

> **Note:**  
> - Each component must be run in a separate terminal or process.  
> - Ensure the server address and port are correctly configured in your configuration files or command-line arguments.

---

## 🔄 Protocol Overview

🗝️ Key Generation
Alice and Bob each generate their own public-private key pairs using pairing-based cryptography.

🔐 Encryption (Alice)
Alice encrypts a message using her public key.

Encrypted ciphertext is sent to the Cloud Server.

🔁 Re-Encryption Key Generation
Alice generates a re-encryption key (rekey) that allows the proxy (Cloud Server) to transform her ciphertext for Bob.

🏢 Proxy Re-Encryption
The Cloud Server receives the original ciphertext and rekey.

It performs the re-encryption, converting Alice’s ciphertext into a format Bob can decrypt.

🔓 Decryption (Bob)
Bob connects to the Cloud Server and fetches the re-encrypted ciphertext.

He decrypts the data using his private key and retrieves the original plaintext message.

📷 Sample Screenshots
Coming soon...
You can include terminal logs showing encryption, rekey generation, and successful decryption.

---

##  🛠️ Troubleshooting
❌ Build errors?
Make sure all dependencies (libpbc-dev, libssl-dev) are installed.

🌐 Can't connect to server?
Ensure server IP and ports are accessible from client terminals.

🔑 Decryption fails?
Double-check the pairing parameters (a.param) are consistent across all roles.

🗂️ Missing build/ folder?
Just run make again, or manually create build/ and compile.
