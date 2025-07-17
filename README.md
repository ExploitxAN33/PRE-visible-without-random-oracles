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

## 🗂️ Project Structure

.
├── include/
│ └── pre_scheme.h # Main PRE class/crypto interface
├── src/
│ ├── common/
│ │ ├── network_utils.cpp # TCP comms and serialization
│ │ └── pre_scheme.cpp # PRE algorithms and core logic
│ ├── data_owner.cpp # Alice role: keygen, encrypt, rekey
│ ├── data_user.cpp # Bob role: keygen, upload, decrypt
│ └── cloud_server.cpp # Proxy server: manages keys/ciphertext, re-encryption
├── params/
│ └── a.param # Pairing parameters (MUST match across programs)
├── Makefile # Build system
└── README.md

markdown
Copy
Edit

---

## ⚙️ Build Instructions

### ✅ Prerequisites

- Linux or Unix-based shell (Ubuntu preferred)
- C++17 compiler (e.g., `g++`, `clang++`)
- [PBC library](https://crypto.stanford.edu/pbc/) (`libpbc-dev`)
- [OpenSSL](https://www.openssl.org/) development libraries
- `make` (already included on most Unix systems)

### 🔧 Build Steps

```bash
git clone https://github.com/<your-github-username>/PRE-visible-without-random-oracles.git
cd PRE-visible-without-random-oracles
```
make
💡 If you want to use custom pairing parameters, generate your own params/a.param using pbc_param_gen.

###  🚀 Usage Example
1️⃣ Start the Proxy Cloud Server
bash
Copy
Edit
./build/cloud_server
Starts the TCP server to receive connections from Alice and Bob.

2️⃣ Run the Data User (Bob)
bash
Copy
Edit
./build/data_user <server_ip> <user_id>
# Example:
./build/data_user 127.0.0.1 bob
Generates Bob’s key pair

Uploads his public key to the server

Waits to receive re-encrypted ciphertext

3️⃣ Run the Data Owner (Alice)
```
./build/data_owner <server_ip> <owner_id> <user_id>
# Example:
./build/data_owner 127.0.0.1 alice bob
```
Generates Alice’s key pair

Fetches Bob’s public key

Encrypts data and generates re-encryption key for Bob

Sends ciphertext + rekey to the Cloud Server

⚠️ All components must be run in separate terminals/sessions

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

##  🛠️ Troubleshooting
❌ Build errors?
Make sure all dependencies (libpbc-dev, libssl-dev) are installed.

🌐 Can't connect to server?
Ensure server IP and ports are accessible from client terminals.

🔑 Decryption fails?
Double-check the pairing parameters (a.param) are consistent across all roles.

🗂️ Missing build/ folder?
Just run make again, or manually create build/ and compile.
