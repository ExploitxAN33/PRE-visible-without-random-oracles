// include/crypto_utils.h
#include "db_helper.h"
#include <vector>

class KeyManager {
public:
    KeyManager(DBHelper& db) : db(db) {}
    void generate_and_store_keys(const std::string& username);
    // ... other methods ...
private:
    DBHelper& db;
};
