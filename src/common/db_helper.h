// include/db_helper.h
#include <sqlite3.h>
#include <string>
#include <vector>

class DBHelper {
public:
    DBHelper(const char* db_path);
    ~DBHelper();

    bool create_user(const std::string& username, const std::string& role);
    int get_user_id(const std::string& username);
    bool store_key(int user_id, const std::string& key_type, const std::vector<unsigned char>& key_data);
    std::vector<unsigned char> get_key(int user_id, const std::string& key_type);
    bool store_ciphertext(int owner_id, const std::vector<unsigned char>& ciphertext);
    std::vector<unsigned char> get_ciphertext(int id);

private:
    sqlite3* db;
};
