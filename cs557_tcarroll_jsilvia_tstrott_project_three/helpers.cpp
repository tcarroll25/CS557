/**********************************************************************
 *
 * P2P with TLS
 *
 * Written by: Tyler Carroll, James Silvia, Tom Strott
 * In completion of: CS557 Project 2
 *
 * A secure P2P storage system
 *
 * helpers.cpp
 *
 **********************************************************************/
#include "helpers.hpp"
#include "dirent.h"

int get_index_value(int index, string in_string) {
    int ret = -1;
    string word;
    stringstream stream(in_string);

    getline(stream, word, ',');
    if (index == atoi(word.c_str())) {
        getline(stream, word, ',');
        //Found the index, return val
        ret = atoi(word.c_str());
    }
    return ret;
}

int get_index(int index, string in_string) {
    int ret = -1;
    string word;
    stringstream stream(in_string);
    
    getline(stream, word, ',');
    if (index == atoi(word.c_str())){
        ret = atoi(word.c_str());
    }
    return ret;
}

string get_stored_user(string in_string) {
    string word;
    stringstream stream(in_string);

    //get index
    getline(stream, word, ',');
    //get val
    getline(stream, word, ',');
    //get user
    getline(stream, word, ',');

    return word;
}

string get_stored_group(string in_string) {
    string word;
    stringstream stream(in_string);

    //get index
    getline(stream, word, ',');
    //get val
    getline(stream, word, ',');
    //get user
    getline(stream, word, ',');
    //get group
    getline(stream, word, ',');

    return word;
}

bool check_for_group(string directory, string group) {
    DIR *dir;
    struct dirent *ent;
    if ((dir = opendir(directory.c_str())) != NULL) {
        /* print all the files and directories within directory */
        while ((ent = readdir (dir)) != NULL) {
            if (group.compare(ent->d_name) == 0) {
                return true;
            }
        }
        closedir (dir);
    } else {
        /* could not open directory */
        cout << "Could not open directory!" << endl;
        return false;
    }
    return false;
}

bool check_group_for_user(string user, string group, string group_dir) {
    string infileName;
    ifstream infile;

    infileName = group_dir + "/" + group;

    if (!check_for_datastore(infileName.c_str())) {
        // File does not exist
        return false;
    }

    infile.open(infileName.c_str(), fstream::in | fstream::app);

    if (infile.fail()) {
        return false;
    }

    string line;
    while(getline(infile, line)) {
        if (user.compare(line) == 0) {
            // User exists in group
            infile.close();
            return true;
        }
    }
    infile.close();
    return false;
}

bool check_pw_complexity(string password) {
    bool upper = false;
    bool lower = false;
    bool digit = false;
    int min_length = 5;

    if (strlen(password.c_str()) < min_length){
        return false;
    }

    for (std::string::iterator it = password.begin(); it != password.end(); it++){
        char ch = *it;
        upper |= isupper(ch);
        lower |= islower(ch);
        digit |= isdigit(ch);
    }
    return (upper & lower & digit);
}


bool check_for_datastore(const char *fileName) {
    ifstream infile(fileName);
    return infile.good();
}


int bytes2str(unsigned char *in_bytes, int count, char *out_string) {

    char *buff_ptr = out_string;

    for (int i = 0; i < count; i++){
        buff_ptr += sprintf(buff_ptr, "%02X", in_bytes[i]);
    }
    *(buff_ptr + 1) = '\0';

    return 0;
}


int str2bytes(char *in_string, int count, unsigned char *out_bytes){ 

    char *pos = in_string;
    char *ptr;

    if ( (out_bytes[0] == '\0') || (strlen(in_string) % 2) ){
        return -1;
    }

    for (int i = 0; i < count; i++){
        char buf[5] = {'0', 'x', pos[0], pos[1], 0};
        out_bytes[i] = strtol(buf, &ptr, 0);
        pos += 2 * sizeof(char);

        /* Non-hex value */
        if (ptr[0] != '\0'){
            return -1;
        }
    }
    return 0;
}
