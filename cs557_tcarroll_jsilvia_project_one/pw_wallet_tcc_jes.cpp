/**********************************************************************
 *
 * Password Wallet
 *
 * Written by: Tyler Carroll and James Silvia
 * In completion of: CS557 Project 1
 *
 * A secure wallet to store passwords
 *
 * pw_wallet_tcc_jes.cpp
 *
 **********************************************************************/
#include <unistd.h>
#include <sys/types.h>
#include <list>
#include <sstream>
#include <fstream>
#include <errno.h>
#include <termios.h>

#include "crypto.hpp"

#define WALLET          "wallet.txt"
#define TEMP            "temp.txt"
#define LOGIN_ATTEMPTS  5
#define BUFFER_MAX      128

bool check_for_wallet(const char *fileName);
bool check_pw_complexity(string password);
int bytes2str(unsigned char *in_bytes, int count, char *out_string);
int str2bytes(char *in_string, int count, unsigned char *out_bytes);
void handleErrors(void);

int main(int argc, char *argv[])
{
    string master, command, tmp, name, pw, yn;
    bool login = false;
    bool first_time = true;

    unsigned char key[KEY_MAX];
    unsigned char ciphertext[BUFFER_MAX];
    unsigned char decryptedtext[BUFFER_MAX];
    unsigned char plaintext[BUFFER_MAX];
    int ciphertext_len, decryptedtext_len;

    /* are we running as root? */
    if(getuid() == 0) {
        cout << "You are running as root! The password file will be more secure!" << endl;
    } else {
        cout << "You are not running as root!" << endl;
        cout << "We recommend you run this application as a root user" << endl;
        cout << "so the password wallet will have elevated privileges!" << endl;
    }

    /* initialize crypto libray */
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    OPENSSL_config(NULL);
 
    /* set tty flags to hide input */
    termios oldt;
    termios newt;
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~ECHO;

    /* Check if a wallet exists */
    if (check_for_wallet(WALLET)) {
        first_time = false;
    }
   
    /* open password wallet file */
    ifstream wallet_in;
    ofstream wallet_out;
    ofstream temp_out;

    /* use different streams for input and output */
    wallet_in.open(WALLET, fstream::in | fstream::app | ios::binary);
    wallet_out.open(WALLET, fstream::out | fstream::app | ios::binary);

    /* enter master password for first time login */
    if (first_time) {
        cout << "First time login, enter your master password: ";
        cout.flush();
        tcsetattr(STDIN_FILENO, TCSANOW, &newt);
        getline(cin, master);
        tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
        cout << endl;

        bool verify_password = check_pw_complexity(master);
        while (!verify_password){
            cout << "Please enter valid password." << endl;
            cout << "It must exceed 5 characters, and contain at least (1) lowercase, (1) uppercase, (1) number..." << endl;
            cout << endl;
            cout << "Try again: ";
            cout.flush();
            tcsetattr(STDIN_FILENO, TCSANOW, &newt);
            getline(cin, master);
            tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
            cout << endl;
            verify_password = check_pw_complexity(master);
        }

        /* Security Stuff */
        memset(key, 0, sizeof(key));
        create_sha256(master, key);
        string line = "master:" + master;
        memset(plaintext, 0, sizeof(plaintext));
        strncpy((char *)plaintext, line.c_str(), line.length());
        ciphertext_len = encrypt(plaintext, strlen((char *)plaintext), key, (unsigned char*)HASH, ciphertext);
        ciphertext[ciphertext_len] = '\0';
        // bytes2str
        char *buffer = (char *) malloc((2*ciphertext_len)+1);
        bytes2str(ciphertext, ciphertext_len, buffer);

        wallet_out << buffer << endl;

        cout << "Great, now logon to verify!" << endl;
    }

    /* Login for wallet access */
    int login_count = 0;
    while (!login) {
        if (login_count >= LOGIN_ATTEMPTS) {
            cout << "Sorry, you have failed to login." << endl;
            cout << "For your own protection, we have emptied your wallet." << endl;
            cout << "Please restore from a backup!" << endl;
            remove(WALLET);
            exit(0);
        }
        
        cout << "Enter Password: ";
        cout.flush();
        tcsetattr(STDIN_FILENO, TCSANOW, &newt);
        getline(cin, command);
        tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
        cout << endl;

        /* Get key for decryption */
        master.clear();
        memset(key, 0, sizeof(key));
        create_sha256(command, key);      

        string line;
        while (getline(wallet_in, line)) {
            /* Get line */
            char buffer[BUFFER_MAX];
            strcpy(buffer, line.c_str());
            // str2bytes
            unsigned char *ciphertext = (unsigned char *) malloc((line.length()/2)+1);
            str2bytes(buffer, line.length()+1, ciphertext);

            /* Security Stuff */
            memset(decryptedtext, 0, sizeof(decryptedtext));
            decryptedtext_len = decrypt(ciphertext, strlen((char *)ciphertext), key, (unsigned char *)HASH, decryptedtext);
            decryptedtext[decryptedtext_len] = '\0';
            
            // Master?
            string find_master(reinterpret_cast<char*>(decryptedtext));
            if (strstr(find_master.c_str(),"master")) {
                master = find_master.substr(find_master.find(":")+1,string::npos);
                first_time = false;
                break;
            }
            free(ciphertext);
        }

        /* 
         * wait until we perform encryption so the user cannot
         * figure out what our password limits are
         */
        bool verify_password = check_pw_complexity(command);

        /* check to see if login is successful */
        if (((strcmp(command.c_str(), master.c_str())) == 0) && verify_password) {
            cout << "Login Successful!" << endl;
            cout << endl;

            /* Display banner on successful login */
            cout << "Welcome to the password wallet!" << endl;
            cout << "Remember to back up your wallet.txt file in the event" << endl;
            cout << "of a corruption from an untrusted party" << endl;
            cout << "Valid commands are:" << endl;
            cout << "\tadd - add a password to the wallet" << endl;
            cout << "\tlist - retrieve a password from the wallet" << endl;
            cout << "\tremove - remove a password from the wallet" << endl;
            cout << "\tquit - exit the application" << endl;

            login = true;
        } else {
            login_count++;
            cout << "Login Failure, please try again." << endl;
            cout << "Login count: " << login_count << "/" << LOGIN_ATTEMPTS << endl;
        }

        // We need to go back to start of file
        wallet_in.clear();
        wallet_in.seekg(0, ios::beg);
    }
    
    /* Send/Recieve commands */
    while (login) {

        /* Get the first word and see what command it is */
        cout << "-> ";
        cout.flush();
        getline(cin, command);

        stringstream temp(command);

        if (!(temp >> tmp)) {
            continue;
        } else if (!( (tmp == "add")||(tmp == "remove")||(tmp == "list")||(tmp == "quit") )) {
            cout << "Valid commands are:" << endl;
            cout << "\tadd - add a password to the wallet" << endl;
            cout << "\tlist - retrieve a password from the wallet" << endl;
            cout << "\tremove - remove a password from the wallet" << endl;
            cout << "\tquit - exit the application" << endl;
            continue;
        } else if(tmp == "add") {
            do {
                cout << "Please enter the name to associate with the password: ";
                cout.flush();
                getline(cin, name);
            } while (name.empty());

            if (!name.compare("master")){
                cout << "Sorry, we do not permit the list of the master password." << endl;
                continue;
            }

            /* check to see if this entry already exists */
            bool found_it = false;
            string temp;
            while (getline(wallet_in, temp)) {
                /* Get temp */
                char buffer[BUFFER_MAX];
                strcpy(buffer, temp.c_str());
                // str2bytes
                unsigned char *ciphertext = (unsigned char *) malloc((temp.length()/2)+1);
                str2bytes(buffer, temp.length()+1, ciphertext);

                /* Security Stuff */
                memset(decryptedtext, 0, sizeof(decryptedtext));
                decryptedtext_len = decrypt(ciphertext, strlen((char *)ciphertext), key, (unsigned char *)HASH, decryptedtext);
                decryptedtext[decryptedtext_len] = '\0';
            
                // You there ?
                string find_pw(reinterpret_cast<char*>(decryptedtext));
                if (name.compare(find_pw.substr(0, find_pw.find(":"))) == 0) {
                    found_it = true;
                    pw = find_pw.substr(find_pw.find(":")+1,string::npos);
                }
                free(ciphertext);
            }

            // We need to go back to start of file
            wallet_in.clear();
            wallet_in.seekg(0, ios::beg);

            if (found_it){
                cout << "Sorry, that name already exists in your wallet." << endl;
                continue;
            }
            
            cout << "Do you want us to auto generate a stored password for you?" << endl;
            do {
                cout << "Please pick y or n: ";
                cout.flush();
                getline(cin, yn);
            } while (yn != "y" && yn != "n");

            /* clear old password */
            pw.clear();
            if (yn == "y") {
                srand(time(0));
                for(unsigned int i = 0; i < 20; ++i) {
                    pw += genRandom();
                }
            } else {
                cout << "Please enter the password: ";
                cout.flush();
                tcsetattr(STDIN_FILENO, TCSANOW, &newt);
                getline(cin, pw);
                tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
                cout << endl;
            }

            /* Lets encrypt and store */
            string line = name + ":" + pw;
            memset(plaintext, 0, sizeof(plaintext));
            strncpy((char *)plaintext, line.c_str(), line.length());
            ciphertext_len = encrypt(plaintext, strlen((char *)plaintext), key, (unsigned char*)HASH, ciphertext);
            ciphertext[ciphertext_len] = '\0';
            // bytes2str
            char *buffer = (char *) malloc((2*ciphertext_len)+1);
            bytes2str(ciphertext, ciphertext_len, buffer);

            wallet_out << buffer << endl;

            cout << "Stored in password wallet!" << endl;
            
        } else if(tmp == "remove") {
            bool found_it = false;

            /* open up stream to temporary file */
            temp_out.open(TEMP, fstream::out | fstream::app | ios::binary);

            do {
                cout << "Please enter the name of the password you are looking to remove: ";
                cout.flush();
                getline(cin, name);
            } while (name.empty());

            if (!name.compare("master")){
                cout << "Sorry, we do not permit the list of the master password." << endl;
                continue;
            }

            string line;
            while (getline(wallet_in, line)) {
                /* Get line */
                char buffer[BUFFER_MAX];
                strcpy(buffer, line.c_str());
                // str2bytes
                unsigned char *ciphertext = (unsigned char *) malloc((line.length()/2)+1);
                str2bytes(buffer, line.length()+1, ciphertext);

                /* Security Stuff */
                memset(decryptedtext, 0, sizeof(decryptedtext));
                decryptedtext_len = decrypt(ciphertext, strlen((char *)ciphertext), key, (unsigned char *)HASH, decryptedtext);
                decryptedtext[decryptedtext_len] = '\0';
            
                // You there ?
                string find_pw(reinterpret_cast<char*>(decryptedtext));
                if (name.compare(find_pw.substr(0, find_pw.find(":"))) == 0) {
                    found_it = true;
                    pw = find_pw.substr(find_pw.find(":")+1,string::npos);
                } else {
                    temp_out << line << endl;
                }
                free(ciphertext);
            }
            /* close stream to temporary file */
            temp_out.close();
            if (!found_it) {
                /* they didnt have that name, no need to do anything, remove
                 * temp file
                 */
                cout << "Sorry, that name does not exist in your wallet." << endl;
                remove(TEMP);
            } else {
                /* we found the name, close streams, rename temp file as wallet.txt,
                 * then reopen streams */
                wallet_in.close();
                wallet_out.close();
                remove(WALLET);
                rename(TEMP, WALLET);
                wallet_in.open(WALLET, fstream::in | fstream::app | ios::binary);
                wallet_out.open(WALLET, fstream::out | fstream::app | ios::binary);
                cout << "The password for " << name << " has been removed from your wallet" << endl; 
            }
            // We need to go back to start of file
            wallet_in.clear();
            wallet_in.seekg(0, ios::beg);

        } else if(tmp == "list") {
            bool found_it = false;

            do {
                cout << "Please enter the name of the password you are looking for: ";
                cout.flush();
                getline(cin, name);
            } while (name.empty());

            if (!name.compare("master")){
                cout << "Sorry, we do not permit the list of the master password." << endl;
                continue;
            }

            string line;
            while (getline(wallet_in, line)) {
                /* Get line */
                char buffer[BUFFER_MAX];
                strcpy(buffer, line.c_str());
                // str2bytes
                unsigned char *ciphertext = (unsigned char *) malloc((line.length()/2)+1);
                str2bytes(buffer, line.length()+1, ciphertext);

                /* Security Stuff */
                memset(decryptedtext, 0, sizeof(decryptedtext));
                decryptedtext_len = decrypt(ciphertext, strlen((char *)ciphertext), key, (unsigned char *)HASH, decryptedtext);
                decryptedtext[decryptedtext_len] = '\0';
            
                // You there ?
                string find_pw(reinterpret_cast<char*>(decryptedtext));
                if (name.compare(find_pw.substr(0, find_pw.find(":"))) == 0) {
                    found_it = true;
                    pw = find_pw.substr(find_pw.find(":")+1,string::npos);
                    cout << "The password for " << name << " is: " << pw << endl; 
                }
                free(ciphertext);
            }
            if (!found_it){
                cout << "Sorry, that name does not exist in your wallet." << endl;
            }

            // We need to go back to start of file
            wallet_in.clear();
            wallet_in.seekg(0, ios::beg);

        } else if (tmp == "quit") {
            cout << "Logging out" << endl;
            login = false;
            break;
        }   

    }

    wallet_in.close();
    wallet_out.close();

    exit(0);
}

bool check_pw_complexity(string password)
{
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

bool check_for_wallet(const char *fileName)
{
    ifstream infile(fileName);
    return infile.good();
}

int bytes2str(unsigned char *in_bytes, int count, char *out_string){

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
