/**********************************************************************
 *
 * P2P with TLS
 *
 * Written by: Tyler Carroll, James Silvia, Tom Strott
 * In completion of: CS557 Project 2
 *
 * A secure P2P storage system
 *
 * peer.cpp
 *
 **********************************************************************/
#include <iostream>
#include <unistd.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#include <string>
#include <list>
#include <sstream>
#include <fstream>
#include <iomanip>
#include <vector>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <stdarg.h>
#include <termios.h>

#include "helpers.hpp"
#include "crypto.hpp"

//TLS begin - include SSL libraries
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/pem.h>
//TLS end

//The backlog for listening
#define BACKLOG 5

//The buffer length for receiving commands
#define BUFFER_LEN 1024

//Login Attempts
#define LOGIN_ATTEMPTS 5

//Max Buffer
#define BUFFER_MAX 256

//Max integer size
#define MAX_SIZE_INT  1000000
#define MAX_DIGIT_INT 7

//datastores
string datastore;
ifstream datastore_in;
ofstream datastore_out;

//Context Container
typedef struct peer_context {
    int port;
    int socket;
    SSL *serverssl;
    char name[BUFFER_MAX];
    unsigned char key[KEY_MAX];
} PEER_CONTEXT_t;


//Using standard namespace
using namespace std;

//peer list
vector<string> peer_list;
vector<int> port_list;
static int peer_list_size = 0;

//Verbose Print Global Variable
static bool verbose = false;

//Verbose printing mode
void printv(char *format, ...){

    if(verbose == false)
        return;

    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
}

/* Error with errno set */
void error(const char * str)
{
    perror(str);
    exit(1);
}

/* Error without errno set */
void error2(const char * str)
{
    cerr << str << endl;
    exit(1);
}

//Get SSL errors - prints the enum for the error, at which point I look it up online to see what it means
//These hardcoded strings are not used anywhere else in the code
int get_errors(SSL *sslerror, int retvalue)
{
    ERR_load_crypto_strings();
    switch(SSL_get_error(sslerror, retvalue))
    {
        case SSL_ERROR_NONE:
            printv("no error\n");
            break;
        case SSL_ERROR_ZERO_RETURN:
            printv("error zero return\n");
            break;
        case SSL_ERROR_WANT_READ:
            printv("error want read\n");
            break;
        case SSL_ERROR_WANT_WRITE:
            printv("error want write\n");
            break;
        case SSL_ERROR_WANT_CONNECT:
            printv("error want connect\n");
            break;
        case SSL_ERROR_WANT_ACCEPT:
            printv("error want accept\n");
            break;
        case SSL_ERROR_WANT_X509_LOOKUP:
            printv("error want x509 lookup\n");
            break;
        case SSL_ERROR_SYSCALL:
            printv("error syscall\n");
            break;
        case SSL_ERROR_SSL:
            printv("error ssl\n");
            break;
        default:
            printv("unknown error\n");
            break;
    }
    return 0;
}

// Handles a client connection
bool handleclient(PEER_CONTEXT_t *peer)
{
    unsigned char cipher[BUFFER_MAX];
    unsigned char decrypted[BUFFER_MAX];
    unsigned char plain[BUFFER_MAX];
    int cipher_len, decrypted_len;

    while (true)
    {
        //Shall we get some data?
        char buffer[BUFFER_LEN + 1] = {0}; //Allow for null.
        string cmd;
        int len = SSL_read(peer->serverssl, buffer, BUFFER_LEN);
        int index, value;

        //Some sort of error
        if (len < 0)
        {
            cerr << "Unable to read from client socket!" << endl;
            break;
        }

        //Disconnected
        if (len == 0)
        {
            printv("The client disconnected!\n");
            break;
        }

        //Grab the command portion
        stringstream strstr(buffer);
        if (!(strstr >> cmd))
            continue;

        if (cmd == "send") {
            //grab the index
            strstr >> cmd;
            index = atoi(cmd.c_str());
            
            //grab the value
            strstr >> cmd;
            value = atoi(cmd.c_str());
            
            // Lets see if it already exists
            bool already_exists = false;
            char copy_buffer[BUFFER_MAX];
            string line;
            while (getline(datastore_in, line)) {
                memset(copy_buffer, 0, sizeof(copy_buffer));
                 strcpy(copy_buffer, line.c_str());
                unsigned char *ciph = (unsigned char *) malloc((line.length()/2)+1);
                // str2bytes
                str2bytes(copy_buffer, line.length()+1, ciph);

                /* Security Stuff */
                memset(decrypted, 0, sizeof(decrypted));
                decrypted_len = decrypt(ciph, strlen((char *)ciph), peer->key, (unsigned char *)HASH, decrypted);
                decrypted[decrypted_len] = '\0';

                // Get the value from datastore
                string data(reinterpret_cast<char*>(decrypted));
                int exists = get_index(index, data);
                // We got it
                if (exists >= 0) {
                    already_exists = true;
                    break;
                }
                free(ciph);
            }

            stringstream response;
            /* Value exists, send response */
            if (already_exists) {
                response << "Sorry, that index already exists. Try again!" << endl;
            } 
            /* Encrypt and store value */
            else {
                stringstream ss;
                ss << index << "," << value;
                cout << "Storing: " << index << "," << value << endl << "-> ";
                cout.flush();
                string to_store = ss.str();
                memset(plain, 0, sizeof(plain));
                strncpy((char *)plain, to_store.c_str(), to_store.length());
                cipher_len = encrypt(plain, strlen((char *)plain), peer->key, (unsigned char*)HASH, cipher);
                cipher[cipher_len] = '\0';
                // bytes2str
                char *out_buff = (char *) malloc((2*cipher_len)+1);
                bytes2str(cipher, cipher_len, out_buff);

                // Store in database
                datastore_out << out_buff << endl;

                response << "Succesfully stored, index: " << index << endl;
            }
                       
            //Send back response
            int len = SSL_write(peer->serverssl, response.str().c_str(), response.str().length());
            if (len != response.str().length())
                error("Unable to send the data!");
        }

        if (cmd == "get") {
            //grab the index
            strstr >> cmd;
            index = atoi(cmd.c_str());
            
            char copy_buffer[BUFFER_MAX];
            /* Get index value from datastore */
            string line;
            while (getline(datastore_in, line)) {
                memset(copy_buffer, 0, sizeof(copy_buffer));
                strcpy(copy_buffer, line.c_str());
                unsigned char *ciph = (unsigned char *) malloc((line.length()/2)+1);
                // str2bytes
                str2bytes(copy_buffer, line.length()+1, ciph);

                /* Security Stuff */
                memset(decrypted, 0, sizeof(decrypted));
                decrypted_len = decrypt(ciph, strlen((char *)ciph), peer->key, (unsigned char *)HASH, decrypted);
                decrypted[decrypted_len] = '\0';

                // Get the value from datastore
                string data(reinterpret_cast<char*>(decrypted));
                value = get_index_value(index, data);
                // We got it
                if (value >= 0) {
                    break;
                }
                free(ciph);
            }

            //Send back response
            stringstream send_data;
            if (value >= 0) {
                send_data << "index: " << index << ", value:  " << value << endl;
            } else {
                send_data << "index: " << index << ", does not exist!!" << endl;
            }
            int len = SSL_write(peer->serverssl, send_data.str().c_str(), send_data.str().length());
            if (len != send_data.str().length())
                error("Unable to send the data!");
        }

        // We need to go back to start of file
        datastore_in.clear();
        datastore_in.seekg(0, ios::beg);
    }

    return true;
}

//function to handle new client as a new thread
void *handleclient_thread(void *newpeer){

    PEER_CONTEXT_t *peer = (PEER_CONTEXT_t*)(newpeer);
    
    handleclient(peer);

    close(peer->socket);
    SSL_free(peer->serverssl);
}

//Main function for server side!
int server(PEER_CONTEXT_t *peer)
{
    //TLS begin
    SSL_CTX *serverctx = NULL;
    
    //method for the server, set to SSL version 3 and also specified as a server so we don't need to set states later
    const SSL_METHOD *servermethod;   
    servermethod = SSLv3_server_method();
    serverctx = SSL_CTX_new(servermethod);

    //Load the server certificate and key, make sure they match
    SSL_CTX_use_certificate_file(serverctx, "./PEM/server-cert.pem", SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file(serverctx, "./PEM/server-key.pem", SSL_FILETYPE_PEM);
    if (!SSL_CTX_check_private_key(serverctx))
    {
        error("couldn't verify private key\n");
        abort();
    }
    else
        printv("verified private key\n");

    //load trust store, basically this specifies that we can trust the client's certificate as long as it is signed by this CA
    if (!SSL_CTX_load_verify_locations(serverctx, "./PEM/ca-cert.pem", NULL))
    {
        error("Can't locate trust store!\n");
    }
    else
        printv("verified trust store\n");

    //Verify in peer mode
    //Depth is 1, as in, the CA should have directly signed the client and server certificates
    SSL_CTX_set_verify(serverctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_verify_depth(serverctx, 1);
    //TLS end 

    struct sockaddr_in serv_addr, cli_addr;
    socklen_t clilen = sizeof(cli_addr);
    pthread_t thread;

    //Create the sock handle
    printv("creating socket\n");
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
        error("Unable to create sock!");
    
    //Clear the structures just incase
    memset(&cli_addr,  0, sizeof(cli_addr));
    memset(&serv_addr, 0, sizeof(serv_addr));
    
    //Fill in the server structure
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(peer->port);
    
    //Bind the socket to a local address
    printv("Binding socket on port %d\n",peer->port);
    if (bind(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
        error("Unable to bind sock!");

    //Begin listening on that port
    if (listen(sock, BACKLOG) < 0)
        error("Unable to listen on sock!");

    bool soldierOn = true;
    while (soldierOn)
    {
        //Accept a new connection!
        printv("Listening for connections...\n");
        int newsock = accept(sock, (struct sockaddr *)&cli_addr, &clilen);
        if (newsock < 0)
            error("Unable to accept connection!");
        peer->socket = newsock;
        
        //TLS begin

        //New SSL token for the server side
        peer->serverssl = SSL_new(serverctx);
        
        //Set_fd basically binds the SSL token to the socket we're using
        //If accept fails we can see why it failed
        SSL_set_fd(peer->serverssl, newsock);
        int ret;
        ret = SSL_accept(peer->serverssl);
        if (ret<1)
        {
            get_errors(peer->serverssl, ret);     
        }
        //TLS end 

        //Start a new thread to handle clients - TC
        printv("Connection made! Starting new thread...\n");
        if(pthread_create(&thread, NULL, handleclient_thread, (void*)peer) < 0)
            error("Unable to create new thread!\n");

    }

    close(sock);
    SSL_CTX_free(serverctx);
    datastore_in.close();
    datastore_out.close();

    //All done.
    return 0;
}

//function to listen for new clients as a new thread
void *startserver_thread(void *newpeer){

    PEER_CONTEXT_t *peer = (PEER_CONTEXT_t*)(newpeer);
    
    server(peer);
}

//Converting the hostname to an IP address
int hostname_to_ip(const char * hostname , char* ip)
{
    struct hostent *he;
    struct in_addr **addr_list;
    int i;

    if ( (he = gethostbyname( hostname ) ) == NULL)
        error2("Unable to get the hostname!");

    addr_list = (struct in_addr **) he->h_addr_list;

    for(i = 0; addr_list[i] != NULL; i++)
    {
        //Return the first one;
        strcpy(ip , inet_ntoa(*addr_list[i]) );
        return 0;
    }

    return 1;
}

//Main function
int main(int argc, char *argv[])
{
    int i;
    int sock;
    int index, value;
    int serverport, clientport;
    struct sockaddr_in cli_addr;
    int clilen = sizeof(cli_addr);
    int readlen;
    char strip[64] = {0};
    pthread_t thread;
    bool serverstarted = false;
    bool first_time = true;
    string temp, master, command;

    /* are we running as root? */
    if(getuid() == 0) {
        cout << "You are running as root! The storage file will be more secure!" << endl;
    } else {
        cout << "You are not running as root!" << endl;
        cout << "We recommend you run this application as a root user" << endl;
        cout << "so the storage file will have elevated privileges!" << endl;
    }
    cout << "We recommend that you back up your storage files for extra protection!" << endl;

    // Server context for pthread
    PEER_CONTEXT_t *peer_context = (PEER_CONTEXT_t *)(malloc(sizeof(PEER_CONTEXT_t)));    

    /* Crypto Stuff */
    OPENSSL_config(NULL);
    unsigned char key[KEY_MAX];
    unsigned char ciphertext[BUFFER_MAX];
    unsigned char decryptedtext[BUFFER_MAX];
    unsigned char plaintext[BUFFER_MAX];
    int ciphertext_len, decryptedtext_len;

    //TLS begin - initialize functions
    //We need these here but once again we may not need them in the server function
    SSL_load_error_strings();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    //create objects
    BIO *certbio = NULL;
    BIO *outbio = NULL;
    BIO *sbio = NULL;
    X509 *cert = NULL;
    X509_NAME *certname = NULL;
    const SSL_METHOD *method;
    SSL_CTX *ctx;
    SSL *ssl;
    int server = 0;
    int ret;
    
    //initialize SSL library and register algorithms
    if (SSL_library_init() < 0)
        printv("Could not initialize OpenSSL library\n");

    //Set client method in SSL version 3
    method = SSLv3_client_method();

    //create new SSL context
    if ((ctx = SSL_CTX_new(method)) == NULL)
        printv("Unable to create a new SSL context struct\n");

    //Load certificate and key on client side, make sure they match
    SSL_CTX_use_certificate_file(ctx, "./PEM/client-cert.pem", SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file(ctx, "./PEM/client-key.pem", SSL_FILETYPE_PEM);
    if (!SSL_CTX_check_private_key(ctx))
    {
        printv("couldn't verify private key\n");
        abort();
    }
    else
        printv("verified private key\n");
    

    //load trust store to specify which CA we trust
    if (!SSL_CTX_load_verify_locations(ctx, "./PEM/ca-cert.pem", NULL))
    {
        printv("Can't locate trust store!\n");
    }
    else
        printv("verified trust store\n");

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

    //create client SSL token
    ssl = SSL_new(ctx);
    //TLS end

    //initialize peer and port lists
    peer_list.push_back("atheon");
    peer_list.push_back("templar");
    peer_list.push_back("gatekeeper");
    peer_list.push_back("oracle");
    port_list.push_back(10311);
    port_list.push_back(10312);
    port_list.push_back(10313);
    port_list.push_back(10314);
    peer_list_size = 4;
 
    /* set tty flags to hide input */
    termios oldt;
    termios newt;
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~ECHO;

    while (true) {
        string str, cmd, name;
        bool loggedin = false;
        bool found_peer = false;

        cout << "Enter your username: ";
        cout.flush();
        getline(cin, name);
        cout << endl;
        
        //Check for peers username in peer list
        for (i = 0; i < peer_list_size; i++) {
            if (strcmp(name.c_str(), peer_list[i].c_str()) == 0) {
                //serverport = port_list[i];
                peer_context->port = port_list[i];
                strcpy(peer_context->name, name.c_str());
                found_peer = true;
                //Each peer has own datastore
                datastore = "store." + name;
            }
        }

        //No peer
        if (!found_peer){
            cout << "That peer does not exist!" << endl;
        } else {
            if (check_for_datastore(datastore.c_str())) {
                first_time = false;
            }
        }

        if (found_peer) {
            /* Setup unique datastore for each server */
            datastore_in.open(datastore.c_str(), fstream::in | fstream::app | ios::binary);
            datastore_out.open(datastore.c_str(), fstream::in | fstream::app | ios::binary);

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
                string line = name + ":" + master;
                memset(plaintext, 0, sizeof(plaintext));
                strncpy((char *)plaintext, line.c_str(), line.length());
                ciphertext_len = encrypt(plaintext, strlen((char *)plaintext), key, (unsigned char*)HASH, ciphertext);
                ciphertext[ciphertext_len] = '\0';
                // bytes2str
                char *buffer = (char *) malloc((2*ciphertext_len)+1);
                bytes2str(ciphertext, ciphertext_len, buffer);
                
                // Save it
                datastore_out << buffer << endl;

                cout << "Great, now logon to verify!" << endl;
                first_time = false;
            }

            /* Login to peer */
            int login_count = 0;
            while (!loggedin) {
                if (login_count >= LOGIN_ATTEMPTS) {
                    cout << "Sorry, you have failed to login." << endl;
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
                while (getline(datastore_in, line)) {
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
                    if (strstr(find_master.c_str(), name.c_str())) {
                        master = find_master.substr(find_master.find(":")+1,string::npos);
                        break;
                    }
                    free(ciphertext);
                }
                /*
                 * wait until we perform encryption so the user cannot
                 * figure out what our password limits are
                 */
                bool verify_password = check_pw_complexity(command);
                if (((strcmp(command.c_str(), master.c_str())) == 0) && verify_password){
                    // Logon banner
                    cout << "Login Successful!" << endl << endl;                    
                    cout << "Valid commands are:" << endl;
                    cout << "\tsend - send an index/value pair to another peer" << endl;
                    cout << "\tget  - retrieve a value for a specific index from another peer" << endl;
                    cout << "\tquit - exit the application" << endl;

                    loggedin = true;
                    strcpy((char *)peer_context->key, (char *)key);
                } else {
                    login_count++;
                    cout << "Login Failure, please try again." << endl;
                    cout << "Login count: " << login_count << "/" << LOGIN_ATTEMPTS << endl;
                }
                // We need to go back to start of file
                datastore_in.clear();
                datastore_in.seekg(0, ios::beg);
            }
        }
        while (loggedin) {

            if (!serverstarted) {
                //spawn server listening on port for that peer
                if (pthread_create(&thread, NULL, startserver_thread, (void*)peer_context) < 0) {
                    error("Unable to create new thread!\n");
                }
                serverstarted = true;
            }

            //Print out a command line
            cout << "-> "; 
            cout.flush();
            getline(cin, str); //Get a full line of text

            //Grab the command portion
            stringstream strstr(str);
            if (!(strstr >> cmd))
                continue;
            
            string peer;
            //Send a key/value pair
            if (cmd == "send") {
                //Ask them what peer to send to
                bool done = false;
                do {
                    cout << "What peer would you like to send to?: ";
                    cout.flush();
                    getline(cin, peer);
                    
                    //find peer connection info
                    if (strcmp(name.c_str(),peer.c_str()) == 0) {
                        cout << "You can not send to yourself!" << endl;
                    } else {
                        for (i = 0; i < peer_list_size; i++) {
                            if (strcmp(peer.c_str(), peer_list[i].c_str()) == 0) {
                                clientport = port_list[i];
                                done = true;
                            }
                        }
                        if (!done && !peer.empty()) {
                            cout << "This peer does not exist!" << endl;
                        }
                    }
                } while (peer.empty() || !done);

                //Ask them what index to use
                done = false;
                do {
                    cout << "What index would you like to send?: ";
                    cout.flush();
                    getline(cin, temp);
                    if (temp.length() > MAX_DIGIT_INT) {
                        cout << "Please enter an integer less than or equal to " << MAX_SIZE_INT << endl;
                        continue;
                    }
                    for (i = 0; i < temp.length(); i++) {
                        if (!isdigit(temp[i]) ) {
                            cout << "Please enter positive integers only!" << endl;
                            done = false;
                            break;
                        }
                        if (!temp.empty()) {
                            done = true;
                        }
                    }
                    if (done) {
                        index = atoi(temp.c_str());
                        if (index > MAX_SIZE_INT) {
                            cout << "Please enter an integer less than or equal to " << MAX_SIZE_INT << endl;
                            done = false;
                        }
                    }
                } while (temp.empty() || !done);

                //Ask them what value to use
                done = false;
                do {
                    cout << "What value would you like to send?: ";
                    cout.flush();
                    getline(cin, temp);
                    if (temp.length() > MAX_DIGIT_INT) {
                        cout << "Please enter an integer less than or equal to " << MAX_SIZE_INT << endl;
                        continue;
                    }
                    for (i = 0; i < temp.length(); i++) {
                        if (!isdigit(temp[i])) {
                            cout << "Please enter positive integers only!" << endl;
                            done = false;
                            break;
                        }
                        if (!temp.empty()) {
                            done = true;
                        }
                    }
                    if (done) {
                        value = atoi(temp.c_str());
                        if (value > MAX_SIZE_INT) {
                            cout << "Please enter an integer less than or equal to " << MAX_SIZE_INT << endl;
                            done = false;
                        }
                    }
                } while (temp.empty() || !done);

                //Clear the structures just incase
                memset(&cli_addr,  0, sizeof(cli_addr));

                //Fill in the server structure
                cli_addr.sin_family = AF_INET;
                cli_addr.sin_port = htons(clientport);
                
                //Get hostname
                if (hostname_to_ip("localhost", strip) != 0)
                    error2("Unable to determine IP from hostname!");

                //Create the sin_addr from the argument
                if (inet_pton(AF_INET, strip, &cli_addr.sin_addr) != 1)
                    error2("Invalid IP address!");
                
                //Close it just incase.
                close(sock);

                //Create the sock handle (TCP Connection)
                sock = socket(AF_INET, SOCK_STREAM, 0);
                if (sock < 0)
                    error("Unable to create sock!");

                //Connect to the target
                if (connect(sock, (struct sockaddr *)&cli_addr, sizeof(cli_addr)) < 0) {
                    cout << "Unable to connet to target address! Peer must not be online" << endl;
                    close(sock);
                    continue;
                }
                
                //TLS begin
                //Use a bio here, specifying BIO_NOCLOSE is what stopped the client from spinning this morning
                //This takes the place of the SSL_set_fd() function
                sbio = BIO_new_socket(sock, BIO_NOCLOSE);
                SSL_set_bio(ssl, sbio, sbio);

                int z = SSL_connect(ssl);
                if (z != 1)
                    get_errors(ssl, z);
                
                //Test to see if we got server certificate
                cert = SSL_get_peer_certificate(ssl);
                if (cert == NULL)
                {
                    cout << "Could not get certificate" << endl;
                }
                else
                {
                    printv("Retrieved server's certificate\n");
                }               
                //TLS end
                
                //Send the data
                stringstream send_data;
                send_data << cmd << " " << index << " " << value << endl;
                int len = SSL_write(ssl, send_data.str().c_str(), send_data.str().length());
                if (len != send_data.str().length())
                    error("Unable to send the data!");
                    
                //Get the response
                char buffer[BUFFER_LEN + 1] = {0};
                len = SSL_read(ssl, buffer, BUFFER_LEN);

                //Some sort of error
                if (len < 0)
                    error("Unable to read from socket.");

                //Disconnected
                if (len == 0)
                    error2("Server disconnected!");
                
                //Print the response
                cout << buffer;
                
                //Close the socket we are done with this transaction
                close(sock);
            }
            
            //Send a key/value pair
            if (cmd == "get") {
                //Ask them what peer to send to
                bool done = false;
                do {
                    cout << "What peer would you like to get a value from?: ";
                    cout.flush();
                    getline(cin, peer);
                    
                    //find peer connection info
                    if (strcmp(name.c_str(),peer.c_str()) == 0) {
                        cout << "You can not get from yourself!" << endl;
                    } else {
                        for (i = 0; i < peer_list_size; i++) {
                            if (strcmp(peer.c_str(), peer_list[i].c_str()) == 0) {
                                clientport = port_list[i];
                                done = true;
                            }
                        }
                        if (!done && !peer.empty()) {
                            cout << "This peer does not exist!" << endl;
                        }
                    }
                } while (peer.empty() || !done);

                //Ask them what index to use
                done = false;
                do {
                    cout << "What index would you like to get?: ";
                    cout.flush();
                    getline(cin, temp);
                    if (temp.length() > MAX_DIGIT_INT) {
                        cout << "Please enter an integer less than or equal to " << MAX_SIZE_INT << endl;
                        continue;
                    }
                    for (i = 0; i < temp.length(); i++) {
                        if (!isdigit(temp[i])) {
                            cout << "Please enter positive integers only!" << endl;
                            done = false;
                            break;
                        }
                        if (!temp.empty()) {
                            done = true;
                        }
                    }
                    if (done) {
                        index = atoi(temp.c_str());
                        if (index > MAX_SIZE_INT) {
                            cout << "Please enter an integer less than or equal to " << MAX_SIZE_INT << endl;
                            done = false;
                        }
                    }
                } while (temp.empty() || !done);

                //Clear the structures just incase
                memset(&cli_addr,  0, sizeof(cli_addr));

                //Fill in the server structure
                cli_addr.sin_family = AF_INET;
                cli_addr.sin_port = htons(clientport);
                
                //Get hostname
                if (hostname_to_ip("localhost", strip) != 0)
                    error2("Unable to determine IP from hostname!");

                //Create the sin_addr from the argument
                if (inet_pton(AF_INET, strip, &cli_addr.sin_addr) != 1)
                    error2("Invalid IP address!");
                
                //Close it just incase.
                close(sock);

                //Create the sock handle (TCP Connection)
                sock = socket(AF_INET, SOCK_STREAM, 0);
                if (sock < 0)
                    error("Unable to create sock!");

                //Connect to the target
                if (connect(sock, (struct sockaddr *)&cli_addr, sizeof(cli_addr)) < 0) {
                    cout << "Unable to connet to target address! Peer must not be online" << endl;
                    close(sock);
                    continue;
                }

                //TLS begin
                //Set up bio, this takes the place of SSL_set_fd() again
                sbio = BIO_new_socket(sock, BIO_NOCLOSE);
                SSL_set_bio(ssl, sbio, sbio);   

                //Connect and report errors
                int z = SSL_connect(ssl);
                if (z != 1)
                    get_errors(ssl, z);
                
                //Check for server's certificate
                cert = SSL_get_peer_certificate(ssl);
                if (cert == NULL)
                {
                    cout << "Could not get certificate" << endl;
                }
                else
                {
                    printv("Retrieved server's certificate\n");
                }               
                //TLS end
                
                //Send the data
                stringstream send_data;
                send_data << cmd << " " << index << endl;
                int len = SSL_write(ssl, send_data.str().c_str(), send_data.str().length());
                if (len != send_data.str().length())
                    error("Unable to send the data!");

                //Get the response
                char buffer[BUFFER_LEN + 1] = {0};
                len = SSL_read(ssl, buffer, BUFFER_LEN);

                //Some sort of error
                if (len < 0)
                    error("Unable to read from socket.");

                //Disconnected
                if (len == 0)
                    error2("Server disconnected!");
                
                //Print the response
                cout << buffer;
                
                //Close the socket we are done with this transaction
                close(sock);
            }

            if (!( (cmd == "send")||(cmd == "get")||(cmd == "quit") )) {
                cout << "Valid commands are:" << endl;
                cout << "\tsend - send an index/value pair to another peer" << endl;
                cout << "\tget  - retrieve a value for a specific index from another peer" << endl;
                cout << "\tquit - exit the application" << endl;
            }

            //Quit
            if (cmd == "quit")
            {
                close(sock);
                SSL_free(ssl);
                X509_free(cert);
                SSL_CTX_free(ctx);
                return 0;
            }
        }
    }

    return 0;
}
