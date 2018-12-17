/*******************************************************************
 * Simple chat program (client side)
 *
 * Do not modify this file.
 *
 *******************************************************************/
 
#include <iostream>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <unistd.h>
#include <arpa/inet.h>

#include "client-ws.h"
#include "common.h"
#include "common-ws.h"

using namespace std;

byte *shared_key;		// DHE generated AES-128 key
byte *hmac_key;			// DHE generated HMAC key

EVP_PKEY *peer_pub_key;		// holds the public key of the peer
EVP_PKEY *self_pubpri_key;	// holds public/private key of self

/*******************************************************************/
// Establish a TCP connection to IP <ip> at port <port>
//
// Returns -1 on error, otherwise the connection id

int ConnectToServer(char *ip, int port) {
    // setup a socket
    int server;
    if ((server = socket(AF_INET, SOCK_STREAM, 0)) < 0) 
    {
        cout << "Could not create socket" << endl;
        return -1;
    }

    // connect to server
    struct sockaddr_in server_info;
    server_info.sin_family = AF_INET;
    server_info.sin_port = htons(port);
    
    if(inet_pton(AF_INET, ip, &server_info.sin_addr)<=0) // valid IP?
        return -1;

    if (connect(server,(struct sockaddr *)&server_info, sizeof(server_info)) != 0) 
        return -1;
    
    return server;
}


/*******************************************************************/
// Client-Server non-duplex messaging interface
//   any side can input # to end the chat

void StartChat(int server) {
    string msg;
    
    int buffer_size = 1024;
    byte buffer[buffer_size];
    
    while (true) {
        // get keyboard input and send to server
        cout << "\033[1;31mClient: \033[0m";
        getline(cin, msg);
        if (msg.length() == 0) msg.push_back(' ');
        
        if (EncryptAndSendMessage(server, shared_key, hmac_key, (byte *)msg.c_str(), msg.length()) == FAILURE) {
            cout << "\n[Unable to send message]" << endl;
            break;
        }
        if (msg.at(0) == '#') break; // client done
        
        // wait for server to say something 
        memset(buffer, 0, buffer_size); // zero-ing out receive buffer
        
        if (ReceiveAndDecryptMessage(server, shared_key, hmac_key, buffer, buffer_size-1) == FAILURE) {
            cout << "\n[Unable to retrieve message]" << endl;
            break;
        }

        cout << "\033[1;33mServer: \033[0m" << buffer << endl;

        if (*buffer == '#') break; // server done            
    } 
}

/*******************************************************************/
// Main


int main()
{
    int port = 1234; // port number where server is listening 
    char server_ip[] = "127.0.0.1"; // server ip
    int server;
    
    // initialize openssl
    OpenSSLInit();

    // read RSA keys (no server keys)
    ReadRSAKeys(NULL,"client_keys_and_certs/client_pubpri.pem", NULL, &self_pubpri_key);

    // connect to server
    if ((server = ConnectToServer(server_ip,port)) == -1) { // error!
        cout << "[Unable to connect to " << server_ip << ":" << port << "]\n" << endl;
        exit(1);
    }
        
    // connected
    cout << "\n[Connected to " << server_ip << "]" << endl;
    
    // authenticate server using certificate and get public key
    if (AuthenticateServerUsingCertificate(server, "client_keys_and_certs/ca.crt", &peer_pub_key)==FAILURE) {
        cout << "[Server certificate validation failed]\n" << endl;
        exit(1);
    }    

    // set up shared secret and HMAC keys using DHE
    // server signature checked using public key from certificate

    shared_key = (byte *)malloc(SYM_KEY_SIZE);
    hmac_key   = (byte *)malloc(HMAC_KEY_SIZE);

    int dhe_ret = GenerateVerifiedKeysWithDHE(server, shared_key, hmac_key,
                                self_pubpri_key, peer_pub_key);  
    if (dhe_ret == DHE_FAIL) {
        cout << "[Key setup failed]\n" << endl;
        exit(1);
    }
    else if (dhe_ret == DHE_SUCCESS_NO_AUTH) {
	cout << "[Server authentication failed]\n" << endl;
        exit(1);
    }
    cout << "\n[Key setup complete; server authenticated]\n" << endl;

    // authenticate self 
    if (AuthenticateToServer(server) == FAILURE) {
        cout << "\n[Client authentication failed]\n" << endl;
        exit(1);
    }
    cout << "\n[Client authenticated]\n" << endl;

    // ready to chat 
    cout << "Enter # to end chat\n" << endl;
    StartChat(server);

    // disconnect from server
    cout << "\n[Chat ended]\n" << endl;
    close(server);
    
    // cleanup openssl
    OpenSSLCleanup();

    return 0;
}
