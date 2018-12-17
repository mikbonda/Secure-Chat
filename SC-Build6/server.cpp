/*******************************************************************
 * Simple chat program (server side)
 *
 * Do not modify this file.
 *
 *******************************************************************/
 
#include <iostream>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <csignal>
#include <unistd.h>
#include <arpa/inet.h>

#include "server-ws.h"
#include "common.h"
#include "common-ws.h"

using namespace std;

byte *shared_key;		// DHE generated AES-128 key
byte *hmac_key;			// DHE generated hmac key

EVP_PKEY *self_pubpri_key;	// holds public/private key of self

/*******************************************************************/
// Handler for ^C -- aborts server

void AbortServer(int s) {
    // cleanup openssl
    OpenSSLCleanup();

    cout << "\r                 \n[Server aborted]\n" << endl;
    exit(1);
}

/*******************************************************************/
// Start server to listen on port <port>; 
//  
// Returns -1 on error, otherwise the connection id

int SetupServer(int port) {
    int server;
    struct sockaddr_in server_info;
    
    // setup server socket
    if ((server = socket(AF_INET, SOCK_STREAM, 0)) < 0) 
    {
        cout << "Could not create socket" << endl;
        return -1;
    }

    // enable socket reuse (for quick restart after failure)
    int enable = 1;
    setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int));

    // bind socket
    server_info.sin_family = AF_INET;
    server_info.sin_addr.s_addr = htons(INADDR_ANY);
    server_info.sin_port = htons(port);

    if ((bind(server, (struct sockaddr*)&server_info,sizeof(server_info))) < 0) 
    {
        cout << "Could not bind to port " << port << endl;
        return -1;
    }
    
    // listen for a client
    listen(server, 1);
    
    return server;
}

/*******************************************************************/
// Accepts connections to server socket <server> and <client_info> 
//  is populated on successful connection
//
// Returns a client connection id

int WaitForConnection(int server, int port, struct sockaddr_in *client_info) {
    int client;
    socklen_t size = sizeof(struct sockaddr);
    
    do {
        cout << "\n[Waiting for connection on port " << port << " -- ^C to exit]\n" << endl;
    
        // wait until a connection is received from a client
        client = accept(server,(struct sockaddr *)client_info,&size);
        
        if (client < 0) // any error?
            cout << "[Error while accepting a new connection]" << endl;
            
    } while (client < 0);
    
    return client;
}


/*******************************************************************/
// Client-Server non-duplex messaging interface
//   any side can input # to end the chat

void StartChat(int client) {
    string msg;
    
    int buffer_size = 1024;
    byte buffer[buffer_size];
    
    while (true) {
        // wait for client to say something
        memset(buffer, 0, buffer_size); // zero-ing out receive buffer
        
        if (ReceiveAndDecryptMessage(client, shared_key, hmac_key, buffer, buffer_size-1) == FAILURE) {
            cout << "\n[Unable to retrieve message]" << endl;
            break;
        }

        cout << "\033[1;31mClient: \033[0m" << buffer << endl;
        if (*buffer == '#') break; // client done
        
        // get keyboard input on server side and send to client
        cout << "\033[1;33mServer: \033[0m";
        getline(cin,msg);
        if (msg.length() == 0) msg.push_back(' ');

        if (EncryptAndSendMessage(client, shared_key, hmac_key, (byte *)msg.c_str(), msg.length()) == FAILURE) {
            cout << "\n[Unable to send message]" << endl;
            break;
        }
        if (msg.at(0) == '#') break; // server done
    }
}

/*******************************************************************/
// Main

int main() {

    int port = 1234;
    int client, server;
    struct sockaddr_in client_info;
    
    int dhe_ret;

    // initialize openssl
    OpenSSLInit();

    // read RSA keys (no client keys)
    ReadRSAKeys(NULL,"server_keys_and_certs/server_pubpri.pem", NULL, &self_pubpri_key);

    // setup Ctrl+C handler
    signal(SIGINT, AbortServer);

    // start server listening
    if ((server = SetupServer(port)) == -1) exit(1); // error!
    
    do { // infinite loop (press ctrl+C to exit)

        // wait for a connection
        client = WaitForConnection(server, port, &client_info);
        
        // connected
        cout << "---------------------------" << endl;
        cout << "[Connected with client " << inet_ntoa(client_info.sin_addr)
                                             << ":" 
                                             << ntohs(client_info.sin_port) 
                                             << "]\n" << endl;
            

        // send certificate bundle
        if (SendServerCertificateBundle(client, "server_keys_and_certs/certbundle.crt")==FAILURE)
            goto done;

        // set up shared secret and HMAC keys using DHE
        shared_key = (byte *)malloc(SYM_KEY_SIZE);
        hmac_key   = (byte *)malloc(HMAC_KEY_SIZE);

        dhe_ret = GenerateVerifiedKeysWithDHE(client, shared_key, hmac_key,
                                self_pubpri_key, NULL); // no check on client signature

        if (dhe_ret == DHE_FAIL) {
            cout << "[Key setup failed]\n" << endl;
            goto done;
        }
        else if (dhe_ret == DHE_SUCCESS_NO_AUTH) {
	    cout << "[Key setup complete; client NOT authenticated]\n" << endl;
            //goto done;
        }
        else cout << "[Key setup complete; client authenticated]\n" << endl;

	// authenticate client                                 
        if (AuthenticateClient(client)==FAILURE) {
            cout << "[Client authentication failed]\n" << endl;
            goto done;
        }
	cout << "[Client authenticated]\n" << endl; 
        
        // ready to chat 
        StartChat(client);
    

        done:

        // close connection to client
        cout << "\n[Connection terminated with client " 
                << inet_ntoa(client_info.sin_addr) << "]" << endl;
        cout << "---------------------------" << endl;     
        close(client);
        
    } while (true); // runs until ^C is pressed

    close(server);
    return 0;
}
