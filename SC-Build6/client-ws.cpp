/*******************************************************************
 * This is your workspace to modify the client application.
 *
 * This is the ONLY client file you will modify in the assignment,
 * but can call any other function in common.cpp and common-ws.cp.
 *
 * You should not modify any other client file in the application.
 *
 * Only implement the TODO blocks.
 * Do not uncomment statements unless explicitly mentioned.
 *
 * To create the client executable:
 *   chmod u+x makeclient    [needed only once]
 *   ./makeclient
 *
 *******************************************************************/

#include <iostream>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>


#include "client-ws.h"
#include "common.h"
#include "common-ws.h"

using namespace std;


/*******************************************************************/
// Returns a stack of X509 certificates received from
//   <server>

STACK_OF(X509) *ReceiveServerCertificateBundle(int server) {

    bytes_t cert_data;
    X509 *cert;
    STACK_OF(X509) *certs = NULL;

    // get number of certificates coming
    byte num_certs; // number of certificates in bundle
    if (ReceiveAMessage(server, &num_certs, 1) < 0) return NULL;

    if (num_certs == 0) return NULL;

    // initialize stack
    if ((certs = sk_X509_new_null())==NULL) return NULL;

    // add certificates to stack
    for (int i=0; i < num_certs; i++) {
        if (ReceiveBytes(server, &cert_data)==FAILURE) { // receive a certificate
		sk_X509_pop_free(certs, X509_free);
                return NULL;
        }

        // convert bytes to X509 certificate
        cert = d2i_X509(NULL, (const unsigned char **)&cert_data.value, (long) cert_data.len);

        if (cert != NULL) sk_X509_push(certs,cert); // push to stack
        else {
            sk_X509_pop_free(certs,X509_free);
            return NULL;
        }

        delete(cert_data.value-cert_data.len); // d2i_X509 increments the pointer!
    }
 
    return certs;
}

/*******************************************************************/
// Authenticates <server> by receiving a X509 certificate (bundle)
//    and extracts public key of server if successful; 
//    the root CA certificate file in passed in <ca_cert_file>;
//    the extracted public key of server is written to <pub_key>
//
// Returns SUCCESS or FAILURE
//
// Read assignment description for more information

int AuthenticateServerUsingCertificate(int server, const char *ca_cert_file, 
                                       EVP_PKEY **pub_key) {

    int ret = FAILURE;

    STACK_OF(X509) *cert_chain = NULL, *trusted_stack = NULL;
    X509 *server_cert = NULL;

    FILE *fp;

    // TODO: receive the certificate bundle from server
    //       store in cert_chain



    // TODO: read root CA certificate from file and store in stack
    //       store in trusted_stack
    if ((fp = fopen(ca_cert_file,"r"))==NULL) goto done;
    
    
   

    // TODO: get the certificate to verify (first one in cert_chain)
    //       store in server_cert



    // print some status
    char cn[128]; 
    if (server_cert)
        X509_NAME_get_text_by_NID(X509_get_subject_name(server_cert), NID_commonName, cn, 127);
    cout << "\n[Verifying " << (server_cert?cn:"<NULL>") << " certificate...";

    // TODO: validate server certificate
    //       store result of validation in ret




    // process validation result
    if (ret == FAILURE) {
        *pub_key = NULL;
        cout << " / FAIL]\n";
    } 
    else {
        // extract public key of server
        *pub_key = X509_get_pubkey(server_cert);
        cout << "OK]\n";
    }


    done:

    // clean up
    sk_X509_pop_free(trusted_stack, X509_free);
    sk_X509_pop_free(cert_chain, X509_free);
    X509_free(server_cert);

    return ret;
}

/*******************************************************************/
// Validate a certificate <v_cert> using trusted certificates
//    <t_stack> and untrusted chain <u_stack>
//
// If validation fails, the reason is printed
//
// Returns SUCCESS or FAILURE


int ValidateCertificate(X509 *v_cert, STACK_OF(X509) *t_stack, 
                              STACK_OF(X509) *u_stack) {
    

    X509_STORE *store;
    X509_STORE_CTX *ctx;

    int ret = FAILURE;
    int cert_error;

    // setup store context
    if ((store = X509_STORE_new())==NULL) goto done;
    if ((ctx = X509_STORE_CTX_new())==NULL) goto done;

    // initialize store context
    if (1 != X509_STORE_CTX_init(ctx, store, v_cert, u_stack)) goto done;
    X509_STORE_CTX_trusted_stack(ctx, t_stack);

    // verify server certificate
    if (X509_verify_cert(ctx) != 1) { // print reason of failure
        cert_error = X509_STORE_CTX_get_error(ctx);
        cout << X509_verify_cert_error_string(cert_error);
    }
    else ret = SUCCESS;

    done: 

    // clean up
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);

    return ret;
}
