/*******************************************************************
 * Header file for client-ws.h
 *******************************************************************/
#include <openssl/pem.h>

int AuthenticateToServer(int server);

// certificates 
STACK_OF(X509) *ReceiveServerCertificateBundle(int server);
int AuthenticateServerUsingCertificate(int server, const char *ca_cert_file, 
                                       EVP_PKEY **pub_key);
int ValidateCertificate(X509 *v_cert, STACK_OF(X509) *t_stack, 
                              STACK_OF(X509) *u_stack);
