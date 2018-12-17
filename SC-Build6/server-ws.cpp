/*******************************************************************
 * This is your workspace to modify the server application.
 *
 * This is the ONLY server file you will modify in the assignment,
 * but can call any other function in common.cpp and common-ws.cp.
 *
 * You should not modify any other server file in the application.
 *
 * Only implement the TODO blocks.
 * Do not uncomment statements unless explicitly mentioned.
 *
 * To create the server executable:
 *   chmod u+x makeserver    [needed only once]
 *   ./makeserver
 *
 *******************************************************************/

#include <iostream>
#include <cstring>
#include <cstdio>
#include <cstdlib>

#include <openssl/evp.h>
#include <openssl/pem.h>

#include "server-ws.h"
#include "common.h"
#include "common-ws.h"

using namespace std;

/*******************************************************************/
// Send the certificate bundle from file <bundle_file>
//    to <client>; max of 255 certificates allowed
//
// First certificate should be the server's certificate; subsequent
//   ones can be present to prove chain to a CA
//    
// Returns SUCCESS (1) or FAILURE (0)

int SendServerCertificateBundle(int client, const char *bundle_file) {

    FILE *fp;
    bytes_t cert_data;
    X509 *cert;
    STACK_OF(X509) *certs;
    int num_certs;

    int ret = FAILURE;

    // read certificates from file into stack
    if((fp = fopen(bundle_file, "r"))==NULL) return FAILURE;

    if ((certs = sk_X509_new_null())==NULL) return FAILURE;

    while (cert = PEM_read_X509(fp,NULL,NULL,NULL)) {
        if (cert) sk_X509_push(certs,cert);
        else goto done;
    }

    fclose(fp);

    // send number of certificates and then the bundle (max 255)
    num_certs = sk_X509_num(certs);

    if (num_certs <=0 || num_certs > 255) num_certs = 0;

    if (SendAMessage(client, (byte *)&num_certs, 1) < 0) goto done;

    for (int i=0; i < num_certs; i++) {
        cert = sk_X509_value(certs, i);

        cert_data.value = NULL;
        cert_data.len = i2d_X509(cert, &cert_data.value); // convert X509 to bytes

        if (SendBytes(client, &cert_data)==FAILURE) goto done;

        OPENSSL_free(cert_data.value);
    }

    ret = (num_certs != 0);

    done:

    // cleanup
    sk_X509_pop_free(certs,X509_free);

    return num_certs != 0;
}
