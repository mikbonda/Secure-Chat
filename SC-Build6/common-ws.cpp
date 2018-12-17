/*******************************************************************
 * This is your workspace to modify common functions of the 
 * application.
 *
 * This is the ONLY common file you will modify in the assignment,
 * but can call any other function in common.cpp.
 *
 * You should not modify common.cpp in the application.
 *
 * Only implement the TODO blocks.
 * Do not uncomment statements unless explicitly mentioned.
 *
 * To create the server executable:
 *   chmod u+x makeserver    [needed only once]
 *   ./makeserver
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
#include <arpa/inet.h>

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include "common.h"
#include "common-ws.h"

using namespace std;


/*******************************************************************/
//  Extract the public key from keypair <key> and write to
//   <pkey> in bytes_t format; also, sign the key using
//   private key <pri_key> and write signature in <pkey_sign>
//
//  Returns DHE_FAIL or DHE_SUCCESS
//
// Read assignment description for more information

int GetBytesAndSignatureFromPublicKey(EVP_PKEY *key, EVP_PKEY *pri_key, 
                                      bytes_t **pkey, bytes_t *pkey_sign) {
    int ret = DHE_FAIL;
    EVP_MD_CTX *mdctx = NULL;
    // get the public key
    if ((*pkey = GetBytesFromPublicKey(key)) == NULL) return DHE_FAIL;

    // TODO: create the message digest context 
    if(!(mdctx = EVP_MD_CTX_create())) 
        goto done;
    // TODO: initialise the DigestSign operation - we will use SHA-256 as the message digest function
    if(1 != EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, pri_key)) 
        goto done;
    // TODO: call update with the message
    if(1 != EVP_DigestUpdate(mdctx, (**pkey).value, (**pkey).len)) 
        goto done;
    // TODO: obtain the length of the signature
    //                                          *pkey_sign->len fails
    if(1 != EVP_DigestSignFinal(mdctx, NULL, &(*pkey_sign).len))
        goto done;
    // std::cout << "The length is: " << (*pkey_sign).len << std::endl;
    // std::cout << "The length is: " << pkey_sign->len << std::endl;
    // TODO: allocate memory for the signature
     if(!((*pkey_sign).value = (byte *)OPENSSL_malloc(pkey_sign->len)))
        goto done;
    // std::cout << "The pkey_sign.value is: " << (*pkey_sign).value << std::endl;
    // TODO: obtain the signature
    if(1 != EVP_DigestSignFinal(mdctx, pkey_sign->value, &(*pkey_sign).len)) 
        goto done;
    // TODO: set ret to SUCCESS

    ret = DHE_SUCCESS;

    done:

    // clean up
    if (pkey_sign->value && ret == DHE_FAIL) OPENSSL_free(pkey_sign->value);
    EVP_MD_CTX_destroy(mdctx);    

    return ret;
}

/*******************************************************************/
// Create a EVP_PKEY <key> from <keydata>, and verify if <signature>
//   was generated using the private key corresponding to
//   public key <pub_key>
//
// If <pub_key> is NULL, then no signature verification is done
//
// Returns
//   DHE_SUCCESS_NO_AUTH: key extracted, but no signature verification
//   DHE_SUCCESS: key extracted and signature matches
//   DHE_FAIL: error
//
// Read assignment description for more information

int VerifyAndGetPublicKeyFromBytes(bytes_t keydata, bytes_t signature,
                                    EVP_PKEY *pub_key, EVP_PKEY **key) {

    int ret = DHE_FAIL;
    EVP_MD_CTX *mdctx = NULL;

    // get the public key
    *key = GetPublicKeyFromBytes(keydata);
    if (*key == NULL) return DHE_FAIL;

    if (pub_key != NULL) { // verify if pub_key is provided

        // TODO: create the message digest dontext
        if(!(mdctx = EVP_MD_CTX_create())) goto done;
        // TODO: initialize with a public key (pub_key)
        if(1 != EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, pub_key)) goto done;
        // TODO: call update to compute digest
         if(1 != EVP_DigestUpdate(mdctx, keydata.value , keydata.len)) goto done;
        // TODO: verify signature and set ret to DHE_SUCCESS or DHE_SUCCESS_NO_AUTH
        if(1 == EVP_DigestVerifyFinal(mdctx, signature.value, signature.len)){
            /* Success */
            ret = DHE_SUCCESS;
        }
        else{
            /* Failure */
            ret = DHE_SUCCESS_NO_AUTH;
        }
        done:
        // clean up
        EVP_MD_CTX_destroy(mdctx);  
    }
    else 
        ret = DHE_SUCCESS_NO_AUTH;  // success, signature not verified

    return ret;
}

/*******************************************************************/
// Generate symmetric key and HMAC key using DHE with <peer>;
//   the syymetric key is written to s_key
//   the HMAC key is written to h_key
//   both buffers should have been pre-allocated
//
// The DHE public key sent to the peer is signed using private
//   key <self_pri_key>
// The DHE public key received from the peer is verified using
//  public key <peer_pub_key> if it is not NULL
//
// Returns SUCCESS or FAILURE

int GenerateVerifiedKeysWithDHE(int peer, byte *s_key, byte *h_key,
                                EVP_PKEY *self_pri_key, EVP_PKEY *peer_pub_key) {

    EVP_PKEY *params = NULL, *dhkey = NULL;
    EVP_PKEY_CTX *kctx = NULL;

    bytes_t *pkey = NULL, pkey_sign;
    int dhe_ret;

    bytes_t keydata, signature;
    EVP_PKEY *peerkey = NULL;
    int ver_ret;

    EVP_PKEY_CTX *ctx = NULL;
    bytes_t ss; // the shared secret

    bytes_t ss_digest; 

    int ret = DHE_FAIL;

    //*** Generate public/private key pair *********************

    // using IETF RFC 5114 parameters
    if(NULL == (params = EVP_PKEY_new())) 
        goto done;
    if(1 != EVP_PKEY_set1_DH(params,DH_get_2048_256())) 
        goto done;

    // create context for the key generation 
    if(!(kctx = EVP_PKEY_CTX_new(params, NULL))) 
        goto done;

    // generate a new key pair
    if(1 != EVP_PKEY_keygen_init(kctx)) 
        goto done;
    if(NULL == (dhkey = EVP_PKEY_new())) 
        goto done;
    if(1 != EVP_PKEY_keygen(kctx, &dhkey))
        goto done;

    //*** Send public key and signature to peer *****************

    if (GetBytesAndSignatureFromPublicKey(dhkey, self_pri_key, &pkey, &pkey_sign)==DHE_FAIL)
        goto done;

    if (SendBytes(peer, pkey)==FAILURE) goto done; // send key
    if (SendBytes(peer, &pkey_sign)==FAILURE) goto done; // send signature

    //*** Get peer's public key and verify signature *************
    
    if (ReceiveBytes(peer, &keydata)==FAILURE) goto done;
    if (ReceiveBytes(peer, &signature)==FAILURE) goto done;

    ver_ret = VerifyAndGetPublicKeyFromBytes(keydata, signature, peer_pub_key, &peerkey);
    if (ver_ret == DHE_FAIL) goto done;

    //*** Compute shared secret ********************************

    if ((ctx = EVP_PKEY_CTX_new(dhkey,NULL)) == 0) goto done;

    if (EVP_PKEY_derive_init(ctx) <= 0) goto done;

    if (EVP_PKEY_derive_set_peer(ctx, peerkey) <= 0) // set peer key
        goto done;

    if (EVP_PKEY_derive(ctx, NULL, &ss.len) <= 0) // determine secret length
        goto done;

    if ((ss.value = (byte *)OPENSSL_malloc(ss.len)) == 0) // allocate memory
        goto done;
 
    if (EVP_PKEY_derive(ctx, ss.value, &ss.len) <= 0) // derive the secret
        goto done;

    //*** Compute shared key and HMAC key ************************

    // compute SHA256 digest of shared secret
    if (DigestMessage(ss.value, ss.len, EVP_sha256(), &ss_digest.value, &ss_digest.len)==FAILURE) {
        cout << "[Error computing SHA256 digest in DHE w/verification]" << endl;
        goto done;
    }

    if (SYM_KEY_SIZE + HMAC_KEY_SIZE > ss_digest.len) { // make sure we have enough bytes
        cout << "[Digest length insufficient for symmetric key and HMAC key]" << endl;
        goto done;
    }

    // use first half of digest as shared key
    memcpy(s_key,ss_digest.value,SYM_KEY_SIZE);
    // use the second half as HMAC key
    memcpy(h_key,ss_digest.value+SYM_KEY_SIZE,HMAC_KEY_SIZE);

    ret = ver_ret;

    done:

    // clean up
    EVP_PKEY_CTX_free(kctx);
    EVP_PKEY_free(params);

    if (pkey) {
        delete(pkey->value);
        delete(pkey);
    }
    OPENSSL_free(pkey_sign.value);

    if (keydata.value) delete(keydata.value);
    if (signature.value) delete(signature.value);

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(dhkey);
    EVP_PKEY_free(peerkey);

    OPENSSL_free(ss.value);
    if (ss_digest.value) delete(ss_digest.value);

    return ret;

}

