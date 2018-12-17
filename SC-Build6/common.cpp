/*******************************************************************
 * Secure Chat Application
 *
 * These functions are common to both the client and the server.
 * Do not modify any of these functions.
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
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/bio.h>

#include "common.h"
#include "common-ws.h"

using namespace std;

unsigned long long next_seq_no;			// sequence number in next send
unsigned long long expected_next_seq_no; 	// sequence number expected in next receive


/*******************************************************************/
// Reset sequence numbers to zero

void InitSequenceNumbers() {
    next_seq_no = 0;
    expected_next_seq_no = 0;
}

/*******************************************************************/
// Generate <num> bytes of crytographically strong
//   random bytes and store in <buffer>
//
// Returns 0/1 for failure/success

int GetRandomBytes(byte *buffer, int num) {
    return RAND_bytes(buffer, num);
}

/*******************************************************************/
// Initialize OpenSSL
//   from: https://wiki.openssl.org/index.php/Libcrypto_API

void OpenSSLInit() {
    // load the human readable error strings for libcrypto 
    ERR_load_crypto_strings();

    // load all digest and cipher algorithms 
    OpenSSL_add_all_algorithms();

    // load config file, and other important initialisation 
    OPENSSL_config(NULL);

    // seed random number generator
    int rc = RAND_load_file("/dev/random", 32);
    if(rc != 32) {
        cout << "[PRNG seeding failed]" << endl;
        exit(1);
    }
}

/*******************************************************************/
// Cleanup OpenSSL
//   from: https://wiki.openssl.org/index.php/Libcrypto_API

void OpenSSLCleanup() {
    // removes all digests and ciphers
    EVP_cleanup();

    // if you omit the next, a small leak may be left when you make 
    // use of the BIO (low level API) for e.g. base64 transformations 
    CRYPTO_cleanup_all_ex_data();

    // remove error strings 
    ERR_free_strings();
}

/*******************************************************************/
// Read RSA keys:
//      1) peer's public key from <peer_keyfile> into <pub_key>
//      2) keypair of self from <self_keyfile> into <pubpri_key>
//
// Loading is skipped when the associated filename is NULL
// Exits on error

void ReadRSAKeys(const char* peer_keyfile, const char *self_keyfile,
                 EVP_PKEY **pub_key, EVP_PKEY **pubpri_key) {

    FILE *fp;

    // load peer's public key
    if (peer_keyfile != NULL) {
        fp = fopen(peer_keyfile,"r");
        if (fp==NULL) {
            cout << "[" << peer_keyfile << " public key file not found]" << endl;
            exit(1);
        }
        if (PEM_read_PUBKEY(fp, pub_key, NULL, NULL)==NULL) {
            cout << "[Error reading peer public key]" << endl;
            exit(1);
        }
        fclose(fp);
    }

    // load self public/private key
    if (self_keyfile != NULL) {
        fp = fopen(self_keyfile,"r");
        if (fp==NULL) {
            cout << "[" << self_keyfile << " key file not found]" << endl;
            exit(1);
        }
        if (PEM_read_PrivateKey(fp, pubpri_key, NULL, NULL)==NULL) {
	    cout << "[Error reading self public/private key]" << endl;
            exit(1);
        }
        fclose(fp);
    }
}

/*******************************************************************/
// Send a message into <msg> of length <len> using socket <dest>
// 
// Returns number of bytes sent, or -1 on error

ssize_t SendAMessage(int dest, byte *msg, int len) {
    ssize_t ret = send(dest, msg, len, MSG_NOSIGNAL);
    return ret;
}

/*******************************************************************/
// Receive a message into <buffer> of max length <buffer_size>
//   using socket <src>
//
// Returns number of bytes read, or -1 on error

ssize_t ReceiveAMessage(int src, byte *buffer, int buffer_size) {
    ssize_t ret = recv(src,buffer, buffer_size, 0);
    return ret;
}

/*******************************************************************/
// Send a byte array <b> using socket <dest>
//   first the length b->len is sent and then the array
//   b->value is sent
//
// Returns SUCCESS or FAILURE

int SendBytes(int dest, bytes_t *b) {
    ssize_t sent;

    sent = SendAMessage(dest, (byte *)&b->len, sizeof(unsigned int));

    if (sent != sizeof(unsigned int)) return FAILURE;

    if (b->value && b->len!=0) {
        sent = SendAMessage(dest, b->value, b->len);
        if (sent != b->len) return FAILURE;
    }

    return SUCCESS;
}

/*******************************************************************/
// Receive a byte array  into <b> using socket <src>
//   b->value will be allocated as per received b->len
//
// Returns SUCCESS or FAILURE

int ReceiveBytes(int src, bytes_t *b) {
    ssize_t recv;

    recv = ReceiveAMessage(src, (byte *)&b->len, sizeof(unsigned int));

    if (recv != sizeof(unsigned int)) return FAILURE;

    if (b->len != 0) {
        b->value = new byte[b->len];
        recv = ReceiveAMessage(src,b->value,b->len);
        if (recv != b->len) {
            delete(b->value);
            return FAILURE;
        }
    }

    return SUCCESS;
}

/*******************************************************************/
// Prints <buff> of length <len> preceeded by <label>

void PrintBytes(const char *label, byte *buff, int len) {
    if (label) cout << label;
    for (int i=0; i<len; i++)
        printf("%02X",buff[i]);

    cout << endl;
}

/*******************************************************************/
// Encrypt <plaintext> of length <plaintext_len> using <key> 
//   and <iv> and place in <ciphertext>; AES-128-CBC is used for
//   encryption
//
// Returns FAILURE or length of encrypted ciphertext

int EncryptMessage(byte *plaintext, int plaintext_len, byte *key,
                   byte *iv, byte *ciphertext)  {
  
    int ret = FAILURE;

    EVP_CIPHER_CTX *ctx = NULL;
 
    int len;
    int ciphertext_len;

    // create and initialise the context 
    if(!(ctx = EVP_CIPHER_CTX_new())) return FAILURE;

    // initialize the encryption operation. IMPORTANT - ensure you use a key
    // and IV size appropriate for your cipher
    // we will use AES-128-CBS with 128 bit key and IV
    if(1 != EVP_EncryptInit(ctx, EVP_aes_128_cbc(), key, iv)) goto done;

    // provide the message to be encrypted, and obtain the encrypted output
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) 
        goto done;

    ciphertext_len = len;

    // finalize the encryption
    if(1 != EVP_EncryptFinal(ctx, ciphertext + len, &len)) 
        goto done;

    ciphertext_len += len;
    ret = ciphertext_len;

    done:

    // clean up
    EVP_CIPHER_CTX_free(ctx);

    return ret;
}

/*******************************************************************/
// Decrypt <ciphertext> of length <ciphertext_len> using <key> 
//   and <iv> and place in <plaintext>; AES-128-CBC is used for
//   decryption
//
// Returns FAILURE or length of plaintext

int DecryptMessage(byte *ciphertext, int ciphertext_len, byte *key,
                   byte *iv, byte *plaintext)  {
  
    int ret = FAILURE;

    EVP_CIPHER_CTX *ctx;

    int len;
    int plaintext_len;

    // create and initialise the context 
    if(!(ctx = EVP_CIPHER_CTX_new())) return FAILURE;

    // initialize the decryption operation. IMPORTANT - ensure you use a key
    // and IV size appropriate for your cipher
    // we will use AES-128 with 128 bit key and IV
    if(1 != EVP_DecryptInit(ctx, EVP_aes_128_cbc(), key, iv)) goto done;

    // provide the message to be decrypted, and obtain the plaintext output
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) 
        goto done;

    plaintext_len = len;

    // finalize the encryption
    if(1 != EVP_DecryptFinal(ctx, plaintext + len, &len)) goto done;
    
    plaintext_len += len;
    ret = plaintext_len;

    done:

    // clean up
    EVP_CIPHER_CTX_free(ctx);

    return ret;
}

/*******************************************************************/
// Compute SHA256 HMAC of <message> using key <key> and store it 
//   in <digest>; the length of the message is in <message_len>;
//   the length of the key is in <key_len>; digest length will be 
//   written to <digest_len>
//
// Memory will be allocated for <digest>
//
// Returns SUCCESS or FAILURE


int HMACMessage(byte *message, size_t message_len, byte *key, int key_len, 
                byte **digest, unsigned int *digest_len) {

    EVP_MD_CTX *mdctx;
    const EVP_MD* md;
    EVP_PKEY *pkey;

    int ret = FAILURE;

    if((mdctx = EVP_MD_CTX_create()) == NULL)
	goto done;

    if ((md = EVP_get_digestbyname("SHA256")) == NULL)
        goto done;

   if(!(pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, key, key_len)))
        goto done;

    if(1 != EVP_DigestSignInit(mdctx, NULL, md, NULL, pkey))
        goto done;

    if(1 != EVP_DigestSignUpdate(mdctx, message, message_len))
        goto done;

    if(1 != EVP_DigestSignFinal(mdctx, NULL, digest_len))
        goto done;

    if((*digest = (unsigned char *)OPENSSL_malloc(*digest_len)) == NULL)
        goto done;

    if(1 != EVP_DigestSignFinal(mdctx, *digest, digest_len))
        goto done;

    ret =  SUCCESS;

    done:

    // clean up
    EVP_PKEY_free(pkey);
    EVP_MD_CTX_destroy(mdctx);
    if (*digest && ret==FAILURE) OPENSSL_free(*digest);

    return ret;
}

/*******************************************************************/
// Compute digest of <message> using method <algo> and store it in
//   <digest>; the length of the message is in <message_len>;
//   digest length will be written to <digest_len>
//
// Memory will be allocated for <digest>
//
// Example <algo>: EVP_md5(), EVP_sha256()
//
// Returns SUCCESS or FAILURE 

int DigestMessage(byte *message, size_t message_len, const EVP_MD *algo, 
                  byte **digest, unsigned int *digest_len) {
    EVP_MD_CTX *mdctx;

    int ret = FAILURE;

    if((mdctx = EVP_MD_CTX_create()) == NULL)
	goto done;

    if(1 != EVP_DigestInit_ex(mdctx, algo, NULL))
        goto done;

    if(1 != EVP_DigestUpdate(mdctx, message, message_len))
        goto done;

    if((*digest = (unsigned char *)OPENSSL_malloc(EVP_MD_size(algo))) == NULL)
        goto done;

    if(1 != EVP_DigestFinal_ex(mdctx, *digest, digest_len))
        goto done;

    ret = SUCCESS;

    done:

    // clean up
    if (*digest && ret == FAILURE) OPENSSL_free(*digest);
    EVP_MD_CTX_destroy(mdctx);

    return ret;
}

/*******************************************************************/
//  Extract the public key from keypair <key> and
//   return as a bytes_t structure
//
//  Returns NULL on error

bytes_t *GetBytesFromPublicKey(EVP_PKEY *key) {
    bytes_t *pkey = NULL;

    // set up OpenSSL memory buffer I/O
    BUF_MEM *bptr;
    BIO* bio = BIO_new(BIO_s_mem());

    if (1 != PEM_write_bio_PUBKEY(bio, key))  { // write public key to buffer
        BIO_free(bio);
        return pkey;
    }

    // get pointer to data in buffer
    BIO_get_mem_ptr(bio,&bptr);

    pkey = (bytes_t *)malloc(sizeof(bytes_t));
    pkey->len = (unsigned int)bptr->length; // set data length
    pkey->value = (byte *)malloc(sizeof(byte)*pkey->len); // allocate
    memcpy(pkey->value, bptr->data, bptr->length); // copy data

    BIO_free(bio); // free memory

    return pkey;
}

/*******************************************************************/
// Create a EVP_PKEY from <keydata>
//
// Return NULL on error

EVP_PKEY *GetPublicKeyFromBytes(bytes_t keydata) {
    EVP_PKEY *peerkey = NULL;

    // copy received data to OpenSSL memory buffer
    BUF_MEM *bptr = BUF_MEM_new(); 
    BUF_MEM_grow(bptr, keydata.len); // set size of buffer
    memcpy(bptr->data, keydata.value, keydata.len); // copy

    BIO *bio = BIO_new(BIO_s_mem()); // set up for OpenSSL buffer I/O
    BIO_set_mem_buf(bio, bptr, BIO_NOCLOSE); // this BIO is now using the BUF_MEM above

    // read public key from OpenSSL buffer
    if ((peerkey = EVP_PKEY_new()) == NULL) goto done;

    PEM_read_bio_PUBKEY(bio, &peerkey, NULL, NULL);
    
    done:

    // clean up
    BUF_MEM_free(bptr);
    BIO_free(bio);
    
    return peerkey;
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
