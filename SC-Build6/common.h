/*******************************************************************
 * Header file common to both client and server
 *******************************************************************/
#include <openssl/evp.h>

//*** Defines

#define NONCE_SIZE		17 // number of bytes in nonce

#define CIPHER_BLOCK_SIZE	16 // AES-128
#define SYM_KEY_SIZE		16 // 128 bit keys
#define HMAC_KEY_SIZE		16 // HMAC SHA256

#define SEQ_NO_SIZE		sizeof(unsigned long long)

#define SUCCESS			1 // common success return value
#define FAILURE			0 // common failure return value

#define DHE_FAIL		0 // unable to complete DHE
#define DHE_SUCCESS		1 // DHE complete (with authentication)
#define DHE_SUCCESS_NO_AUTH	2 // DHE complete (without authentication)

//*** Typedefs

typedef unsigned char byte;

typedef struct {         // a byte array structure
    unsigned int len;    // number of bytes
    byte *value = NULL;  // the byte array
} bytes_t;

//*** Function prototypes

// Sequence numbers
void InitSequenceNumbers();

// Random bytes generation
int GetRandomBytes(byte *buffer, int num);

// OpenSSL setup/cleanup
void OpenSSLInit();
void OpenSSLCleanup();
void ReadRSAKeys(const char* peer_keyfile, const char *self_keyfile,
                 EVP_PKEY **pub_key, EVP_PKEY **pubpri_key);

// send/receive buffer
ssize_t SendAMessage(int dest, byte *msg, int len);
ssize_t ReceiveAMessage(int src, byte *buffer, int buffer_size);

// send/receive/print bytes_t
int SendBytes(int dest, bytes_t *b);
int ReceiveBytes(int src, bytes_t *b);
void PrintBytes(const char *label, byte *buff, int len);

// symmetric encrypt/decrypt message
int EncryptMessage(byte *plaintext, int plaintext_len, byte *key,
                   byte *iv, byte *ciphertext);
int DecryptMessage(byte *ciphertext, int ciphertext_len, byte *key,
                   byte *iv, byte *plaintext);


// symmetric encrypt/decrypt message with send/receive
int EncryptAndSendMessage(int dest, byte *s_key, byte *h_key, byte *msg, int len);
int ReceiveAndDecryptMessage(int src, byte *s_key, byte *h_key, byte *buffer, int buffer_size);

// message digest computation
int HMACMessage(byte *message, size_t message_len, byte *key, int key_len, 
                byte **digest, unsigned int *digest_len);
int DigestMessage(byte *message, size_t message_len, const EVP_MD *algo, 
                byte **digest, unsigned int *digest_len);

// signing on DHE keys
bytes_t *GetBytesFromPublicKey(EVP_PKEY *key);
EVP_PKEY *GetPublicKeyFromBytes(bytes_t keydata);
int GetBytesAndSignatureFromPublicKey(EVP_PKEY *key, EVP_PKEY *pri_key, 
                                      bytes_t **pkey, bytes_t *pkey_sign);
int VerifyAndGetPublicKeyFromBytes(bytes_t keydata, bytes_t signature,
                                    EVP_PKEY *pub_key, EVP_PKEY **key);
int GenerateVerifiedKeysWithDHE(int peer, byte *s_key, byte *h_key,
                                EVP_PKEY *self_key, EVP_PKEY *peer_key);


