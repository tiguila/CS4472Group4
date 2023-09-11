

/** Pseudocodo
function task5(S)
	team5Result = sign the message (using Alince's (e, n) public key)
	return team5Result == S
*/



#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/sha.h>

// Define Alice's public key values
const char *e_hex = "010001";
const char *n_hex = "AE1CD4DC432798D933779FBD46C6E1247F0CF1233595113AA51B450F18116115";

// Function to convert hexadecimal string to BIGNUM
BIGNUM *hex_to_bn(const char *hex) {
    BIGNUM *bn = NULL;
    BN_hex2bn(&bn, hex);
    return bn;
}

// Function to verify the signature
int verify_signature(const char *message, const char *signature_hex, const char *e_hex, const char *n_hex) {
    
    // Convert e and n to BIGNUM
    BIGNUM *e = hex_to_bn(e_hex);
    BIGNUM *n = hex_to_bn(n_hex);

    // Convert the hexadecimal signature to a BIGNUM
    BIGNUM *signature_bn = hex_to_bn(signature_hex);

    // Decrypt the signature using Alice's public key
    BIGNUM *decrypted_signature = BN_new();
    BN_mod_exp(decrypted_signature, signature_bn, e, n, NULL);

    // Convert the decrypted signature to a hexadecimal string
    char *decrypted_signature_hex = BN_bn2hex(decrypted_signature);

    // Calculate the hash of the original message and compare it with the decrypted signature
    unsigned char hash[20]; // SHA-1 hash
    SHA1((const unsigned char *)message, strlen(message), hash);

    // Convert the hash to a BIGNUM
    BIGNUM *hash_bn = BN_bin2bn(hash, 20, NULL);

    // Compare the hash with the decrypted signature
    int result = BN_cmp(decrypted_signature, hash_bn);

    // Free memory
    // BN_free(e);
    // BN_free(n);
    // BN_free(signature_bn);
    // BN_free(decrypted_signature);
    // BN_free(hash_bn);
    // OPENSSL_free(decrypted_signature_hex);

    return result == 0;
}

int main() {
    const char *message = "Launch a missile.";
    const char *signature_hex = "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6802F";

    int result = verify_signature(message, signature_hex, e_hex, n_hex);

    if (result) {
        printf("Signature is valid.\n");
    } else {
        printf("Signature is not valid.\n");
    }

    return 0;
}
