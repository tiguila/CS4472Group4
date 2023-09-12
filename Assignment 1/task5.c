#include <stdio.h>
#include <openssl/bn.h>
#define NBITS 256
void printBN(char *msg, BIGNUM * a)
{
    /* Use BN_bn2hex(a) for hex string
    * Use BN_bn2dec(a) for decimal string */
    char * number_str = BN_bn2hex(a);
    printf("%s %s\n", msg, number_str);
    OPENSSL_free(number_str);
}

int main ()
{
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *m = BN_new();
    BIGNUM *s = BN_new();
    BIGNUM *e = BN_new();
    BIGNUM *n = BN_new();
    BIGNUM *res = BN_new();

    // hex to big number
    BN_hex2bn(&m, "4c61756e63682061206d697373696c65");
    BN_hex2bn(&s, "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6802F");
    BN_hex2bn(&e, "010001");
    BN_hex2bn(&n, "AE1CD4DC432798D933779FBD46C6E1247F0CF1233595113AA51B450F18116115"); // python -c 'print("Launch a missile".encode("hex"))'
    
    
    // s^e mod n
    BN_mod_exp(res, s, e, n, ctx);
    printBN("Decrypted message in big number: ", res);
    printBN("s: ", s);
    OPENSSL_free(ctx);
    OPENSSL_free(m);
    OPENSSL_free(e);
    OPENSSL_free(n);
    
    return 0;
}