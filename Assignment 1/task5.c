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

void compare( BIGNUM * a, BIGNUM * b )
{
    int cmp_result = BN_cmp(a, b);
    if (cmp_result == 0) {
        printf("The signature is indeed Alice’s\n");
    } else {
        printf("NO, the signature is not Alice’s\n");
    }
    printBN("signature decrypted: ", a);
    printBN("message:                  ", b);
}

int main ()
{
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *m = BN_new();
    BIGNUM *s = BN_new();
    BIGNUM *cs = BN_new();//corrupted signature 
    BIGNUM *e = BN_new();
    BIGNUM *n = BN_new();
    BIGNUM *res = BN_new();
    BIGNUM *res2 = BN_new();

    // decimal to big number
    BN_hex2bn(&m, "4c61756e63682061206d697373696c652e");
    BN_hex2bn(&s, "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6802F");
    BN_hex2bn(&cs, "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6803F");//corrupted signature
    BN_hex2bn(&e, "010001");
    BN_hex2bn(&n, "AE1CD4DC432798D933779FBD46C6E1247F0CF1233595113AA51B450F18116115");

    // res = s^e mod n
    BN_mod_exp(res, s, e, n, ctx);

    // res2 = cs^e mod n
    BN_mod_exp(res2, cs, e, n, ctx);

    compare(res,m);// comparing the decrypted signature with the message 
    compare(res2,m); // comparing the decrypted corrupted signature with the message 

    BN_CTX_free(ctx);
    BN_free(m);
    BN_free(n);
    
    return 0;
}
