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
    BIGNUM *a = BN_new();
    BIGNUM *b = BN_new();
    BIGNUM *n = BN_new();
    BIGNUM *res = BN_new();
    BIGNUM *e = BN_new();
    BIGNUM *d = BN_new();
    BIGNUM *m = BN_new();

    // hex to big number
    BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
    BN_hex2bn(&e, "010001");
    BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");
    BN_hex2bn(&m, "4120746f702073656372657420e28093207465616d20233421"); // python -c 'print("A top secret – team #4!".encode("hex"))'
    // BN_hex2bn(&m, "4120746f702073656372657421"); // python -c ’print("A top secret!".encode("hex"))’
    
    // res = aˆb mod n      ---> // P^e(mod n)
    BN_mod_exp(res, m, e, n, ctx);
    printBN("Encrypted message in big number: ", res);
    
    printBN("e: ", e);
    printBN("n: ", n);

    OPENSSL_free(ctx);
    OPENSSL_free(a);
    OPENSSL_free(b);
    OPENSSL_free(d);
    OPENSSL_free(m);
    return 0;
}