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
    BIGNUM *n = BN_new();
    BIGNUM *e = BN_new();
    BIGNUM *m = BN_new();
    BIGNUM *d = BN_new();
    BIGNUM *res = BN_new();

    // hex to big number
    BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
    BN_hex2bn(&e, "010001");
    BN_hex2bn(&m, "49206f776520796f752024343030302e"); // python -c 'print("I owe you $4000.".encode("hex"))'
    BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");

    // res = m^d mod n
    BN_mod_exp(res, m, d, n, ctx);
    printBN("Signature for task4.c: ", res);
    
    OPENSSL_free(ctx);
    OPENSSL_free(n);
    OPENSSL_free(e);
    OPENSSL_free(d);
    OPENSSL_free(m);
    
    return 0;
}
