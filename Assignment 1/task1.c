// use "RSA algorithm"
// Task: Calcuate d, the private key.

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
    BIGNUM *p = BN_new();
    BIGNUM *q = BN_new();
    BIGNUM *e = BN_new();
    BIGNUM *n = BN_new();
    BIGNUM *res2 = BN_new();

    BIGNUM *phiOfn = BN_new();

    BIGNUM *subtraction1 = BN_new();
    BIGNUM *subtraction2 = BN_new();
    
    // private key
    BIGNUM *d = BN_new();

    // Initialize p, q, e
    BN_hex2bn(&p, "F7E75FDC469067FFDC4E847C51F452DF");
    BN_hex2bn(&q, "E85CED54AF57E53E092113E62F436F4F");
    BN_hex2bn(&e, "0D88C3");
    
    // n = p*q
    BN_mul(n, p, q, ctx);
    
    // phi(n) = (p-1)*(q-1)
    BN_one(subtraction1);
    BN_one(subtraction2);
    BN_sub(subtraction1, p, subtraction1);
    BN_sub(subtraction2, q, subtraction2);
    BN_mul(phiOfn, subtraction1, subtraction2, ctx);

    // d*e = 1 % phiofn     or      d = e^(-1)  mod ø(n)
    BN_mod_inverse(d, e, phiOfn, ctx);
    
    
    // ---------------------
    // res = a ∗ b mod n    -----------    d*e(mod n)
    BN_mod_mul(res2, d, e, phiOfn, ctx);

    printBN("p:", p);
    printBN("q:", q);
    printBN("e:", e);
    printBN("Private key (d):", d);
    printBN("d*e (mod ø(n)) = ", res2);

    OPENSSL_free(ctx);
    OPENSSL_free(n);
    OPENSSL_free(phiOfn);
    OPENSSL_free(subtraction1);
    OPENSSL_free(subtraction2);

    return 0;
}








// // use "RSA algorithm"
// // Task: Calcuate d, the private key.

// #include <stdio.h>
// #include <openssl/bn.h>
// #define NBITS 256
// void printBN(char *msg, BIGNUM * a)
// {
//     /* Use BN_bn2hex(a) for hex string
//     * Use BN_bn2dec(a) for decimal string */
//     char * number_str = BN_bn2hex(a);
//     printf("%s %s\n", msg, number_str);
//     OPENSSL_free(number_str);
// }

// int main ()
// {
//     BN_CTX *ctx = BN_CTX_new();
//     BIGNUM *p = BN_new();
//     BIGNUM *q = BN_new();
//     BIGNUM *e = BN_new();
//     BIGNUM *n = BN_new();

//     BIGNUM *phiOfn = BN_new();

//     BIGNUM *subtraction1 = BN_new();
//     BIGNUM *subtraction2 = BN_new();
    
//     // private key
//     BIGNUM *d = BN_new();

//     // Initialize p, q, e
//     BN_hex2bn(&p, "F7E75FDC469067FFDC4E847C51F452DF");
//     BN_hex2bn(&q, "E85CED54AF57E53E092113E62F436F4F");
//     BN_hex2bn(&e, "0D88C3");
    
//     // n = p*q
//     BN_mul(n, p, q, ctx);
    
//     // phi(n) = (p-1)*(q-1)
//     BN_one(subtraction1);
//     BN_one(subtraction2);
//     BN_sub(subtraction1, p, subtraction1);
//     BN_sub(subtraction2, q, subtraction2);
//     BN_mul(phiOfn, subtraction1, subtraction2, ctx);

//     // d*e = 1 % phiofn     or      d = e^(-1)  mod ø(n)
//     BN_mod_inverse(d, e, phiOfn, ctx);
//     printBN("p:", p);
//     printBN("q:", q);
//     printBN("e:", e);
//     printBN("d:", d);


//     return 0;
// }
