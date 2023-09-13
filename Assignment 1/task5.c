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

    // decimal to big number
    
    BN_hex2bn(&m, "4c61756e63682061206d697373696c652e");//python -c 'print("Launch a missile.".encode("hex"))'
    //BN_hex2bn(&s, "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6802F");
    BN_dec2bn(&e, "65537");
     BN_dec2bn(&s, "45339830040223574130572214402551075218831845230048698262435226537506664513583");
    
    //BN_hex2bn(&n, "AE1CD4DC432798D933779FBD46C6E1247F0CF1233595113AA51B450F18116115"); 
    BN_dec2bn(&n,"78753376479788145540053418473724888139725316235000551140606913691881296716053");
    
        
    // res = s^e mod n
    BN_mod_exp(res, s, e, n, ctx);


   int cmp_result = BN_cmp(res, m); // Compare Alice's signature(decrypted) with the message
    if (cmp_result == 0) {
        printf("The signature is indeed Alice’s\n");
    } else {
        printf("NO, the signature is not Alice’s\n");
    }
    printBN("signature decrypted: ", res);
    printBN("message:                          ", m);
    

    OPENSSL_free(ctx);
    OPENSSL_free(m);
    OPENSSL_free(n);
    
    return 0;
}
