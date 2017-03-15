#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>          // encrytion library

void getSalt(unsigned char* salt, int len)
{
    FILE * salt_f = fopen("salt", "rb");
    int err;
    err = fread(salt, 1, len, salt_f);
    printf("read %d bytes from salt file\n", len);
    fclose(salt_f);
}

void hash(unsigned char *buf, int bufSize, unsigned char *md_value )
{
    // intialization
    OpenSSL_add_all_digests();
    const EVP_MD *md;
    int md_len;
    const  char *hash_type = "SHA256";
    md = EVP_get_digestbyname(hash_type);

    if(!md)
    {
        printf("Unknown message digest: %s", hash_type);
        exit(1);
    }

    // intialize library function
    EVP_MD_CTX *mdctx;
    mdctx = EVP_MD_CTX_create();
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, buf, bufSize);
    EVP_DigestFinal_ex(mdctx, md_value, &md_len);
    EVP_MD_CTX_destroy(mdctx);

    /* Call this once before exit. */
    EVP_cleanup();
}

void updateArray1WithArray2(unsigned char *startPoint1, unsigned char *startPoint2, int updateTimes)
{
    int i;
    for (i = 0; i < updateTimes; i++)
    {
        startPoint1[i] = startPoint2[i];
    }
}

void print(unsigned char *buf, int len)
{
    int i;
    for (i = 0; i < len; i++)
    {
        printf("%02x", buf[i]);
    }
    printf("\n\n\n");
}

int main()
{
    FILE * f = fopen("password", "rb+");
    unsigned char password[] = {'p', 'a', 's', 's', 'w', 'o', 'r', 'd' };
    //print(password, 10);
    unsigned char hash_newPassword[32];
    unsigned char salt[4];

    getSalt(salt , sizeof(salt));
    printf("the getted salt is : ");
    int i;
    for (i = 0; i < 4 ; i++)
    {
        printf("%c", salt[i]);
    }
    printf("\n");
    unsigned char salt_password[12];
 	updateArray1WithArray2(salt_password, salt, 4);
 	updateArray1WithArray2(&salt_password[4], password, sizeof(password));


    hash(salt_password, sizeof(password) + sizeof(salt) , hash_newPassword);
    printf("the hash value is: ");
    print(hash_newPassword, 32);
    fwrite(hash_newPassword,1, 32, f);
    fclose(f);
}	