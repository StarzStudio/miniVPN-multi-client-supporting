/*

* tunproxy.c --- small demo program for tunneling over UDP with tun/tap

*

* Copyright (C) 2003  Philippe Biondi <phil@secdev.org>

*

* This program is free software; you can redistribute it and/or modify it

* under the terms of the GNU Lesser General Public License as published by

* the Free Software Foundation.

*

* This program is distributed in the hope that it will be useful, but

* WITHOUT ANY WARRANTY; without even the implied warranty of

* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU

* Lesser General Public License for more details.

*/

#include <sys/prctl.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <getopt.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <memory.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <openssl/evp.h>          // encrytion library
#include <openssl/hmac.h>
#include <openssl/rsa.h>       /* SSLeay stuff */
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define DEBUG 1
/* define HOME to be dir for key and cert files... */
#define HOME "./"
/* Make these what you want for cert & key files@main */
#define SERV_CERTF  HOME "server.crt"
#define SERV_KEYF  HOME  "server.key"
#define CLI_CERTF  HOME "client.crt"
#define CLI_KEYF  HOME  "client.key"

#define CACERT HOME "ca.crt"

#define CHK_NULL(x) if ((x)==NULL) exit (1)
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define CHK_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stderr); exit(2); }

#define PERROR(x) do { perror(x); exit(1); } while (0)

#define ERROR(x, args ...) do { fprintf(stderr,"ERROR:" x, ## args); exit(1); } while (0)

// length of key and iv
#define KEYLEN 16 // 128 bits
#define IVLEN 16 // 128 bits
// length of HMAC value
#define HMACTYPE 16;

// define sliding window size
#define WindowSize 100;
// bool type
#define true 1;
#define false 0;
typedef int bool;




// store client's ip address, use socket number as index to identify
char *sockNum_ip[100];
unsigned char *sockNum_key[100];
// server CN container
char SER_CERT_CN[50];

// seqence number conunter
int sequenceCounter = 0;

// store sequence number
int sequenceList[100];

// have been replay attacked times
int replayCounter = 0;



struct ipheader {
 unsigned char      iph_ihl:4, iph_ver:4;
 unsigned char      iph_tos;
 unsigned short int iph_len;
 unsigned short int iph_ident;
 //unsigned char      iph_flag;
 unsigned short int iph_offset;
 unsigned char      iph_ttl;
 unsigned char      iph_protocol;
 unsigned short int iph_chksum;
 unsigned int       iph_sourceip;
 unsigned int       iph_destip;
};
 
// UDP header's structure
struct udpheader {
 unsigned short int udph_srcport;
 unsigned short int udph_destport;
 unsigned short int udph_len;
 unsigned short int udph_chksum;
};

unsigned int findHostIp(unsigned char* buf)
{
    struct ipheader *ip = (struct ipheader *) buf;
    return ip->iph_sourceip;
}

char* VpnCliIp[100];
unsigned int HostIp[100]; 

void addIPTable(char* cli_ip, int host_ip, int sd)
{
    char *CliipOnHeap = (char *)malloc( sizeof(unsigned char) * (strlen(cli_ip) + 1));
    strcpy(CliipOnHeap, cli_ip);
    VpnCliIp[sd] = CliipOnHeap;

    HostIp[sd] = host_ip;
}

int  findVPNClientIPBasedOnHostIp(char* cli_ip, int host_ip)
{
    int pos = -1;

     int i = 0;
     
    for (i = 0; i < sizeof(HostIp); i++)
    {
        if ( HostIp[i] == host_ip )  
        {
             pos = i;
        }
    }

    if (pos == -1)
    {   
        printf("not found host ip addr in the store\n");
        return -1 ;
    }
    else
    {
        strcpy(cli_ip, VpnCliIp[pos]);
        return 0;
    }
}




// decrypt or encrypt data part
////////////////////////////////////////////

// return 0 if error, otherwise return 1
int decryptData(unsigned char *buffer, int buffer_size, unsigned char *key, unsigned char *iv)
{
    //unsigned char outbuf[1024];
    int outlen, tmplen;
    /* Bogus key and IV: we'd normally set these from
    * another source.
    */
    //unsigned char key[] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
    //unsigned char iv[] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    // copy everything in the buffer to the temp intext
    unsigned char intext[buffer_size];
    int i;
    for (i = 0; i < buffer_size; i++)
    {
        intext[i] = buffer[i];
    }

    EVP_CIPHER_CTX *ctx;

    ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_ofb(), NULL, key, iv);

    if (!EVP_DecryptUpdate(ctx, buffer, &outlen, intext, buffer_size))  // here need to be the size of the intext
    {
        printf("in the if EVP_DecryptUpdate( scope:\n");
        /* Error */
        return 0;
    }
    /* Buffer passed to EVP_EncryptFinal() must be after data just
    * encrypted to avoid overwriting it.
    */
    if (!EVP_DecryptFinal_ex(ctx, buffer + outlen, &tmplen))
    {
        printf("in the EVP_DecryptFinal_ex( scope:\n");
        /* Error */
        return 0;
    }
    outlen += tmplen;
    EVP_CIPHER_CTX_free(ctx);

    // buffer = memset(buffer, 0, outlen);

    // for (i = 0; i < outlen; i++)
    // {
    //     buffer[i] = outbuf[i];
    // }

    // printf("inside the decryption function, the buffer content is:\n");
    // for (i = 0; i < outlen; i++)
    // {
    //  printf("%02x", buffer[i]);
    // }
    // printf("\n\n\n");

    return outlen;
}

// return 0 if error, otherwise return 1
int encryptData(unsigned char *buffer, int buffer_size, unsigned char *key, unsigned char *iv)
{
    //unsigned char outbuf[5800];
    int outlen, tmplen;
    /* Bogus key and IV: we'd normally set these from
    * another source.
    */
    //unsigned char key[] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
    //unsigned char iv[] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    // copy everything in the buffer to the temp intext
    unsigned char intext[buffer_size];
    int i;
    for (i = 0; i < buffer_size; i++)
    {
        intext[i] = buffer[i];
    }

    EVP_CIPHER_CTX *ctx;

    ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_ofb(), NULL, key, iv);   // ofb is good because least corrput influence

    if (!EVP_EncryptUpdate(ctx, buffer, &outlen, intext, buffer_size))  // here need to be the size of the intext
    {
        /* Error */
        return 0;
    }
    /* Buffer passed to EVP_EncryptFinal() must be after data just
    * encrypted to avoid overwriting it.
    */
    if (!EVP_EncryptFinal_ex(ctx, buffer + outlen, &tmplen))
    {
        /* Error */
        return 0;
    }
    outlen += tmplen;
    EVP_CIPHER_CTX_free(ctx);

    // buffer = memset(buffer, 0, outlen);

    // for (i = 0; i < outlen; i++)
    // {
    //     buffer[i] = outbuf[i];
    // }

    return outlen;
}

///////////////////////////////////////////////////////

// HMAC part
//////////////////////////////////////////////////////
void appendHmac(unsigned  char *buf, unsigned char *Hmac, int bufLen, int hmacLen)
{
    int i, j;
    // append this HMAC value to thes end of the packet
    for (i = bufLen, j = 0; j < hmacLen; j++, i++)
    {
        buf[i] = Hmac[j];
    }
}

// return signature length, or 0 if error happens
int doHmac(unsigned char *buffer, int buffer_size, unsigned char *hmac_value, unsigned char  *key)
{
    // intialization
    OpenSSL_add_all_digests();

    // declare iterator
    int i;

    HMAC_CTX  hmacctx;
    // copy everything in the buffer to the temp intext
    unsigned char intext[buffer_size];
    for (i = 0; i < buffer_size; i++)
    {
        intext[i] = buffer[i];
    }

    int hmac_len;
    // unsigned char hmac_value[EVP_MAX_MD_SIZE];

    // provide type of hash algorithm

    const EVP_MD *md;
    const  char *hash_type = "MD5";  // shall generate 16 bytes result
    md = EVP_get_digestbyname(hash_type);

    if (!md)
    {
        printf("Unknown message digest: %s", hash_type);
        exit(1);
    }

    HMAC_CTX_init(&hmacctx);

    //HMAC_CTX_reset(hmacctx);

    //EVP_DigestInit_ex(mdctx, md, NULL);
    HMAC_Init_ex(&hmacctx, key, KEYLEN, md, NULL);
    HMAC_Update(&hmacctx, intext, buffer_size);
    HMAC_Final(&hmacctx, hmac_value, &hmac_len);

    // EVP_DigestUpdate(mdctx, intext, strlen(intext));
    // EVP_DigestFinal_ex(mdctx, md_value, &md_len);
    // EVP_MD_CTX_destroy(mdctx);

    if(DEBUG)
    {
        printf("HMAC Digest is: ");
        for (i = 0; i < hmac_len; i++)
            printf("%02x", hmac_value[i]);
        printf("\n");
        printf("HMAC length is %d\n", hmac_len);
    }

    /* Call this once before exit. */
    HMAC_CTX_cleanup(&hmacctx);

    //EVP_cleanup();
    return hmac_len;
}


// return true if equal
int compareHmac(unsigned char *mac1, unsigned char *mac2, int macLength)
{
    int i;
    bool isEqual = true;
    for (i = 0; i < macLength; i++)
    {
        if (mac1[i] != mac2[i])
        {
            isEqual = false;
        }
    }
    return isEqual;
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



//////////////////////////////////////////////////////////


//  utility function
//////////////////////////////////////
void usage()
{
    fprintf(stderr, "Usage: tunproxy [-s port|-c targetip:port] [-e]\n");

    exit(0);
}

bool compareArray(unsigned char *a1, unsigned char *a2, int len_a1)
{
    int i;
    for(i = 0 ; i < len_a1; i++)
    {
        if(a1[i] != a2[i])
            return false;
    }
    return true;
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

void randomize(unsigned char *buf, int len)
{
    FILE *random = fopen("/dev/urandom", "r");
    fread(buf, sizeof(unsigned char)*len, 1, random);
    fclose(random);
}
//////////////////////////////////////




//  tcp tunnel part (ssl)
///////////////////////////////////////////
// return ture if this is key packet

void killChild(int pid)
{
    kill(pid, SIGTERM);
    wait();
}


void getKeyFromClient(unsigned char *key, SSL *ssl)
{
    int err = SSL_read(ssl, key, KEYLEN);
    CHK_SSL(err);
    if(DEBUG)
    {
        printf("key sent from client is:");
        print(key, KEYLEN);
    }

    // inform client that server has received the key
    char *response = "Y";
    err = SSL_write(ssl, response, strlen(response));
    CHK_SSL(err);

    printf("key has been received from client\n");

}

void sendKeyToServer(unsigned char *key, SSL *ssl)
{
    unsigned char newKey[1024] = {'k'};
    updateArray1WithArray2(&newKey[1], key, KEYLEN);
    int err = SSL_write(ssl, newKey, KEYLEN + 1);
    CHK_SSL(err);
    if(DEBUG)
    {
        printf("key sent to server is:");
        print(key, KEYLEN);
    }
    char response[1024];
    err = SSL_read(ssl, response, sizeof(response) - 1);
    response[err] = '\0';
    if(strcmp(response, "KY") == 0)
    {
        printf("Key received by remote server:\n ");
    }
    else
    {
        PERROR("Key exchanging proess fail\n");
    }
}


void sendUsername(SSL *ssl)
{
    int err;
    char userName[1024];
    char response[1024];
    printf("please enter your user name:\n");

    while (1)
    {
        fflush(stdin);
        scanf("%s", userName);
        err = SSL_write(ssl, userName, strlen(userName));
        CHK_SSL(err);
        err = SSL_read(ssl, response, sizeof(response) - 1);
        CHK_SSL(err);
        response[err] = '\0';
        if (strcmp(response, "UY") == 0)
        {
            printf("username correct!\n");
            return;
        }
        else if(strcmp(response, "UN") == 0)
        {
            printf("There is no such username, please type again!\n");
            continue;
        }
        else
        {
            printf("unknown response!\n");
            exit(1);    // exit reporting error
        }
    }
}

void sendLoggingNotify(SSL *ssl)
{
    int err;
    char response[1024];
    while (1)
    {
        err = SSL_write(ssl, "l", strlen("l"));
        CHK_SSL(err);
        err = SSL_read(ssl, response, sizeof(response) - 1);
        CHK_SSL(err);
        response[err] = '\0';
        if (strcmp(response, "LY") == 0)
        {
            printf("begin logging process!\n");
            return;
        }
        else
        {
            printf("unknown response!\n");
            exit(1);    // exit reporting error
        }
    }
}


void sendPassword(SSL *ssl)
{
    int err;
    unsigned char password[1024];
    char response[1024];
    printf("please enter your password:\n");

    while (1)
    {
        fflush(stdin);
        scanf("%s", password);
        err = SSL_write(ssl, password, strlen(password));
        CHK_SSL(err);
        err = SSL_read(ssl, response, sizeof(response) - 1);
        CHK_SSL(err);
        response[err] = '\0';
        if (strcmp(response, "PY") == 0)
        {
            printf("password correct!\n");
            return;
        }
        else if(strcmp(response, "PN") == 0)
        {
            printf("password incorrect, please type again!\n");
            continue;
        }
        else
        {
            printf("unknown response!\n");
            exit(1);    // exit reporting error
        }
    }
}


void checkUsername(SSL *ssl)
{
    char username[50];
    char storedUsername[100]; // this must big enough
    int err;
    while(1)
    {
        printf("waiting for user to enter username\n");
        err = SSL_read(ssl, username, sizeof(username) - 1);
        CHK_SSL(err);
        //printf("err of username is:%d", err);
        username[err] = '\0';
        // extract pre-stored username from the fiel
        FILE *f = fopen("username", "rb");
        err = fread(storedUsername, 1, sizeof(storedUsername), f);
        fclose(f);
        // search username in the extracting content
        // int i;
        // char prefix[4] = { '\n' ,'#', '0x20', ':'};
        // for (i = 0; i < 2000; i++)
        // {
        //     prefix[2] = i;
        // }
        storedUsername[err] = '\0';
        printf("storedusername is: %s\n\n" ,storedUsername);
        char * s = strstr(storedUsername, username );
        
        if (s != NULL)
        {
            char *response = "UY";
            err = SSL_write(ssl, response, strlen(response));
            CHK_SSL(err);
            if (DEBUG)
                printf("username correct!\n");
            return;
        }
        else
        {
            char *response = "UN";
            err = SSL_write(ssl, response, strlen(response));
            CHK_SSL(err);
            if (DEBUG)
                printf("username incorrect!\n");
            continue;
        }
        //printf("Got %d chars:'%s'\n", err, username);
    }
}


void overWritePassword(unsigned char *buf, int len)
{
    int i;
    for (i = 0; i < len; i++)
    {
        buf[i] = 'a';
    }
}

void getSalt(unsigned char *salt, int len)
{
    FILE *salt_f = fopen("salt", "rb");
    int err;
    err = fread(salt, 1, len, salt_f);
    printf("read %d bytes from salt file\n", len);
    fclose(salt_f);
    if (DEBUG)
    {
        printf("the extracted salt is : ");
        int i;
        for (i = 0; i < 4 ; i++)
        {
            printf("%c", salt[i]);
        }
    }
}
void checkPassword(SSL *ssl)
{
    int err;
    unsigned char password[20];
    unsigned char storedPassword[200];
    while(1)
    {
        printf("waiting for user to enter password\n\n");
        err = SSL_read(ssl, password, sizeof(password) - 1);
        CHK_SSL(err);
        password[err] = '\0';
        FILE *f = fopen("password", "rb");
        err = fread(storedPassword, 1, sizeof(storedPassword), f);
        CHK_ERR(err, "read password file failed\n");
        fclose(f);
        storedPassword[err] = '\0';
        if (DEBUG)
        {
            printf("the disk stored password length is:%d", err );
            printf("the disk stored password is: %s", storedPassword);
            printf("the password sent from client is :%s\n", (char *)password );
        }

        // extract salt from file
        unsigned char salt[4] ;
        getSalt(salt, sizeof(salt));

        unsigned char hash_password[32];
        unsigned char salt_password [12];
        updateArray1WithArray2(salt_password, salt, 4 );
        updateArray1WithArray2(&salt_password[4], password,  strlen(password));
        if (DEBUG)
        {
            printf("the new salt_password is: ");
            int i;
            for(i = 0; i < 12; i++)
            {
                printf("%c", salt_password[i]);
            }
            printf("\n");
        }
        hash(salt_password, strlen(password) + sizeof(salt), hash_password);


        printf("the hash value is:");
        print(hash_password, 32);

        hash_password[32] = '\0';
        char *s = strstr((char *)storedPassword, (char *)hash_password );

        if (s != NULL)
        {
            char *response = "PY";
            err = SSL_write(ssl, response, strlen(response));
            CHK_SSL(err);
            if (DEBUG)
                printf("password correct!\n");
            return;
        }
        else
        {

            char *response = "PN";
            err = SSL_write(ssl, response, strlen(response));
            CHK_SSL(err);
            if (DEBUG)
                printf("password incorrect!\n");
            continue;
        }

        // prevent attacker read from memory
        overWritePassword(password, sizeof(password));
        overWritePassword(storedPassword, sizeof(storedPassword));
        overWritePassword(hash_password, sizeof(hash_password));
        overWritePassword(salt_password, sizeof(salt_password));
        overWritePassword(salt, sizeof(salt));
    }
    // printf("Got %d chars:'%s'\n", err, password);
}

void showUserMenu()
{
    printf("please enter instrutions:\n");
    printf("k -- Send random key to the server\n");
    printf("s -- stop connection and shut down server\n");
    printf("l -- log into the system\n");
    printf("> --: \n");
}

// void clientHandler(SSL *ssl, int pipe_fd, unsigned char *key , ctx)
// {
//     unsigned char buf[1024];


// }
void sendShutdownToServer(SSL *ssl)
{
    int err;
    char *stopSignal = "s";

    while (1)
    {
        char response[1024];
        err = SSL_write(ssl, stopSignal, strlen(stopSignal));
        CHK_SSL(err);
        err = SSL_read(ssl, response, sizeof(response) - 1);
        CHK_SSL(err);
        response[err] = '\0';
        if (strcmp(response, "SY") == 0)
        {
            printf("server has been shut down!\n");
            return;
        }
        else
        {
            printf("unknown response!\n");
            exit(1);    // exit reporting error
        }
    }
}

void checkCN(X509 *server_cert)
{
    // process flow:
    // 1. get server CN from certificate
    // 2. extract domain name, which must be truncated at tail
    // 3. compare with prestored CN, regardless of upper or lower case
    char serv_CN[256];
    X509_NAME_get_text_by_NID(X509_get_subject_name(server_cert),  NID_commonName, serv_CN, 256); // here serv_CN will be written null terminated
    // check chars at the end with prestored CN
    // chars in the end must be domain.
    int len_serv_CN = strlen(serv_CN);
    int len_SER_CERT_CN = strlen(SER_CERT_CN);
    char DomainPart[256];
    strcpy(DomainPart, &serv_CN[len_serv_CN - len_SER_CERT_CN]);
    if(strcasecmp(DomainPart, SER_CERT_CN))
    {
        printf("server's CN: %s, local request: %s\n", serv_CN, SER_CERT_CN);
        PERROR("Common name doesn't match host name\n");
    }
    else
    {
        printf("CN check matches, the CN is:%s \n", SER_CERT_CN);
    }
}


void tcpTunnel_client(char *server_ip, char *cli_ip, int pipe_fd, int pid, int serv_PORT, int cli_PORT)
{
    int err;
    int sd;
    struct sockaddr_in sa, sa_loc;
    SSL_CTX *ctx;
    SSL     *ssl;
    X509    *server_cert;
    char    *str;
    char     buf[5800];
    SSL_METHOD *meth;

    unsigned char key[KEYLEN];


    SSLeay_add_ssl_algorithms();
    meth = SSLv23_client_method();
    SSL_load_error_strings();
    ctx = SSL_CTX_new(meth);
    CHK_NULL(ctx);

    CHK_SSL(err);



    // printf("before verify server\n");

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_load_verify_locations(ctx, CACERT, NULL);

    if (SSL_CTX_use_certificate_file(ctx, CLI_CERTF, SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        killChild(pid);
        exit(-2);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, CLI_KEYF, SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        killChild(pid);
        exit(-3);
    }

    if (!SSL_CTX_check_private_key(ctx))
    {
        printf("Private key does not match the certificate public keyn");
        killChild(pid);
        exit(-4);
    }

    /* ----------------------------------------------- */
    /* Create a socket and connect to server using normal socket calls. */


    //printf("before making socket\n");



    sd = socket(AF_INET, SOCK_STREAM, 0);
    CHK_ERR(sd, "socket");

    // Local binding
    memset(&sa_loc, 0, sizeof(struct sockaddr_in));
    sa_loc.sin_family = AF_INET;
    sa_loc.sin_port = htons(cli_PORT);

    //printf("before cli_ip\n");

    sa_loc.sin_addr.s_addr = inet_addr(cli_ip);

    //printf("after cli_ip\n");

    // reuse port if already be bound
    int on = 1;
    setsockopt( sd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on) );

    err = bind(sd, (struct sockaddr *)&sa_loc, sizeof(struct sockaddr));
    CHK_ERR(err, "bind local");


    memset(&sa, '\0', sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = inet_addr(server_ip);   /* Server IP */

    sa.sin_port = htons(serv_PORT);          /* Server Port number */

    //printf("before coonect func\n");


    err = connect(sd, (struct sockaddr *) &sa,
                  sizeof(sa));
    CHK_ERR(err, "connect");

    /* ----------------------------------------------- */
    /* Now we have TCP conncetion. Start SSL negotiation. */


    // printf("before making ssl\n");


    ssl = SSL_new(ctx);
    CHK_NULL(ssl);
    SSL_set_fd(ssl, sd);
    err = SSL_connect(ssl);
    CHK_SSL(err);



    err = SSL_read(ssl, buf, sizeof(buf) - 1);
    CHK_SSL(err);

    printf("the connection confirmation message is:%s", buf);
    /* Following two steps are optional and not required for
    data exchange to be successful. */

    /* Get server's certificate (note: beware of dynamic allocation) - opt */

    // printf("before get ssl information\n");




    server_cert = SSL_get_peer_certificate(ssl);
    CHK_NULL(server_cert);
    printf("Server certificate:\n");

    str = X509_NAME_oneline(X509_get_subject_name(server_cert), 0, 0);
    CHK_NULL(str);
    printf("\t subject: %s\n", str);
    OPENSSL_free(str);

    str = X509_NAME_oneline(X509_get_issuer_name(server_cert), 0, 0);
    CHK_NULL(str);
    printf("\t issuer: %s\n", str);
    OPENSSL_free(str);

    // verify peer certificate
    if (SSL_get_verify_result(ssl) != X509_V_OK)
        PERROR("Certificate doesn't verify.\n");

    // check CN
    checkCN(server_cert);

    /* We could do all sorts of certificate verification stuff here before
    deallocating the certificate. */

    X509_free(server_cert);

    /* --------------------------------------------------- */
    /* DATA EXCHANGE - Send a message and receive a reply. */

    //printf("before enter in while\n");

    bool hasLogged = false;

    while(1)
    {
        printf("\n\nplease enter command, press 'h' to display help man\n");
        char command[1024];
        fflush(stdin);
        scanf("%s", command);
        if (strcmp(command, "s") == 0)
        {
            sendShutdownToServer(ssl);
            break;
        }
        if (strcmp(command, "h") == 0)
        {
            showUserMenu();
            continue;
        }
        if (strcmp(command, "l") == 0)
        {
            sendLoggingNotify(ssl);
            sendUsername(ssl);
            sendPassword(ssl);
            hasLogged = true;
            continue;   // if not continue, will jumpt to else {} block
        }
        if (strcmp(command, "k") == 0)
        {
            if(!hasLogged)
            {
                printf("please first log to the server!\n");
                continue;
            }
            // generate random key
            randomize(key, KEYLEN);
            // send key to server
            sendKeyToServer(key, ssl);

            // pass key to the udp tunnel
            unsigned char temp[KEYLEN + 1];
            temp[0] = 'k';
            updateArray1WithArray2(&temp[1], key, KEYLEN);
            // write key to the udp channel
            write(pipe_fd, temp, KEYLEN + 1);
        }
        else
        {
            printf("unknown command, please type again, input command is:%s\n", command);
            continue;
        }

    }


    /* Clean up. */
    killChild(pid);

    wait();

    SSL_shutdown (ssl);  /* send SSL/TLS close_notify */

    close(sd);
    SSL_free(ssl);
    SSL_CTX_free(ctx);

}



void closeClient(SSL *ssl, int *sd , int *socket_collection)
{
    close( *sd );
    SSL_free (ssl);
    *socket_collection = 0;
}




void tcpTunnel_server(int pipe_fd, int pid, int PORT)
{
    // tcp part
    int listen_sd;
    struct sockaddr_in sa_serv;
    struct sockaddr_in sa_cli;
    size_t client_len;
    char     buf [5800];

    // ssl part
    SSL_CTX *ctx;
    int err;

    X509    *client_cert;
    char    *str;
    SSL_METHOD *meth;


    // key part
    unsigned char key[KEYLEN];

    //serv_SSLCheck(ctx, ssl, client_cert, meth);




    /* SSL preliminaries. We keep the certificate and key with the context. */
    SSL_load_error_strings();
    SSLeay_add_ssl_algorithms();
    meth = SSLv23_server_method();
    ctx = SSL_CTX_new (meth);
    if (!ctx)
    {
        ERR_print_errors_fp(stderr);
        killChild(pid);
        exit(2);
    }


    // don't verify Client's certificate
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL); /* whether verify the certificate */
    SSL_CTX_load_verify_locations(ctx, CACERT, NULL);

    if (SSL_CTX_use_certificate_file(ctx, SERV_CERTF, SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        killChild(pid);
        exit(3);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, SERV_KEYF, SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        killChild(pid);
        exit(4);
    }

    if (!SSL_CTX_check_private_key(ctx))
    {
        fprintf(stderr, "Private key does not match the certificate public key\n");
        killChild(pid);
        exit(5);
    }



    /* ----------------------------------------------- */
    /* Prepare TCP socket for receiving connections */

    listen_sd = socket (AF_INET, SOCK_STREAM, 0);
    CHK_ERR(listen_sd, "socket");

    memset (&sa_serv, '\0', sizeof(sa_serv));
    sa_serv.sin_family      = AF_INET;
    sa_serv.sin_addr.s_addr = INADDR_ANY;
    sa_serv.sin_port        = htons (PORT);          /* Server Port number */

    // reuse port if already be bound
    int on = 1;
    setsockopt( listen_sd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on) );

    err = bind(listen_sd, (struct sockaddr *) &sa_serv,
               sizeof (sa_serv));
    CHK_ERR(err, "bind error in tcp tunnel");

    /* Receive a TCP connection. */

    err = listen (listen_sd, 5);
    CHK_ERR(err, "listen");


    int opt = 1;
    int activity,  valread, max_clients = 10,  new_socket , client_socket[10], sd, max_sd;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    // ssl part
    SSL *client_ssl[10];

    // iterator
    int i;

    char buffer[1024];
    //set of socket descriptors
    fd_set readfds;



    //a connection establishment message
    char *message = "welcome connecting to VPN server\n";
    //initialise all client_socket[] to 0 so not checked
    for (i = 0; i < max_clients; i++)
    {
        client_socket[i] = 0;
    }
    // initialize all client_ssl to NULL,
    for (i = 0; i < max_clients; i++)
    {
        SSL  *ssl;
        ssl = SSL_new (ctx);
        CHK_NULL(ssl);
        client_ssl[i] = ssl;
    }

    while(1)
    {
        //clear the socket set
        FD_ZERO(&readfds);

        //add master socket to set
        FD_SET(listen_sd, &readfds);
        max_sd = listen_sd;

        //add child sockets to set
        for ( i = 0 ; i < max_clients ; i++)
        {
            //socket descriptor
            sd = client_socket[i];

            //if valid socket descriptor then add to read list
            if(sd > 0)
                FD_SET( sd , &readfds);

            //highest file descriptor number, need it for the select function
            if(sd > max_sd)
                max_sd = sd;
        }

        printf("the max_sd is:%d", max_sd);
        //wait for an activity on one of the sockets , timeout is NULL , so wait indefinitely
        activity = select( max_sd + 1 , &readfds , NULL , NULL , NULL);

        if ((activity < 0) && (errno != EINTR))
        {
            printf("select error");
        }

        //If something happened on the listening socket , then its an incoming connection
        if (FD_ISSET(listen_sd, &readfds))
        {
            printf("listen socket got sth\n");


            if ((new_socket = accept(listen_sd, (struct sockaddr *)&address, (socklen_t *)&addrlen)) < 0)
            {
                perror("accept");
                exit(EXIT_FAILURE);
            }

            //inform user of socket number - used in send and receive commands
            printf("New connection , socket fd is %d , ip is : %s , port : %d \n" , new_socket , inet_ntoa(address.sin_addr) , ntohs(address.sin_port));


            //add new socket to array of sockets
            for (i = 0; i < max_clients; i++)
            {
                //if position is empty
                if( client_socket[i] == 0 )
                {
                    client_socket[i] = new_socket;
                    printf("Adding to list of sockets as %d\n" , i);



                    // pass client ip address to the udp tunnel
                    unsigned char temp[50];
                    temp[0] = 'i';           // 'i' is for udp tunnel to identify this is ip address
                    temp[1] = new_socket;           // add socket num in address info
                    char client_ip[50];
                    strcpy(client_ip, inet_ntoa(address.sin_addr));
                    printf("The client ip to be passed to the child process is:%s\n", client_ip);
                    printf("and the new socket number is:%d\n", new_socket);
                    updateArray1WithArray2(&temp[2], (unsigned char *)client_ip, strlen(client_ip));

                    // write key to the udp channel
                    write(pipe_fd, temp, strlen(client_ip) + 2);


                    // ssl part
                    SSL *ssl = client_ssl[i];
                    err = SSL_set_fd (ssl, new_socket);
                    if (err = 0)
                        PERROR("SSL_SET_fd");

                    err = SSL_accept (ssl);
                    CHK_SSL(err);

                    //send new connection greeting message
                    if( SSL_write(ssl, message, strlen(message)) != strlen(message) )
                    {
                        perror("send");
                    }
                    puts("Welcome message sent successfully");

                    break;
                }
            }

        }

        //else its some IO operation on some other socket :)
        for (i = 0; i < max_clients; i++)
        {
            sd = client_socket[i];
            SSL *ssl = client_ssl[i];
            if (FD_ISSET( sd , &readfds))
            {
                // //Check if it was for closing , and also read the incoming message
                // if ((valread = SSL_read( ssl , buffer, sizeof(buffer))) == 0)
                // {
                //     //Somebody disconnected , get his details and print
                //     getpeername(sd , (struct sockaddr *)&address , (socklen_t *)&addrlen);
                //     printf("Host disconnected , ip %s , port %d \n" , inet_ntoa(address.sin_addr) , ntohs(address.sin_port));

                //     //Close the socket and mark as 0 in list for reuse
                //     closeClient(ssl, ctx, &sd, &client_socket[i], &client_ssl[i]);

                // }

                // //Echo back the message that came in
                // else
                // {
                // do client stuff:
                //clientHandler(ssl, pipe_fd, key);
                int err = SSL_read(ssl, buf, sizeof(buf) - 1);
                CHK_SSL(err);
                buf[err] = '\0';
                if(DEBUG)
                {
                    printf("The content sent from client is:%s\n", buf);
                }
                if (strcmp(buf, "s") == 0) // shutdown
                {
                    printf("terminal signal sent from client!\n");
                    char *response = "SY";
                    err = SSL_write(ssl, response, strlen(response));
                    CHK_SSL(err);
                    closeClient(ssl, &sd, &client_socket[i]);
                    printf("The client with socket id: %d has been closed", sd);

                }
                if (strcmp(buf, "l") == 0)          // logging
                {
                    printf("Client request logging!\n");
                    char *response = "LY";
                    err = SSL_write(ssl, response, strlen(response));
                    CHK_SSL(err);
                    // check username
                    checkUsername(ssl);

                    // check password
                    checkPassword(ssl);
                }
                if (buf[0] == 'k')          // receiving key
                {
                    updateArray1WithArray2(key, &buf[1], KEYLEN); // eliminate the first 'k' signal from buf

                    if(DEBUG)
                    {
                        printf("key sent from client is:");
                        print(key, KEYLEN);
                    }

                    // inform client that server has received the key
                    char *response = "KY";
                    err = SSL_write(ssl, response, strlen(response));
                    CHK_SSL(err);

                    printf("key has been received from client!\n");

                    // pass key to the udp tunnel
                    unsigned char temp[KEYLEN + 2];
                    temp[0] = 'k';
                    temp[1] = sd;           // add socket num in key info
                    updateArray1WithArray2(&temp[2], key, KEYLEN);

                    // write key to the udp channel
                    write(pipe_fd, temp, KEYLEN + 2);

                    if (DEBUG)
                    {
                        printf("Here in parent process, the key sent to child is: ");
                        print(temp, KEYLEN + 2);
                    }
                }
                else if (strlen(buf) > 1)
                {
                    printf("unknown content coming from client!\n");
                }


            }
        }
    }
    /* Clean up. */
    killChild(pid);
    close (listen_sd);
    SSL_CTX_free (ctx);
}





// initialize collection to all NULLs
void Init_sockNum_IpkeyCollection()
{
    int i;
    for (i = 0; i < sizeof(sockNum_ip); i++)
    {
        sockNum_ip[i] = "a";            // can not initialize with NULL, otherwise when do strcmp, will segment core fault
    }
    for (i = 0; i < sizeof(sockNum_key); i++)
    {
        sockNum_key[i] = "a";
    }
    for (i = 0; i < sizeof(HostIpToVpnCliIp); i++)
    {
        VpnCliIp[i] = "a"; 
    }
    for (i = 0; i < sizeof(HostIpToVpnCliIp); i++)
    {
        HostIp[i] = 0;
    }

}
void storeIpIntoCollection(char *ip, int socketNum) // key shall be 'k', 'sock_num' + 16 byte real key info
{
    char *ipOnHeap = (char *)malloc( sizeof(unsigned char) * (strlen(ip) + 1));
    strcpy(ipOnHeap, ip);
    sockNum_ip[socketNum] = ipOnHeap;
    if (DEBUG)
    {
        //printf("In store process: the client's ip is :");

        // for(i = 0; i < strlen(ip); i++)
        // {
        //     printf("%c", ipOnHeap[i]);
        // }
        //printf(", stored in index(sock_id): %d\n", socketNum);
        printf("In store process: the client's ip is :%s , stored in index(sock_id): %d\n", ipOnHeap, socketNum);
    }
}

void storeKeyIntoCollection(unsigned char *key, int socketNum) // key shall be 'k', 'sock_num' + 16 byte real key info
{
    unsigned char *keyOnHeap = (unsigned char *)malloc( sizeof(unsigned char) * KEYLEN );
    updateArray1WithArray2(keyOnHeap, key, 16);
    if ( strcmp( sockNum_key[socketNum], "a" ) != 0)   // already store a key
    {
        free(sockNum_key[socketNum]);
    }
    sockNum_key[socketNum] = keyOnHeap;  // replace with new key
    if (DEBUG)
    {
        printf("the key:");
        print(keyOnHeap, KEYLEN);
        printf(", stored in index(sock_id): %d\n", socketNum);
    }
}

int lookForSockNum(char *ip)
{
    int i = 0;


    for (i = 0; i < sizeof(sockNum_ip); i++)
    {
        if (strcmp(sockNum_ip[i], ip) == 0 )  // if two ip string equal, then return index as socket id
        {
            if (DEBUG)
            {
                printf("current sock_ip is:%s, the passed in ip is: %s, and  i is: %d,\n", sockNum_ip[i], ip, i);
            }
            return i;
        }
    }
    return -1;
}

int lookForKey(unsigned char *key, int sock_id)
{
    if (0 <= sock_id && sock_id < sizeof(sockNum_key))
    {
        updateArray1WithArray2(key, sockNum_key[sock_id], KEYLEN);
        return 0;
    }
    return -1;
}

// check whether key and Ip address are correspondent
bool checkKey_Ip(unsigned char *key, char *ip)
{
    int sock_id = lookForSockNum(ip);
    if(lookForKey(key, sock_id) < 0 )
        return false;
    return true;
}




// key and IV part in UDP channel
///////////////////////////////////////////////////////

// the iv will be added at the head of the packet
// update len of buf at the same time
int addIVintoPacket(unsigned char *buf, int len, unsigned char *iv)
{
    unsigned char temp[len];
    updateArray1WithArray2(temp, buf, len);
    updateArray1WithArray2(buf, iv, KEYLEN);
    updateArray1WithArray2(&buf[KEYLEN], temp, len);
    return len + KEYLEN;
}

// the iv will be added at the head of the packet
// update len of buf at the same time
int extractIVfromPacket(unsigned char *buf, int len, unsigned char *iv)
{
    updateArray1WithArray2(iv, buf, KEYLEN);
    updateArray1WithArray2(buf, &buf[KEYLEN], len - KEYLEN);
    return len - KEYLEN;
}

int getClientID(unsigned char *buf)
{
    int sock_id = (int)buf[1];
    return sock_id;
}

int suckFromPipe_serv_side(int fd)
{
    int err;
    int sock_id;
    unsigned char buf[1024];
    bool hasKeyForThisCli = false;
    while (1)
    {
        err = read(fd, buf, sizeof(buf));
        if (err > 0)
        {
            //CHK_ERR(err,"read from parent process error");
            buf[err] = '\0';
            // if (strcmp("quit", buf) == 0) // receive terminate program command from parent process
            // {
            //     printf("udp channel is terminated...............\n");
            //     exit(0);
            // }
            if (buf[0] == 'k')
            {
                unsigned char key[KEYLEN];
                // get socket_id
                sock_id = getClientID(buf);
                // get key based on socket_id from client IP collection
                updateArray1WithArray2(key, &buf[2], KEYLEN);
                storeKeyIntoCollection(key, sock_id);
                if (DEBUG)
                {
                    printf("In the child process, key is:");
                    print(key, KEYLEN);
                }
                hasKeyForThisCli = true;   // we can do our work
                continue;
            }
            // get client's ip address from tcp tunnel
            // store it into collection for future use
            if (buf[0] == 'i')
            {
                // get socket_id
                sock_id = getClientID(buf);
                printf("in the child process, buf[0] == i, sock ID is %d\n", sock_id);
                // get key based on socket_id from client IP collection
                char address[50];
                updateArray1WithArray2((unsigned char *)address, &buf[2], strlen(buf) - 2);
                address[strlen(buf) - 2] = '\0';
                storeIpIntoCollection(address, sock_id);
                if (DEBUG)
                {
                    printf("In the child process, received client's ip address is: %s\n", address);
                }
                continue;
            }
            else
            {
                PERROR("unknown token received from tcp tunnel");
            }
        }
        else
        {
            break;
        }
    }
    return hasKeyForThisCli;
}


int receiveKeyFromTcpTunnel_cli_Side(unsigned char *key, int fd)
{
    int err;
    unsigned char buf[1024];
    err = read(fd, buf, sizeof(buf));
    if (err > 0)
    {
        //CHK_ERR(err,"read from parent process error");
        buf[err] = '\0';
        // if (strcmp("quit", buf) == 0) // receive terminate program command from parent process
        // {
        //     printf("udp channel is terminated...............\n");
        //     exit(0);
        // }
        if (buf[0] == 'k')
        {
            updateArray1WithArray2(key, &buf[1], KEYLEN);
            if (DEBUG)
            {
                printf("In the child process, key is:");
                print(key, KEYLEN);
            }
            return 1;
        }
        else
        {
            PERROR("unknown token received from tcp tunnel");
        }
    }
    return err;
}


/////////////////////////////////////////////////////////////

// udp tunnel part (child process)
////////////////////////////////////////////////////
// udp tunnel part (child process)
////////////////////////////////////////////////////


int appendSequenceNum(unsigned char *buf, int len)
{
    // copy a int number into 4 unsigned char block
    updateArray1WithArray2(&buf[len], (unsigned char *)&sequenceCounter, 4);
    return len + 4;
}

int extractSequenceNum(unsigned char *buf, int* len)
{
    *len = *len - 4; 
    int c = *((int *)(&buf[*len]));
    return c;
}

// return true if duplicate
bool duplicateInList(int seq)
{
    int i;
    int lowerBoundry = sequenceCounter - WindowSize;
    for (i = 0; i < 100; i++)
    {
        if (sequenceList[i] == seq)
            return true;
    }
    return false;
}
void updateInList()
{
    int i;
    int lowerBoundry = sequenceCounter - WindowSize;
    for (i = 0; i < 100; i++)
    {
        if (sequenceList[i] < lowerBoundry)
            sequenceList[i] = 0;
    }
}

void addToList(int seq)
{
    int i;
    for (i = 0; i < 100; i++)
    {
        if (sequenceList[i] == 0)
            sequenceList[i] = seq;
    }
}

void init_SequenceList()
{
    int i;
    for (i = 0; i < 100; i++)
    {
        sequenceList[i] = 0;
    }
}

void IncreaseSequenceCounterByOne()  // for client side, after send
{
    sequenceCounter++;
}

// anti-replay attack
// ruturn false to indicate drop the packet
bool checkSeqenceNum(int sequenceNum)
{
    int lowerBoundry = sequenceCounter - WindowSize;
    // less than the lowest sequence in the window: drop
    if (sequenceNum < lowerBoundry)
    {
        return false;
    }
    // bigger than largest sequence in the window, update the counter
    else if (sequenceNum > sequenceCounter)
    {
        sequenceCounter = sequenceNum;
        updateInList();
        addToList(sequenceNum);
        return true;
    }
    else
    {
        if (duplicateInList(sequenceNum))
        {
            return false;
        }
        else
        {
            addToList(sequenceNum);
            return false;
        }
    }

}




void udpTunnel(int MODE, int TUNMODE, int PORT, int server_port, char *server_ip, int pipe_fd)
{


    struct sockaddr_in sin, sout, from;

    struct ifreq ifr;

    int fd, s, fromlen, soutlen, l;

    int sock_id;

    unsigned char buf[5800];

    unsigned char key[KEYLEN];

    unsigned char iv[KEYLEN];

    Init_sockNum_IpkeyCollection();


    fd_set fdset;

    if ((fd = open("/dev/net/tun", O_RDWR)) < 0) PERROR("open");

    memset(&ifr, 0, sizeof(ifr));

    ifr.ifr_flags = TUNMODE;

    strncpy(ifr.ifr_name, "toto%d", IFNAMSIZ);

    if (ioctl(fd, TUNSETIFF, (void *)&ifr) < 0) PERROR("ioctl");

    printf("Allocated interface %s. Configure and use it\n", ifr.ifr_name);

    s = socket(PF_INET, SOCK_DGRAM, 0);

    // reuse port if already be bound

    sin.sin_family = AF_INET;

    sin.sin_addr.s_addr = htonl(INADDR_ANY);

    sin.sin_port = htons(PORT);

    if (MODE == 1)
    {
        int on = 1;
        setsockopt( s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on) );
    }

    if (bind(s, (struct sockaddr *)&sin, sizeof(sin)) < 0) PERROR("bind");

    if(MODE == 2)
    {
        fromlen = sizeof(from);
        from.sin_family = AF_INET;
        from.sin_port = htons(server_port);
        inet_aton(server_ip, &from.sin_addr);
    }


    bool begin = false;


    while (1)
    {

        // receive key from tcp channel
        if (MODE == 1)
        {
            int return1;
            if( return1 = suckFromPipe_serv_side(pipe_fd) > 0 )
            {
                printf("start to do job, return is: %d\n", return1);
                begin = true;
            }

        }
        if (MODE == 2)
        {
            if (receiveKeyFromTcpTunnel_cli_Side(key, pipe_fd) > 0)
                begin = true;
        }
        // if (sock_id = suckFromPipe(key, pipe_fd) > 0)
        // {
        //     begin = true;
        // }
        if (begin == 0)
        {
            sleep(1);
            //printf("There is no key passed into client udp tunnel: ");
            continue;
        }

        if (DEBUG && MODE == 2)
        {
            printf("The current key used in client udp tunnel is: ");
            print(key, KEYLEN);
        }

        FD_ZERO(&fdset);

        FD_SET(fd, &fdset);

        FD_SET(s, &fdset);

        if (select(fd + s + 1, &fdset, NULL, NULL, NULL) < 0) PERROR("select");

        // this is data send part ( from tun dev to socket)
        if (FD_ISSET(fd, &fdset))
        {
            // process flow is :
            // 1. generate IV
            // 2. encrypt data
            // 3. add iv
            // 4. HMAC

            // although for server, it will receive first and then update key information
            // we shall still double check whether key is correspond to current client
            if (MODE == 1)
            {
                checkKey_Ip(key, inet_ntoa(from.sin_addr));
            }

            l = read(fd, buf, sizeof(buf));

            if (l < 0) PERROR("read");

            // add iv in the head

            randomize(iv, IVLEN);

            if (DEBUG)
            {
                printf("The iv is:\n");
                print(iv, IVLEN);
            }

            if (DEBUG)
            {
                printf("Encpytion section:\n\n");
                // display buf content before encryption
                printf("before encryption: buffer length is:%d\n", l);
                printf("before encryption: buffer content is:\n");
                print(buf, l);
            }


            // encryption happens before sendint to socket
            /////////////////////////////////////////////////
            int newBufferLen = encryptData(buf, l, key, iv);
            if (!newBufferLen)
            {
                PERROR("encryption process wrong : (\n");
            }
            // update l
            l = newBufferLen;


            if (DEBUG)
            {
                // display packet content
                printf("after encryption: buffer length is:%d\n", l);
                printf("after encryption: buffer content is:\n");
                print(buf, l);
            }

            if (DEBUG)
            {
                printf("add iv section:\n\n");
                // display buf content before encryption
                printf("before adding iv: buffer length is:%d\n", l);
                printf("before adding iv: buffer content is:\n");
                print(buf, l);
            }


            l = addIVintoPacket(buf, l, iv);

            if (DEBUG)
            {
                // display buf content before encryption
                printf("after adding iv: buffer length is:%d\n", l);
                printf("after adding iv: buffer content is:\n");
                print(buf, l);
            }

            // add HMAC in the end of the packet
            /////////////////////////////////////////////////
            unsigned char hmac_value[EVP_MAX_MD_SIZE];

            int len_sign = doHmac(buf, l, hmac_value, key);
            if (!len_sign)
            {
                PERROR("HMAC process wrong : (\n");
            }
            appendHmac(buf, hmac_value, l, len_sign);

            // update the buf length
            l += len_sign;


            if (DEBUG)
            {
                // display packet content
                printf("after HMAC: buffer length is:%d\n", l);
                printf("after HMAC: buffer content is:\n");

                print(buf, l);

            }

            // now the data is encrypted and has signature
            ///////////////////////////////////////////////

            // // add sequence number on the tail of the packet
            // if(MODE == 2)
            // {
            //     l = appendSequenceNum(buf, l);
            //     printf("currently, the sequence is counted to: %d\n", sequenceCounter);
            
            //     IncreaseSequenceCounterByOne();  // update sequence counter by + 1
            // }


            // send processed data out to the server side
            if (sendto(s, buf, l, 0, (struct sockaddr *)&from, fromlen) < 0) PERROR("sendto");

            printf("send packet to  %s:%i\n" , inet_ntoa(from.sin_addr), ntohs(from.sin_port));

        }
        else    // this is the data receive part ( from socket to tun dev )
        {
            // initialize iterator
            int i;

            fromlen = sizeof(from);

            l = recvfrom(s, buf, sizeof(buf), 0, (struct sockaddr *)&from, &fromlen);

            printf("receive packet from  %s:%i\n" , inet_ntoa(from.sin_addr), ntohs(from.sin_port));
            // receive key from tcp channel
            if (MODE == 1)
            {
                suckFromPipe_serv_side(pipe_fd) ;
            }


            

            // process flow:
            // 1. detach HMAC part and (data+iv)
            // 2. HMAC verify
            // 3. extract iv from data
            // 4. decrypt

            // if (MODE == 1)
            // {
            //     // extract sequence num
            //     int seqNum = extractSequenceNum(buf, &l);
            //     int signal = checkSeqenceNum(seqNum);
            
            //     printf("The sequence of the packet is: %d\n", seqNum);
            
            //     if (signal)
            //     {
            //         printf("sequence number is normal, packet shall preserve\n");
            
            //     }
            //     else
            //     {
            //         printf("This is replay attack, packet shall dropped\n");
            //         printf("As for now, the replay attack's times: %d\n", replayCounter++);
            //         continue;
            //     }
            // }


            if (MODE == 1)
            {
                // server side to find key from pre stored key collection, then it can do decryption
                printf("looking in ip:%s\n", inet_ntoa(from.sin_addr));
                sock_id = lookForSockNum(inet_ntoa(from.sin_addr));
                if ( sock_id < 0 )
                {
                    printf("can not find client socket id, the ip addr unrecognizable\n");
                }
                // printf("current ip stored in collectionis:\n");
                // for(i = 0; i < 10; i++)
                // {
                //     printf("the socket number:%d, coresponding ip is:%s\n", i , sockNum_ip[i]);
                // }

                if(DEBUG)
                {
                    printf("the socket number found matches the client's ip addr is: %d\n", sock_id);
                }

                if (lookForKey(key, sock_id) < 0 )
                {
                    printf("can not find key, sock_id out of range\n");
                }
                // printf("current key  stored in collectionis:\n");
                // for(i = 0; i < 10; i++)
                // {
                //     printf("the socket number:%d, coresponding key is:", i);
                //     print(sockNum_key[i], KEYLEN);
                //     printf("\n");
                // }
                if(DEBUG)
                {
                    printf("the key found matches with sock id is:");
                    print(key, KEYLEN);
                }
            }

            
            if (DEBUG)
            {
                printf("Decryption section:\n\n");
                printf("the length of l is%d\n", l);
                printf("the untouched content from client is\n");
                print(buf, l);
            }


            // detach HMAC and data
            int datalength = l - HMACTYPE;
            int hmacLength = HMACTYPE;
            unsigned char data[datalength];
            unsigned char HMAC[hmacLength];
            for (i = 0; i < datalength; i++)
            {
                data[i] = buf[i];
            }
            for (i = 0; i < hmacLength; i++)
            {
                //printf("%d th element is:%02x\n", i, buf[i + datalength]);
                HMAC[i] = buf[i + datalength];
            }


            if (DEBUG)
            {
                // display buf content before encryption
                printf("before decryption: data length is:%d\n", datalength);
                printf("before decryption: data content is:\n");

                print(data, datalength);

                printf("The Hmac value is:\n");
                print(HMAC, hmacLength);
            }

            // do HMAC again to the data
            /////////////////////////////////////////////////
            unsigned char hmac_value[EVP_MAX_MD_SIZE];

            doHmac(data, datalength, hmac_value, key);

            bool isAuthenticated = compareHmac(HMAC, hmac_value, hmacLength);
            if (!isAuthenticated)
            {
                PERROR("not coming from authenticated party\n");
            }


            datalength = extractIVfromPacket(data, datalength , iv);


            if (DEBUG)
            {
                printf("after extraction, the iv is\n");
                print(iv, KEYLEN);
            }
            if (DEBUG)
            {
                printf("after extraction, the remaining data length is%d\n", datalength);
                printf("after extraction, the remaining data is\n");
                print(data, datalength);

            }

            // encryption happens before sendint to socket
            /////////////////////////////////////////////////
            int  decryptedLength = decryptData(data, datalength, key, iv);
            if (!decryptedLength)
            {
                PERROR("decryption process wrong!\n");
            }

            if(DEBUG)
            {
                // display packet content
                printf("after decryption: buffer length is:%d\n", decryptedLength);
                printf("after decryption: buffer content is:\n");

                print(data, decryptedLength);
            }


            // now the data is decrypted and authenticated
            ///////////////////////////////////////////////


            // shall be the decrypted length: original data's length
            if (write(fd, data, decryptedLength) < 0) PERROR("write");
        }
    }

    // clear key 
    overWritePassword(key, KEYLEN);

}


int getIpByHostName(char *hostName, char *ip)
{
    struct hostent *host;
    struct in_addr **addr_list;
    int i;

    if ( (host = gethostbyname( hostName ) ) == NULL)
    {
        // get the host info
        herror("gethostbyname");
        return 1;
    }

    addr_list = (struct in_addr **) host->h_addr_list;

    for(i = 0; addr_list[i] != NULL; i++)
    {
        //Return the first one;
        strcpy(ip , inet_ntoa(*addr_list[i]) );
        return 0;
    }

    return 1;
}


int main(int argc, char *argv[])
{
    int serv_PORT, PORT;

    char c, *p, *ptr, serv_ip[20], *cli_ip;

    int MODE = 0, TUNMODE = IFF_TUN;


    // take in arguments from command line
    while ((c = getopt(argc, argv, "i:s:c:eh")) != -1)
    {
        switch (c)
        {
        case 'h':

            usage();

        case 's':

            MODE = 1; // server mode

            PORT = atoi(optarg);

            break;
        case 'i':

            MODE = 2; // client mode

            char *ptr = memchr(optarg, ':', 16);

            if (!ptr) ERROR("invalid argument : [%s]\n", optarg);

            *ptr = 0;

            cli_ip = optarg;

            PORT = atoi(ptr + 1);

            printf("the  client ip is: %s\n", cli_ip);

            printf("the  client port is: %d\n", PORT);

            break;

        case 'c':

            MODE = 2; // client mode

            p = memchr(optarg, ':', 30);

            if (!p) ERROR("invalid argument : [%s]\n", optarg);

            *p = 0;


            char server_name[50];
            strcpy(server_name, optarg);
            if (DEBUG)
            {
                printf("\nthe server name is:%s\n", server_name);

            }

            getIpByHostName(server_name, serv_ip);  // get server's ip by looking into /etc/hosts file
            // strcpy(SER_CERT_CN, optarg);         // update CN

            serv_PORT = atoi(p + 1);

            if (DEBUG)
            {
                printf("\nthe server ip:%s, port is: %d", serv_ip, serv_PORT);
            }

            break;

        case 'e':

            TUNMODE = IFF_TAP;

            break;

        default:

            usage();
        }
    }

    if (MODE == 0) usage();

    // inti sequence number list
   // init_SequenceList();


    
    int fd[2];
    pipe(fd);
    fcntl(fd[0], F_SETFL, O_NONBLOCK);
    pid_t pid = fork();
    if(pid < 0)
    {
        PERROR("fork");
    }
    if (pid == 0) // child process : udp tunnel
    {
        prctl(PR_SET_PDEATHSIG, SIGHUP);
        close(fd[1]);
        if(DEBUG)
        {
            printf("\nin the child process, pid = %d\n", pid);
        }
        // start udp channel
        udpTunnel(MODE, TUNMODE, PORT, serv_PORT, serv_ip, fd[0]);
        printf("udp tunnel terminated\n\n\n\n");
        exit(0);
    }
    else  // parent process : tcp tunnel
    {
        if (DEBUG)
        {
            printf("\nin the parent process, pid = %d\n", pid);
        }


        close(fd[0]);
        switch(MODE)
        {
        case 1:   // server
            tcpTunnel_server(fd[1], pid, PORT + 1); // tcp port is 1 bigger than udp tunnel port
            break;
        case 2:   // client
            tcpTunnel_client(serv_ip, cli_ip, fd[1], pid, serv_PORT + 1, PORT + 1);
            break;
        }
        exit(0);
    }
}
