/* serv.cpp  -  Minimal ssleay server for Unix
   30.9.1996, Sampo Kellomaki <sampo@iki.fi> */


/* mangled to work with SSLeay-0.9.0b and OpenSSL 0.9.2b
   Simplified to be even more minimal
   12/98 - 4/99 Wade Scholine <wades@mail.cybg.com> */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <openssl/rsa.h>       /* SSLeay stuff */
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>


/* define HOME to be dir for key and cert files... */
#define HOME "./"
/* Make these what you want for cert & key files */
#define CERTF  HOME "server.crt"
#define KEYF  HOME  "server.key"
#define CACERT HOME "ca.crt"


#define CHK_NULL(x) if ((x)==NULL) exit (1)
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define CHK_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stderr); exit(2); }

// bool type 
#define true 1;
#define false 0;
typedef int bool;



bool checkUsername(char* buf)
{
  char username[1024]; 
  FILE* f = fopen("username","r");
  fread(username, strlen(buf), 1, f);
  fclose(f);
  username[strlen(buf)] = '\0';
  if(strcmp(username,buf)== 0)
  {
    return true;
  }
  else 
  {
    return false;
  }
}
bool checkPassword(char* buf)
{
  char password[1024]; 
  FILE* f = fopen("password","r");
  fread(password, strlen(buf), 1, f);
  fclose(f);
  password[strlen(buf)] = '\0';
  if(strcmp(password,buf)== 0)
  {
    return true;
  }
  else 
  {
    return false;
  }
}

bool isStopSignal(char* buf)
{
  char* stop = "exit";
  int isStop = strcmp(stop,buf);
  if (isStop ==0)
  {
    return true;
  }
  else
  {
    return false;
  }
}

void print(unsigned char* buf, int len)
{
	int i;
	for (i = 0; i < len; i++)
	{
		printf("%02x", buf[i]);
	}
	printf("\n\n\n");
}

int main ()
{
  int err;
  int listen_sd;
  int sd;
  struct sockaddr_in sa_serv;
  struct sockaddr_in sa_cli;
  size_t client_len;
  SSL_CTX* ctx;
  SSL*     ssl;
  X509*    client_cert;
  char*    str;
  char     buf [4096];
  SSL_METHOD *meth;
  
  /* SSL preliminaries. We keep the certificate and key with the context. */

  SSL_load_error_strings();
  SSLeay_add_ssl_algorithms();
  meth = SSLv23_server_method();
  ctx = SSL_CTX_new (meth);
  if (!ctx) {
    ERR_print_errors_fp(stderr);
    exit(2);
  }
	

// don't verify Client's certificate
  SSL_CTX_set_verify(ctx,SSL_VERIFY_NONE,NULL); /* whether verify the certificate */
  SSL_CTX_load_verify_locations(ctx,CACERT,NULL);
  
  if (SSL_CTX_use_certificate_file(ctx, CERTF, SSL_FILETYPE_PEM) <= 0) {
    ERR_print_errors_fp(stderr);
    exit(3);
  }
  if (SSL_CTX_use_PrivateKey_file(ctx, KEYF, SSL_FILETYPE_PEM) <= 0) {
    ERR_print_errors_fp(stderr);
    exit(4);
  }

  if (!SSL_CTX_check_private_key(ctx)) {
    fprintf(stderr,"Private key does not match the certificate public key\n");
    exit(5);
  }

  /* ----------------------------------------------- */
  /* Prepare TCP socket for receiving connections */

  listen_sd = socket (AF_INET, SOCK_STREAM, 0);   CHK_ERR(listen_sd, "socket");
  
  memset (&sa_serv, '\0', sizeof(sa_serv));
  sa_serv.sin_family      = AF_INET;
  sa_serv.sin_addr.s_addr = INADDR_ANY;
  sa_serv.sin_port        = htons (1111);          /* Server Port number */
  
  err = bind(listen_sd, (struct sockaddr*) &sa_serv,
	     sizeof (sa_serv));                   CHK_ERR(err, "bind");
	     
  /* Receive a TCP connection. */
	     
  err = listen (listen_sd, 5);                    CHK_ERR(err, "listen");
  
  client_len = sizeof(sa_cli);
  sd = accept (listen_sd, (struct sockaddr*) &sa_cli, &client_len);
  CHK_ERR(sd, "accept");
  close (listen_sd);

  printf ("Connection from %lx, port %x\n",
	  sa_cli.sin_addr.s_addr, sa_cli.sin_port);
  
  /* ----------------------------------------------- */
  /* TCP connection is ready. Do server side SSL. */

  ssl = SSL_new (ctx);                           CHK_NULL(ssl);
  SSL_set_fd (ssl, sd);
  err = SSL_accept (ssl);                        CHK_SSL(err);
  
  /* Get the cipher - opt */
  
  printf ("SSL connection using %s\n", SSL_get_cipher (ssl));
  
  /* Get client's certificate (note: beware of dynamic allocation) - opt */

  client_cert = SSL_get_peer_certificate (ssl);
  if (client_cert != NULL) {
    printf ("Client certificate:\n");
    
    str = X509_NAME_oneline (X509_get_subject_name (client_cert), 0, 0);
    CHK_NULL(str);
    printf ("\t subject: %s\n", str);
    OPENSSL_free (str);
    
    str = X509_NAME_oneline (X509_get_issuer_name  (client_cert), 0, 0);
    CHK_NULL(str);
    printf ("\t issuer: %s\n", str);
    OPENSSL_free (str);
    
    /* We could do all sorts of certificate verification stuff here before
       deallocating the certificate. */
    
    X509_free (client_cert);
  } else
    printf ("Client does not have certificate.\n");

  /* DATA EXCHANGE - Receive message and send reply. */

    // check username
  char username[1024];
  err = SSL_read (ssl, username, sizeof(username) - 1);                   CHK_SSL(err);
  username[err] = '\0';
  printf ("Got %d chars:'%s'\n", err, username);
  if (checkUsername(username))
    printf("username correct\n");
  else 
    printf("username incorrect\n");

	// check password
  char password[1024];
  err = SSL_read (ssl, password, sizeof(password) - 1);                   CHK_SSL(err);
  password[err] = '\0';
  if (checkPassword(password))
    printf("password correct\n");
  else 
    printf("password incorrect\n");
  printf ("Got %d chars:'%s'\n", err, password);
  
  // check key
 char key [16];
   err = SSL_read (ssl, key, sizeof(key) - 1);                   CHK_SSL(err);
  	FILE* k = fopen("key", "w");
  	fwrite(key, 16, 1, k);
  	fclose(k);
  printf ("key is:");
  print(key,16);

  err = SSL_write (ssl, "I hear you.", strlen("I hear you."));  CHK_SSL(err);
  
  /* Clean up. */

  close (sd);
  SSL_free (ssl);
  SSL_CTX_free (ctx);

  return 0;
}




/* EOF - serv.cpp */
