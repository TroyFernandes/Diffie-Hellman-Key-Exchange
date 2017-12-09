#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <fcntl.h>
#include <unistd.h>
#include <getopt.h>

#define MAXSIZE 4096
#define PUB_KEY_LEN 256
#define ERR_SOCKET 2
#define ERR_CONN 3

#define CHECK(assertion, call_description)  \
  do {                                      \
    if (!(assertion)) {                     \
      fprintf(stderr, "(%s, %d): ",         \
        __FILE__, __LINE__);                \
      perror(call_description);             \
      exit(EXIT_FAILURE);                   \
    }                                       \
  } while(0)


/**
* Open file <filename>, read public Diffie-Hellman parameters P and G and store them in <pdhm>
* @param pdhm Diffie-Hellman key exchange context
* @param filename file from which to read P and G
*/
DH * __read_pg_from_file(const char * filename) {
	BIO * pbio;
	DH * pdh;

	/* Get DH modulus and generator (P and G) */
	pbio = BIO_new_file(filename, "r");
	CHECK(pbio != NULL, "BIO_new_file");

	/* Read P and G from f */
	pdh = PEM_read_bio_DHparams(pbio, NULL, NULL, NULL);
	CHECK(pdh != NULL, "PEM_read_bio_DHparams");

	BIO_free(pbio);
	return pdh;
}

void my_receive(int sockfd, char * buffer, int length) {
	int bytes_received = 0;
	int rc;
	while (bytes_received < length) {
		rc = recv(sockfd, buffer + bytes_received, length - bytes_received, 0);
		CHECK(rc >= 0, "recv");

		bytes_received += rc;
	}
}

int main(int argc, char* argv[]) {
	int k, n;
	int opt = 0;
	int listen_fd = 0;
	int connect_fd = 0;
	char buf[MAXSIZE];
	int file_fd;
	char file_size[256];
	int len = 0;
	unsigned char buf_pubkey_ours[256];
	unsigned char buf_pubkey_theirs[256];
	unsigned char buf_secret_key[256];
	BIGNUM *pub_key, *priv_key, *pub_key_theirs;
	unsigned int serv_port = 1337;
	char* serv_ip = "127.0.0.1";
	char* filename = "smallfile.dat";
	struct sockaddr_in client_addr, server_addr;
	socklen_t client_len;
	size_t bytes_sent, bytes_read;

	// get arg params
	while ((opt = getopt(argc, argv, "i:p:f:")) != -1) {
		switch (opt) {
		case 'i':
			serv_ip = optarg;
			break;
		case 'p':
			serv_port = atoi(optarg);
			break;
		case 'f':
			filename = optarg;
			break;
		default:
			fprintf(stderr, "Usage %s [-i IP] [-p PORT] [-f FILENAME]\n", argv[0]);
			exit(EXIT_FAILURE);
		}
	}

	// get DH public key using fixed parameters
	DH * tdh = __read_pg_from_file("dhparam.pem");

	// TODO 1: obtain DH public key from the parameters already saved in tdh
	// Check the function DH_generate_key
	// See documentation at:
	// https://www.openssl.org/docs/man1.1.0/crypto/

	// TODO 2: obtain the public and private keys in the BIGNUM structs
	// pub_key and priv_key. Check what methods (DH_get..) may help you do that

	// Export public key to binary and print it
	n = BN_num_bytes(pub_key);
	printf("[server] Pub key has %d bytes\n", n);
	CHECK(PUB_KEY_LEN == n, "DH PUB KEY LEN");
	BN_bn2bin(pub_key, buf_pubkey_ours);
	printf("[server] Our public key is: ");
	for (k = 0; k<n; k++)
		printf("%02X", buf_pubkey_ours[k]);
	printf("\n");

	/* Create new socket */
	listen_fd = socket(AF_INET, SOCK_STREAM, 0);
	CHECK(listen_fd >= 0, "socket");

	/* Setup sockaddr_in struct */
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = inet_addr(serv_ip);
	server_addr.sin_port = htons(serv_port);

	/* Bind */
	CHECK(bind(listen_fd, (struct sockaddr *) &server_addr, sizeof(server_addr)) >= 0, "bind");

	/* Listen */
	CHECK(listen(listen_fd, 0) >= 0, "listen");

	printf("[server] Server listening on port %d...\n", serv_port);

	/* Accept incoming connections */
	while (1) {
		client_len = sizeof(client_addr);
		connect_fd = accept(listen_fd, (struct sockaddr *) &client_addr, &client_len);
		CHECK(connect_fd >= 0, "accept");

		printf("[server] Got a request...\n");

		printf("[server] Sending public key...\n");
		len = send(connect_fd, buf_pubkey_ours, n, 0);
		CHECK(len >= 0, "send");

		my_receive(connect_fd, buf_pubkey_theirs, 256);
		printf("[server] Received public key from client...\n");
		printf("[server] The received public key is: ");
		for (k = 0; k<PUB_KEY_LEN; k++)
			printf("%02X", buf_pubkey_theirs[k]);
		printf("\n");

		// Obtain the secret key

		// TODO 3:get the public key into the BIGNUM buffer pub_key_theirs (what might correspond to BN_bn2bin ?)

		// TODO 4: compute the secret key from our DH structure and the other party public key
		// return the length in the integer n, although we expect it to be PUB_KEY_LEN

		// Print exchanged secret key
		printf("[client] Exchanged secret key has %d bytes\n", n);
		printf("[client] The exchanged secret key is: ");
		for (k = 0; k<n; k++)
			printf("%02X", buf_secret_key[k]);
		printf("\n");
	}

	close(listen_fd);
	close(file_fd);


	DH_free(tdh);
	return 0;
}


