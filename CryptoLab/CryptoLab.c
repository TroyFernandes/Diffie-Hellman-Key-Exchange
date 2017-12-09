/*
* Author: Troy Fernandes
* Date: November 30th 2017
* This program demonstrates the Diffie Hellman Key Exchange
*/

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>


//Define the number of puzzles you want to generate. 
//In this case 2^16 = 65536
#define MAX_KEYS 1024


//Needed for OpenSSL Development in Visual Studio 2015
//Comment out after
#pragma comment (lib, "crypt32")

/*
This youtube video explaining Merkles Puzzles was used as reference
https://www.youtube.com/watch?v=wRBkzEX-4Qo

Merkle's puzzle is as follows...

Pi {0,1}^2

XiKi {0,1}^128

Puzzle = E( 0^14||Pi , "Puzzle Xi || Ki" )

1) Alice sends 2^16 puzzles to Bob
2) Bob chooses one random puzzle and tries all possible keys knowing
   that the first 14 bytes are zero
3) If Bob sees the word "Puzzle" in the message after decrypting with the given key, he knows that he successfully solved
   one of the puzzles.
4) In the decrypted message, Bob sees the Xi and Ki value embedded, therefore he sends back to Alice Xi
5) Alice then uses the Xi value to look up in her table the matching Ki value.
6) Ki becomes the shared secret key between Bob and Alice

*/




/*
Struct for Alice which holds an identifier, the puzzle, Xi, and Ki
*/
struct xi_ki {
	int i;
	char *puzzle[39];
	char *firstSecretX[16];
	char *sharedSecretK[16];
};
/*
Struct for all the encrypted messages Alice generates.
Alice will send these encrypted puzzles to Bob
*/
struct encryptedMessages {
	unsigned char cipher[128];

};

//Pointers for the structs
struct encryptedMessages *pointer;
struct xi_ki *xi_ki_pointer;

int counterV;
int puzCounter;
//Prototypes
void solve();
void encPuzzle(int i, char *encKey);
void generate(int identifier);
void encryptMessage(char *encKey, char *encIV, char *message, int index);
void decryptMessage(char *decKey, char *decIV, unsigned char ciphertextLocal[128]);
void lookup();

//Holds the cipher text
unsigned char ciphertext[128];
//Holds the deciphered text
unsigned char decryptedtext[128];
//length variables
int decryptedtext_len, ciphertext_len;
//Decrypted text will be copied to this array and getXI will manipulated to check whether 
//the puzzle has been successfully decrypted
unsigned char getXI[128];

clock_t begin, end;
double time_spent;


int main(void)
{

	printf("ALICE ----------------------------------------------------------------\n");
	//Allocate memory
	xi_ki_pointer = malloc(sizeof(struct xi_ki) * MAX_KEYS);
	pointer = malloc(sizeof(struct encryptedMessages) * MAX_KEYS);
	//Using a seed
	srand(time(NULL));

	if (xi_ki_pointer == NULL) {
		perror("Malloc");
		exit(EXIT_FAILURE);
	}

	begin = clock();
	//Start generating puzzles. In this case 2^16 = 65536
	for (int i = 0; i < MAX_KEYS; i++) {
		generate(i);
		//break;
	}
	end = clock();

	time_spent = (double)(end - begin) / CLOCKS_PER_SEC;

	//Bob tries to solve a given puzzle	
	solve();

	//Alice will lookup in her database the matching Ki value for a given Xi value
	lookup(xi_ki_pointer);

	printf("-----------------------------------------------------------------------\n");
	printf("%d Puzzles were generated in %fs\n", MAX_KEYS, time_spent);
	printf("Average Generations per Second is %f G/s\n",MAX_KEYS/time_spent);

	//Free dynamically allocated memory
	free(xi_ki_pointer);
	free(pointer);

	return 0;
}

void handleErrors(void)
{
	ERR_print_errors_fp(stderr);
	abort();
}

//Taken from the OpenSSL Wiki on how to use the built in encryption function https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext)
{
	EVP_CIPHER_CTX *ctx;

	int len;

	int ciphertext_len;

	/* Create and initialise the context */
	if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

	/* Initialise the encryption operation. IMPORTANT - ensure you use a key
	* and IV size appropriate for your cipher
	* In this example we are using 256 bit AES (i.e. a 256 bit key). The
	* IV size for *most* modes is the same as the block size. For AES this
	* is 128 bits */
	if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
		handleErrors();

	/* Provide the message to be encrypted, and obtain the encrypted output.
	* EVP_EncryptUpdate can be called multiple times if necessary
	*/
	if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
		handleErrors();
	ciphertext_len = len;

	/* Finalise the encryption. Further ciphertext bytes may be written at
	* this stage.
	*/
	if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
	ciphertext_len += len;

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	return ciphertext_len;
}

//Taken from the OpenSSL Wiki on how to use the built in decrpytion function https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,unsigned char *iv, unsigned char *plaintext)
{
	EVP_CIPHER_CTX *ctx;

	int len;

	int plaintext_len;

	/* Create and initialise the context */
	if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

	/* Initialise the decryption operation. IMPORTANT - ensure you use a key
	* and IV size appropriate for your cipher
	* In this example we are using 256 bit AES (i.e. a 256 bit key). The
	* IV size for *most* modes is the same as the block size. For AES this
	* is 128 bits */
	if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
		handleErrors();

	/* Provide the message to be decrypted, and obtain the plaintext output.
	* EVP_DecryptUpdate can be called multiple times if necessary
	*/
	if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
		handleErrors();
	plaintext_len = len;

	/* Finalise the decryption. Further plaintext bytes may be written at
	* this stage.
	*/
	if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) //handleErrors();
	plaintext_len += len;

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	return plaintext_len;
}

//Generate puzzles. identifier helps for easy lookup for corresponding Puzzle, Xi, and Ki
void generate(int identifier) {
	printf("GENERATING PUZZLE #%d\n",identifier);
	//Array for the hex values
	char *array[16] = { "0","1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f" };

	//Array for the private keys
	char *privateKeyTemp[16];

	//Array for the Xi value
	char *XiTemp[16];
	char *xiPointer = XiTemp;

	//Array for the Ki Value
	char *KiTemp[16];
	char *kiPointer = KiTemp;

	//Generate a random Key, Xi and Ki
	for (int i = 0; i < 16; i++) {
		sprintf(privateKeyTemp, "00000000000000%s%s", array[rand() % 16], array[rand() % 16]);
		xiPointer += sprintf(xiPointer, "%s", array[rand() % 16]);
		kiPointer += sprintf(kiPointer, "%s", array[rand() % 16]);

	}
	//printf("Struct Identifier #%d\n",identifier);
	printf("Key Used %s\n", privateKeyTemp);
	//printf("Xi Value %s\n", XiTemp);
	//printf("Ki Value %s\n", KiTemp);

	//Use the identifier to put the proper values in the struct
	xi_ki_pointer[identifier].i = identifier;
	sprintf(xi_ki_pointer[identifier].puzzle, "Puzzle %s%s", XiTemp, KiTemp);
	strcpy(xi_ki_pointer[identifier].firstSecretX, XiTemp);
	strcpy(xi_ki_pointer[identifier].sharedSecretK, KiTemp);

	//Encrypt the puzzle
	encPuzzle(identifier, privateKeyTemp);

}

//Encrypt puzzle and save it to the encrypted message struct
void encPuzzle(int i, char *encKey) {
	char *message[39];
	//printf("Key is: %s\n", encKey);
	sprintf(message, "Puzzle %s%s", xi_ki_pointer[i].firstSecretX, xi_ki_pointer[i].sharedSecretK);
	//printf("Plaintext is: %s\n", message);
	encryptMessage(encKey, "e0e0e0e0f1f1f1f1", message, i);
	//memset(message, 0, 39 * (sizeof message[0]));

}

//Function to solve one of the puzzles
void solve() {
	printf("\nSOLVING----------------------------------------------------------\n");

	char *key[16];

	unsigned char *iv = (unsigned char *)"e0e0e0e0f1f1f1f1";

	//Pattern match word
	unsigned char *word = "Puzzle";
	//Try all possible keys. In this case (2^4)*(2^4) = 256. 
	//This keeps the maximum key value 00000000000000FF
	for (int i = 0; i < 256; i ++) {

		sprintf(key, "00000000000000%02x", i);
		printf("*\nUsing Key %s\n", key);
		//Decrypt the message using the sequentially generated key, IV, and by choosing a random puzzle 
		decryptMessage(key,iv,pointer[(rand() % MAX_KEYS)].cipher);
		//Check to see whether "Puzzle" is in the decrypted text.
		if (strstr(decryptedtext,word)) {

			//Copy the decrypted text into another array
			strncpy(getXI, decryptedtext, 23);
			//null terminate
			getXI[23] = 0;
			//Remove necessary data to only obtain the Xi value
			memmove(getXI, getXI + 7, strlen(getXI));
			//Print out the key used to decrypt
			printf("Found the key used: %s\n", key);
			//printf("Decrypted text is: %s\n", getXI);
			//Done
			break;
		}

		/*
		If i = 255, then reset i.
		*/
		if (i == 255) {
			i = 0;
		}
		//break;
	}

}

//Encryption method which takes a key, IV, message, and index
void encryptMessage(char *encKey, char *encIV, char *message, int index) {
	//printf("\n");
	//printf("ENCRYPTION METHOD----------------------------------------------------------\n");

	/* A 256 bit key */
	unsigned char *key = (unsigned char *)encKey;


	/* A 128 bit IV */
	unsigned char *iv = (unsigned char *)encIV;

	/* Message to be encrypted */
	unsigned char *plaintext = (unsigned char *)message;


	/* Initialise the library */
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
	OPENSSL_config(NULL);

	/* Encrypt the plaintext */
	ciphertext_len = encrypt(plaintext, strlen((char *)plaintext), key, iv, ciphertext);
	encrypt(plaintext, strlen((char *)plaintext), key, iv, pointer[index].cipher);

	//printf("Ciphertext length: %d\n", ciphertext_len);
	//printf("Ciphertext is: %s\n", ciphertext);

	//printf("------------------------------------------------------------------\n");
	//printf("Key Was: %s\n", key);
	//printf("IV Was: %s\n", iv);

	//printf("Plaintext Was: %s\n", plaintext);
	/* Do something useful with the ciphertext here */

	//printf("Ciphertext is: \n");
	//BIO_dump_fp(stdout, (const char *)ciphertext, ciphertext_len);
	//printf("\n");

	//printf("CIPHER TEXT\n");

	//for (counterV = 0; counterV < 48; counterV++) {
	//	printf("%x", ciphertext[counterV]);
	//}
	//printf("\n");
	//printf("------------------------------------------------------------------\n");

	/* Clean up */
	EVP_cleanup();
	ERR_free_strings();

	//printf("------------------------------------------------------------------\n");//Alice done

}

//Decryption method which takes a key, IV, and the ciphertext
void decryptMessage(char *decKey, char *decIV, unsigned char ciphertextLocal[128]) {
	//printf("\n");

	//printf("DECRYPTION METHOD----------------------------------------------------------\n");
	/* A 256 bit key */
	unsigned char *key = (unsigned char *)decKey;


	/* A 128 bit IV */
	unsigned char *iv = (unsigned char *)decIV;


	/* Initialise the library */
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
	OPENSSL_config(NULL);

	/* Decrypt the ciphertext */
	decryptedtext_len = decrypt(ciphertextLocal, ciphertext_len, key, iv, decryptedtext);

	//printf("decrpytext length: %d\n", decryptedtext_len);

	/* Add a NULL terminator. We are expecting printable text */
	decryptedtext[decryptedtext_len + 16] = '\0';

	/* Show the decrypted text */
	printf("Decrypted text is: %s\n", decryptedtext);

	/* Clean up */
	EVP_cleanup();
	ERR_free_strings();

	//printf("------------------------------------------------------------------\n");//Alice done


}

//Lookup function that looks up for the corresponding Ki value given an Xi value
void lookup() {
	printf("\nLOOKING UP KEY/VALUE PAIR\n");
	for (int i = 0; i < MAX_KEYS; i++) {
		if (strstr(xi_ki_pointer[i].firstSecretX, getXI)) {
			printf("Solved Puzzle #%d\n",i);
			printf("Xi %s | Ki %s\n", xi_ki_pointer[i].firstSecretX, xi_ki_pointer[i].sharedSecretK);
			printf("Secret Key b/w Bob and Alice will be: %s\n", xi_ki_pointer[i].sharedSecretK);
			break;
		}
		
	}
}