#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

// Function prototypes
const char *detect_hash_type(const char *hash);
void compute_hash(const char *input, unsigned char *output, const char *hash_type);
void hash_to_hex(const unsigned char *hash, char *hex_output, int len);
void encrypt_message(const char *message, const char *key, const char *iv, unsigned char *encrypted, int *len, const EVP_CIPHER *cipher);
void decrypt_message(const unsigned char *encrypted, int len, const char *key, const char *iv, char *decrypted, const EVP_CIPHER *cipher);
void encode_base64(const char *input, char *output);
void encode_hex(const char *input, char *output);
void decode_base64(const char *input, char *output);
void decode_hex(const char *input, unsigned char *output, int *len);
void interactive_mode();
void crack_hash(const char *target_hash, const char *password_file, const char *hash_type);

// Function to detect the hash type based on its length
const char *detect_hash_type(const char *hash) {
    size_t hash_len = strlen(hash);
    if (hash_len == 64) return "SHA256";
    if (hash_len == 40) return "SHA1";
    if (hash_len == 32) return "MD5";
    return "Unknown";
}

// Function to hash a given string using a specified algorithm
void compute_hash(const char *input, unsigned char *output, const char *hash_type) {
    const EVP_MD *md;

    if (strcmp(hash_type, "SHA256") == 0) {
        md = EVP_sha256();
    } else if (strcmp(hash_type, "SHA1") == 0) {
        md = EVP_sha1();
    } else if (strcmp(hash_type, "MD5") == 0) {
        md = EVP_md5();
    } else {
        fprintf(stderr, "Unsupported hash type: %s\n", hash_type);
        exit(1);
    }

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, input, strlen(input));
    EVP_DigestFinal_ex(mdctx, output, NULL);
    EVP_MD_CTX_free(mdctx);
}

// Function to convert the hash into a readable hex format
void hash_to_hex(const unsigned char *hash, char *hex_output, int len) {
    for (int i = 0; i < len; i++) {
        sprintf(hex_output + (i * 2), "%02x", hash[i]);
    }
    hex_output[len * 2] = '\0';
}

// Base64 encoding function
void encode_base64(const char *input, char *output) {
    BIO *bio, *b64;
    BUF_MEM *buffer;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL); // No newline
    bio = BIO_push(b64, bio);

    BIO_write(bio, input, strlen(input));
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &buffer);

    memcpy(output, buffer->data, buffer->length);
    output[buffer->length] = '\0';

    BIO_free_all(bio);
}

// Hex encoding function
void encode_hex(const char *input, char *output) {
    for (size_t i = 0; i < strlen(input); i++) {
        sprintf(output + (i * 2), "%02x", (unsigned char)input[i]);
    }
    output[strlen(input) * 2] = '\0';
}

// Base64 decoding function
void decode_base64(const char *input, char *output) {
    BIO *bio, *b64;
    int decode_len;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_mem_buf(input, -1);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL); // No newline
    bio = BIO_push(b64, bio);

    decode_len = BIO_read(bio, output, strlen(input));
    output[decode_len] = '\0';

    BIO_free_all(bio);
}

// Hex decoding function
void decode_hex(const char *input, unsigned char *output, int *len) {
    size_t input_len = strlen(input);
    *len = input_len / 2;

    for (size_t i = 0; i < *len; i++) {
        sscanf(input + (i * 2), "%2hhx", &output[i]);
    }
}

// Encryption function
void encrypt_message(const char *message, const char *key, const char *iv, unsigned char *encrypted, int *len, const EVP_CIPHER *cipher) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, cipher, NULL, (unsigned char *)key, (unsigned char *)iv);

    int outlen;
    EVP_EncryptUpdate(ctx, encrypted, &outlen, (unsigned char *)message, strlen(message));
    *len = outlen;

    EVP_EncryptFinal_ex(ctx, encrypted + outlen, &outlen);
    *len += outlen;

    EVP_CIPHER_CTX_free(ctx);
}

// Decryption function
void decrypt_message(const unsigned char *encrypted, int len, const char *key, const char *iv, char *decrypted, const EVP_CIPHER *cipher) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, cipher, NULL, (unsigned char *)key, (unsigned char *)iv);

    int outlen;
    EVP_DecryptUpdate(ctx, (unsigned char *)decrypted, &outlen, encrypted, len);

    int tmplen;
    EVP_DecryptFinal_ex(ctx, (unsigned char *)decrypted + outlen, &tmplen);
    outlen += tmplen;

    decrypted[outlen] = '\0';
    EVP_CIPHER_CTX_free(ctx);
}

// Interactive mode
void interactive_mode() {
    while (1) {
        printf("\n--- Interactive Menu ---\n");
        printf("1. Hash a string\n");
        printf("2. Encrypt/Encode a message\n");
        printf("3. Decrypt/Decode a message\n");
        printf("4. Exit\n");
        printf("Enter your choice: ");

        int choice;
        scanf("%d", &choice);
        getchar(); // Consume newline

        if (choice == 4) {
            printf("Exiting...\n");
            break;
        }

        char input[256], output[1024], key[32], iv[16];
        int len;

        switch (choice) {
            case 1: { // Hash a string
                printf("Enter the string to hash: ");
                fgets(input, sizeof(input), stdin);
                input[strcspn(input, "\n")] = '\0';

                printf("Select hash type (SHA256/SHA1/MD5): ");
                char hash_type[10];
                fgets(hash_type, sizeof(hash_type), stdin);
                hash_type[strcspn(hash_type, "\n")] = '\0';

                unsigned char hash[EVP_MAX_MD_SIZE];
                compute_hash(input, hash, hash_type);
                hash_to_hex(hash, output, strlen(hash_type) == 6 ? 32 : (strlen(hash_type) == 4 ? 20 : 16));
                printf("Hashed (%s): %s\n", hash_type, output);
                break;
            }

            case 2: { // Encrypt a message
                printf("Enter the message to encrypt/encode: ");
                fgets(input, sizeof(input), stdin);
                input[strcspn(input, "\n")] = '\0';

                printf("Select encryption/encoding format:\n");
                printf("1. Base64\n");
                printf("2. Hex\n");
                printf("3. AES-256-CBC\n");
                printf("4. AES-128-CBC\n");
                printf("Enter your choice: ");

                int enc_choice;
                scanf("%d", &enc_choice);
                getchar(); // Consume newline

                switch (enc_choice) {
                    case 1: // Base64
                        encode_base64(input, output);
                        printf("Encoded (Base64): %s\n", output);
                        break;

                    case 2: // Hex
                        encode_hex(input, output);
                        printf("Encoded (Hex): %s\n", output);
                        break;

                    case 3: // AES-256-CBC
                    case 4: { // AES-128-CBC
                        const EVP_CIPHER *cipher = (enc_choice == 3) ? EVP_aes_256_cbc() : EVP_aes_128_cbc();

                        printf("Enter a 32-character key: ");
                        fgets(key, sizeof(key), stdin);
                        key[strcspn(key, "\n")] = '\0';

                        printf("Enter a 16-character IV: ");
                        fgets(iv, sizeof(iv), stdin);
                        iv[strcspn(iv, "\n")] = '\0';

                        unsigned char encrypted[1024];
                        encrypt_message(input, key, iv, encrypted, &len, cipher);

                        printf("Encrypted message (hex): ");
                        for (int i = 0; i < len; i++) {
                            printf("%02x", encrypted[i]);
                        }
                        printf("\n");
                        break;
                    }

                    default:
                        printf("Invalid encryption/encoding choice.\n");
                        break;
                }
                break;
            }

            case 3: { // Decrypt a message
                printf("Enter the message to decrypt/decode: ");
                fgets(input, sizeof(input), stdin);
                input[strcspn(input, "\n")] = '\0';

                printf("Select decryption/decoding format:\n");
                printf("1. Base64\n");
                printf("2. Hex\n");
                printf("3. AES-256-CBC\n");
                printf("4. AES-128-CBC\n");
                printf("Enter your choice: ");

                int dec_choice;
                scanf("%d", &dec_choice);
                getchar(); // Consume newline

                switch (dec_choice) {
                    case 1: { // Base64
                        decode_base64(input, output);
                        printf("Decoded (Base64): %s\n", output);
                        break;
                    }

                    case 2: { // Hex
                        unsigned char decoded[512];
                        decode_hex(input, decoded, &len);
                        printf("Decoded (Hex): %.*s\n", len, decoded);
                        break;
                    }

                    case 3: // AES-256-CBC
                    case 4: { // AES-128-CBC
                        const EVP_CIPHER *cipher = (dec_choice == 3) ? EVP_aes_256_cbc() : EVP_aes_128_cbc();

                        printf("Enter a 32-character key: ");
                        fgets(key, sizeof(key), stdin);
                        key[strcspn(key, "\n")] = '\0';

                        printf("Enter a 16-character IV: ");
                        fgets(iv, sizeof(iv), stdin);
                        iv[strcspn(iv, "\n")] = '\0';

                        unsigned char encrypted[512];
                        decode_hex(input, encrypted, &len); // Decode hex to binary
                        decrypt_message(encrypted, len, key, iv, output, cipher);
                        printf("Decrypted message: %s\n", output);
                        break;
                    }

                    default:
                        printf("Invalid decryption/decoding choice.\n");
                        break;
                }
                break;
            }

            default:
                printf("Invalid choice. Try again.\n");
                break;
        }
    }
}

// Function to attempt to crack the hash using a password file
void crack_hash(const char *target_hash, const char *password_file, const char *hash_type) {
    FILE *file = fopen(password_file, "r");
    if (!file) {
        perror("Unable to open password file");
        exit(1);
    }

    char line[256];
    unsigned char hash[EVP_MAX_MD_SIZE];
    char hex_output[65]; // Maximum for SHA256: 64 hex chars + null terminator
    int hash_len = (strcmp(hash_type, "SHA256") == 0) ? 32 :
                   (strcmp(hash_type, "SHA1") == 0) ? 20 :
                   (strcmp(hash_type, "MD5") == 0) ? 16 : 0;

    printf("Cracking the hash using hash type: %s\n", hash_type);
    printf("Live comparisons (Ctrl+C to abort):\n");

    while (fgets(line, sizeof(line), file)) {
        // Remove newline character from password
        line[strcspn(line, "\n")] = '\0';

        // Compute hash of the password
        compute_hash(line, hash, hash_type);
        hash_to_hex(hash, hex_output, hash_len);

        // Compare the computed hash with the target hash
        if (strcmp(hex_output, target_hash) == 0) {
            printf("\nPassword found: %s\n", line);
            fclose(file);
            return;
        }
    }

    printf("\nPassword not found in the list.\n");
    fclose(file);
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        interactive_mode();
        return 0;
    }

    const char *hash_file = argv[1];
    const char *password_file = argv[2];
    char target_hash[65]; // Maximum for SHA256: 64 characters + null terminator

    // Read the hash from the file
    FILE *file = fopen(hash_file, "r");
    if (!file) {
        perror("Unable to open hash file");
        return 1;
    }
    if (!fgets(target_hash, sizeof(target_hash), file)) {
        perror("Error reading hash from file");
        fclose(file);
        return 1;
    }
    fclose(file);

    target_hash[strcspn(target_hash, "\n")] = '\0';

    // Detect the hash type
    const char *hash_type = detect_hash_type(target_hash);
    printf("Detected Hash Type: %s\n", hash_type);

    if (strcmp(hash_type, "Unknown") == 0) {
        fprintf(stderr, "Unsupported or unrecognized hash type.\n");
        return 1;
    }

    printf("Target Hash: %s\n", target_hash);
    printf("Using Wordlist: %s\n", password_file);

    // Crack the hash
    crack_hash(target_hash, password_file, hash_type);

    return 0;
}
