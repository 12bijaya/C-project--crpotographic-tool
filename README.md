# Crypto Utility & Hash Cracker

A compact command-line utility written in C that provides hashing, encoding/decoding, AES encryption/decryption, and a simple dictionary-based hash cracking mode. The tool uses OpenSSL's EVP and BIO APIs.

---

## Features

* Hash a string (MD5, SHA1, SHA256)
* Base64 and hex encode/decode
* AES-128-CBC and AES-256-CBC encrypt/decrypt
* Dictionary-based hash cracking (file-driven)
* Interactive menu mode for one-off operations

---

## Requirements

* A Unix-like system (Linux, macOS)
* `gcc` (or other C compiler)
* OpenSSL development headers and library (libcrypto)

  * Debian/Ubuntu: `libssl-dev`
  * Fedora: `openssl-devel`
  * macOS (Homebrew): `brew install openssl`

Optional tools for preparing wordlists:

* `sed`, `tr`, `awk` (common Unix utilities)

---

## Build / Install

1. Clone or copy the source file into a directory.
2. Compile with `gcc` linking against OpenSSL's crypto library:

```sh
gcc -o crypto_tool main.c -lcrypto
```

If your system installs OpenSSL headers to a non-standard location (macOS with Homebrew), you may need:

```sh
gcc -I/usr/local/opt/openssl/include -L/usr/local/opt/openssl/lib -o crypto_tool main.c -lcrypto
```

---

## Usage

### Interactive mode

Run the program with no arguments to enter the interactive menu:

```sh
./crypto_tool
```

Follow the menu prompts to hash strings, encode/decode, or encrypt/decrypt.

### Dictionary crack mode

Provide two arguments: a file containing the target hex hash and a password/wordlist file. Supported hash lengths are automatically detected (MD5/SHA1/SHA256).

```sh
./crypto_tool target_hash.txt wordlist.txt
```

* `target_hash.txt` should contain the hex-encoded hash (one line).
* `wordlist.txt` should contain candidate passwords (one per line).

Example:

```sh
echo "5d41402abc4b2a76b9719d911017c592" > target_hash.txt  # md5("hello")
./crypto_tool target_hash.txt wordlist.txt
```

### Quick non-interactive examples

Hashing a string (internally via interactive menu): use the menu and choose the hashing option.

Encrypting (AES) notes:

* AES-256-CBC expects a 32-byte key and 16-byte IV (entered as raw text in the interactive prompt).
* AES-128-CBC expects a 16-byte key and 16-byte IV.
* The tool prints AES ciphertext as hex for copy/paste.

---

## Important Notes & Limitations

* **Key/IV lengths**: The interactive prompts expect raw-text keys of the correct length. The program does not derive keys from passphrases (no PBKDF2/scrypt/KDF). If your key is shorter/longer you must adjust it externally or modify the code to derive a key.

* **Binary safety**: Some encoding/decoding functions assume input sizes and may not be safe for arbitrary large binary blobs. Use small test vectors or extend buffers if needed.

* **Hash detection** is based solely on hex string length (32/40/64 chars). This is convenient but may mis-detect non-standard hashes.

* **Performance**: The cracker reads the wordlist line-by-line and hashes candidates sequentially — no parallelism. For large wordlists, consider `hashcat` / `john` for GPU-accelerated cracking.

---

## Security & Legal

Only use this software on hashes and data you own or are authorized to test. Unauthorized cracking, interception, or tampering with systems and data is illegal in many jurisdictions.

This tool is educational and not hardened for production use. Do not rely on it for protecting secrets.

---

## Troubleshooting

* **OpenSSL link errors**: make sure `libcrypto` is installed and visible to your compiler/linker. On macOS you might need to pass `-I` and `-L` flags pointing to Homebrew's OpenSSL as shown above.

* **AES key/IV problems**: ensure you enter keys and IVs with correct byte lengths. Use hex-to-binary conversion or modify the code to accept hex keys if you prefer.

* **Decoder outputs garbage**: when decoding hex to text, ensure the original data was text. Binary data may contain nulls and non-printable bytes.

---

## How to Improve / Contribute

* Add KDF (PBKDF2 / Argon2) to derive keys from passphrases
* Add support for additional hash algorithms (bcrypt, SHA3, etc.)
* Add multi-threaded cracking or integration with `libpthreads` for speed
* Improve buffer handling and error checking (robust input validation)

Contributions welcome — submit a pull request or open an issue describing the change.

---

## License

Include your preferred license here (e.g., MIT, Apache-2.0). Example header:

```
MIT License
(c) Your Name
```

---

If you want, I can also:

* Generate example `wordlist.txt` and `target_hash.txt` for testing
* Modify the README to include more detailed compilation flags for specific OSes
* Add a sample `Makefile` and improved key-derivation code snippet
