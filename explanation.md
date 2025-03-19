### 1. **Signing a File**
The program signs a configuration file using the config manager's private key. The `sign_file` function accomplishes this:

```c
Signature sign_file(const char *file_path, const char *priv_key_path)
```

#### **Steps:**
1. Reads the file contents into memory using `read_file`.
2. Loads the private key from `private_key.pem`.
3. Creates a new OpenSSL signing context (`EVP_MD_CTX_new`).
4. Initializes the signing process using SHA-256.
5. Processes the file data for signing (`EVP_DigestSignUpdate`).
6. Computes the required signature size and allocates memory.
7. Generates the final signature (`EVP_DigestSignFinal`).
8. Cleans up memory and returns the signature.

---

### 2. **Verifying a Signature**
After signing, the program verifies the signature using a public key. The `verify_signature` function is responsible for this:

```c
int verify_signature(const char *file_path, const char *pub_key_path, const unsigned char *signature, size_t sig_len)
```

#### **Steps:**
1. Reads the file contents into memory.
2. Loads the public key from `public_key.pem`.
3. Creates a new OpenSSL verification context.
4. Initializes verification with SHA-256.
5. Processes the file data for verification (`EVP_DigestVerifyUpdate`).
6. Checks if the signature matches (`EVP_DigestVerifyFinal`).
7. Outputs whether the signature is valid or not.

---

### 3. **Integration in `main()`**
The signing and verification process is integrated into the main function:

```c
Signature sig = sign_file(output_yaml, private_key_path);
if (sig.signature) {
    printf("Configuration file signed. Signature length: %zu bytes\n", sig.length);

    if (verify_signature(output_yaml, "public_key.pem", sig.signature, sig.length) != 0) {
        printf("Failed to verify signature.\n");
    } else {
        printf("Signature verified successfully.\n");
    }
    free_signature(&sig);
}
```

#### **Flow:**
1. Calls `sign_file()` to generate a signature.
2. If signing is successful, attempts to verify the signature with `verify_signature()`.
3. Displays whether the verification was successful.
4. Cleans up memory.

---
