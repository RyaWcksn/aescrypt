# aescrypt

AES to Base64 Encrypt and Decrypt with key

This is my personal project to encrypt and decrypt a text using GO

# Encrypt

```bash
aescrypt -input <input.txt> -output <encrypt.txt> -key <secret.key> -encrypt=true
```

# Encrypt

```bash
aescrypt -input <encrypt.txt> -output <decrypt.txt> -key <secret.key> -decrypt=true
```

# Key generate

```bash
aescrypt -key <secret.key> -generatekey=true
```
