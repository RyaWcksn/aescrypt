package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
)

func main() {
	var (
		inputFile   string
		keyFile     string
		outputFile  string
		encryptFlag bool
		decryptFlag bool
		generateKey bool
	)

	flag.StringVar(&inputFile, "input", "", "Input file to encrypt/decrypt")
	flag.StringVar(&keyFile, "key", "", "Key file for encryption/decryption")
	flag.StringVar(&outputFile, "output", "", "Output file")
	flag.BoolVar(&encryptFlag, "encrypt", false, "Set to true for encryption")
	flag.BoolVar(&decryptFlag, "decrypt", false, "Set to true for decryption")
	flag.BoolVar(&generateKey, "generatekey", false, "Set to true to generate a new key")
	flag.Parse()

	if generateKey {
		err := generateAESKey(keyFile)
		if err != nil {
			log.Fatal("Error generating key:", err)
			return
		}
		fmt.Println("Random AES key generated and saved to", keyFile)
		return
	}

	if encryptFlag && decryptFlag {
		fmt.Println("Please specify either -encrypt or -decrypt, not both.")
		return
	}

	if inputFile == "" || keyFile == "" || outputFile == "" {
		fmt.Println("Usage: go run main.go -input <input_file> -key <key_file> -output <output_file> -encrypt=true|false")
		return
	}

	keyData, err := ioutil.ReadFile(keyFile)
	if err != nil {
		log.Fatal("Error reading key file:", err)
		return
	}

	inputData, err := ioutil.ReadFile(inputFile)
	if err != nil {
		log.Fatal("Error reading input file:", err)
		return
	}

	if encryptFlag {
		cryptoText := encrypt(keyData, string(inputData))
		err := ioutil.WriteFile(outputFile, []byte(cryptoText), 0644)
		if err != nil {
			log.Fatal("Error writing output file:", err)
			return
		}
		fmt.Println("Encryption completed. Output written to", outputFile)
	} else if decryptFlag {
		plainText := decrypt(keyData, string(inputData))
		err := ioutil.WriteFile(outputFile, []byte(plainText), 0644)
		if err != nil {
			log.Fatal("Error writing output file:", err)
			return
		}
		fmt.Println("Decryption completed. Output written to", outputFile)
	}
}

func generateAESKey(keyFile string) error {
	key := make([]byte, 32) // AES-256 requires a 32-byte key
	_, err := rand.Read(key)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(keyFile, key, 0644)
	if err != nil {
		return err
	}

	return nil
}

// encrypt string to base64 crypto using AES
func encrypt(key []byte, text string) string {
	plaintext := []byte(text)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	return base64.URLEncoding.EncodeToString(ciphertext)
}

// decrypt from base64 to decrypted string
func decrypt(key []byte, cryptoText string) string {
	ciphertext, _ := base64.URLEncoding.DecodeString(cryptoText)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	if len(ciphertext) < aes.BlockSize {
		panic("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	return string(ciphertext)
}
