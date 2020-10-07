// Cli tool for AES encrypting and decrypting files
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"os"
	"io"
	"io/ioutil"
	"fmt"
	"log"

	"golang.org/x/crypto/scrypt"
)

// Generate cryptographically secure salt string
// which is also easy to write down does not have to be escaped.
func generateSalt(saltLength int) string {
	saltChars := []byte{}
	for len(saltChars) < saltLength {
		candidateBytes := make([]byte, 128)
		_, randErr := rand.Read(candidateBytes)
		if randErr != nil {
			log.Panicf("Error generating salt. %v", randErr.Error())
		}
		for _, byteCanditate := range candidateBytes {
			if len(saltChars) < saltLength {
				// Numbers
				if byteCanditate > 48 && byteCanditate < 57 {
					saltChars = append(saltChars, byteCanditate)
				}
				// Capital letter
				if byteCanditate > 65 && byteCanditate < 90 {
					saltChars = append(saltChars, byteCanditate)
				}
				// Letters
				if byteCanditate > 97 && byteCanditate < 122 {
					saltChars = append(saltChars, byteCanditate)
				}
			}
		}
	}
	return string(saltChars)
}

func encrypt(filePath string, secretKey string) string {
	fileContent, err := ioutil.ReadFile(filePath)
	if err != nil {
		log.Panicf("Error reading file. %v", err.Error())
	}

	// Generate 128-bit cryptographically secure salt
	salt := generateSalt(16)

	derivedKey, err := scrypt.Key([]byte(secretKey), []byte(salt), 1<<15, 8, 1, 32)
	if err != nil {
		log.Panicf("Error generating derived key using scrypt. %v", err.Error())
	}

	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		log.Panicf("Error creating new cipher from secret key. %v", err.Error())
	}
	
	// Allocate byte slice for our cipher data
	cipherBytes := make([]byte, aes.BlockSize+len(fileContent))

	// Create a new slice for our IV (nonce)
	initializationVector := cipherBytes[:aes.BlockSize]

	// Fill IV with cryptographically secure pseudorandom numbers
	if _, err := io.ReadFull(rand.Reader, initializationVector); err != nil {
		log.Panicf("Error generating random numbers. %v", err.Error())
	}

	stream := cipher.NewCFBEncrypter(block, initializationVector)

	// XOR each byte in fileContent with a byte from the cipher's key stream
	stream.XORKeyStream(cipherBytes[aes.BlockSize:], fileContent)

	// Write encrypted fileContent to filename.encrypted
	ioutil.WriteFile(filePath + ".encrypted", cipherBytes, 0644)
	return salt
}

func decrypt(filePath string, secretKey string, salt string) {
	encryptedFileContent, err := ioutil.ReadFile(filePath)
	if err != nil {
		log.Panicf("Error reading file. %v", err.Error())
	}

	derivedKey, err := scrypt.Key([]byte(secretKey), []byte(salt), 1<<15, 8, 1, 32)
	if err != nil {
		log.Panicf("Error generating derived key using scrypt. %v", err.Error())
	}

	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		log.Panicf("Error creating AES cipher using secret key. %v", err.Error())
	}

	// Read first 16 bytes for initializationVector (nonce)
	initializationVector := encryptedFileContent[:aes.BlockSize]

	// Remove initializationVector from the encryptedFileContent
	encryptedFileContent = encryptedFileContent[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, initializationVector)

	// Decrypt encryptedFileContent
	stream.XORKeyStream(encryptedFileContent, encryptedFileContent)

	// Remove .encrypted and save decrypted file
	if filePath[len(filePath)-10:len(filePath)] == ".encrypted" {
		filePath = filePath[0:len(filePath)-10]
	}
	ioutil.WriteFile(filePath, encryptedFileContent, 0644)
}

func main() {
	if len(os.Args) >= 4 {
		switch os.Args[1] {
		case "encrypt":
			salt := encrypt(os.Args[2], os.Args[3])
			fmt.Printf("File encryption complete.\n\nIMPORTANT! Salt: %v\n\n", salt)
			fmt.Println("Make sure you keep your salt safe! It is required for decryption.\n")
			return
		case "decrypt":
			decrypt(os.Args[2], os.Args[3], os.Args[4])
			fmt.Println("File decryption complete.")
			return
		}
	}
	fmt.Println("File Encryption Tunkki v1.0")
	fmt.Println("Examples:")
	fmt.Println("crypto encrypt myfile.txt mysecretpassword")
	fmt.Println("crypto decrypt myfile.txt mysecretpassword mysalt\n")
}