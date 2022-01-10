package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"
)


func GenerateRandomString(n int) (string, error) {
	const letters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-"
	ret := make([]byte, n)
	for i := 0; i < n; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		if err != nil {
			return "", err
		}
		ret[i] = letters[num.Int64()]
	}

	return string(ret), nil
}

// AES encryption requires a seed phrase to encrypt characters passed into it
func encrypt(seed string, text string)(string, error){
	

	if len(seed) < 32 {
		return "", errors.New("Error: seed phrase must be 32 byte long")
	}

	characters := []byte(text)
	key := []byte(seed)

	// generate a new aes cipher using 32byte long key
	c, err := aes.NewCipher(key)

	if err != nil {
		fmt.Println(err)
	}

	// gcm or Galois/Counter Mode, is a mode of operation
    // for symmetric key cryptographic block ciphers
	gcm, err := cipher.NewGCM(c)

	if err != nil {
		fmt.Println(err)
	}

	// creates a new byte array the size of the nonce
    // which must be passed to Seal
	nonce := make([]byte, gcm.NonceSize())

	// populates our nonce with a cryptographically secure
    // random sequence

	if _, err := io.ReadFull(rand.Reader, nonce); err != nil{
		fmt.Println(err)
	} 

	encryptedWord := gcm.Seal(nonce, nonce, characters, nil)
	// Write word into a file. The WriteFile method returns an error if unsuccessful

	// handle this error
		if err != nil {
		// print it out
		fmt.Println(err)
  		}

	return string(encryptedWord), nil
}

func decrypt(encrypted string, seed string)(string, error){

	if len(seed) < 32 {
		return "", errors.New("Error: seed phrase must be 32 byte long")
	}

	key := []byte(seed)
	
	c, err := aes.NewCipher(key)

	if err != nil {
        fmt.Println(err)
    }

	ciphertext := []byte(encrypted)
    gcm, err := cipher.NewGCM(c)
    if err != nil {
        fmt.Println(err)
    }

    nonceSize := gcm.NonceSize()
    if len(ciphertext) < nonceSize {
        fmt.Println(err)
    }

    nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
    plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
    if err != nil {
        fmt.Println(err)
    }

	return string(plaintext),nil
}

func main(){
	seed, err := GenerateRandomString(32) 
	if err != nil {
		fmt.Println(err)
	}
	encryptedWord, err := encrypt(seed, "Satoshis")

	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(encryptedWord)
	decryptedWord, err := decrypt(encryptedWord, seed)
	if err != nil {
		fmt.Println(err)
	}
	
	fmt.Println(decryptedWord)
}