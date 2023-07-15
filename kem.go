package kem

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"log"
	"math/big"
)

// Encrypt encypts a random set of bytes the same size as the publicKey.
// The SHA256 sum of the bytes is used a symetric key in an AES-GCM scheme.
// The symmetric key is used to encrypt the rest of the message.
// The result look like the following
// [encrypted bytes][initialization vector][encrypted message][authorization tag]
//
// Encrypt returns the encrypted bytes specified by the scheme above.
func Encrypt(publicKey rsa.PublicKey, msg []byte) ([]byte, error) {
	keyLength := publicKey.Size()
	sourceBytes, err := genRandBytes(keyLength)
	if err != nil {
		return nil, err
	}
	aesKey := createSymetricKey(sourceBytes)

	encMsg, err := symmetricEncrypt(msg, aesKey[:])
	if err != nil {
		return nil, err
	}

	encSrcBytes := publicEncrypt(publicKey, sourceBytes)
	return append(encSrcBytes, encMsg...), nil
}

// Decrypt decrypts a message using an RSA private key and returns the plaintext bytes
// The encrypted message should be formatted as follows:
// [encrypted bytes of length == privateKey.Size()][initialization vector][encrypted message][authroization tag]
func Decrypt(privateKey *rsa.PrivateKey, msg []byte) ([]byte, error) {
	keyLength := privateKey.Size()
	encryptedKey, encryptedMessage := msg[:keyLength], msg[keyLength:]
	key := createSymetricKey(privateDecypt(privateKey, encryptedKey))
	return symmetricDecrypt(encryptedMessage, key[:])
}

func privateDecypt(pk *rsa.PrivateKey, cipherText []byte) []byte {
	c := new(big.Int).SetBytes(cipherText)
	plainText := c.Exp(c, pk.D, pk.N).Bytes()

	return plainText
}

func publicEncrypt(pub rsa.PublicKey, data []byte) []byte {
	encrypted := new(big.Int)
	e := big.NewInt(int64(pub.E))
	payload := new(big.Int).SetBytes(data)
	encrypted.Exp(payload, e, pub.N)
	return encrypted.Bytes()
}

func symmetricEncrypt(plaintext []byte, key []byte) ([]byte, error) {
	log.Println(len(key))
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Generate a random nonce
	iv, err := genRandBytes(12)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nil, iv, plaintext, nil)
	ciphertext = append(iv, ciphertext...)
	return ciphertext, nil
}

func symmetricDecrypt(ct []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	ivSize := gcm.NonceSize()
	if ivSize > len(ct) {
		return nil, fmt.Errorf("invalid iv + ciphertext")
	}

	return gcm.Open(nil, ct[0:ivSize], ct[ivSize:], nil)
}

func createSymetricKey(b []byte) [32]byte {
	return sha256.Sum256(b)
}

func genRandBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	n, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}
