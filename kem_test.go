package kem

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

func TestPublicPrivateEncryptDecrypt(t *testing.T) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 512) // 512 bits just for testing, using values too large will cause errors due to insufficient randomness
	b, err := genRandBytes(privateKey.Size())
  if err != nil {
    t.Error(err)
  }
	enc := publicEncrypt(privateKey.PublicKey, b)
	if bytes.Compare(b, enc) == 0 {
		t.Error("enc and b are equal when they should be differnt")
	}

	res := privateDecypt(privateKey, enc)
	if bytes.Compare(b, res) != 0 {
		t.Error("decrypted bytes not equal to original bytes")
	}
}

func TestSymetricEncrypt(t *testing.T) {
	key, _ := genRandBytes(32)
	enc, _ := symmetricEncrypt([]byte("message"), key)
	dec, err := symmetricDecrypt(enc, key)
	if err != nil {
		t.Error(err)
	}

	if bytes.Compare([]byte("message"), dec) != 0 {
		t.Error("decrypted message was not equal to original message")
	}
}

func TestEncryptDecrypt(t *testing.T) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 512)

  mySecretMessage := []byte("secret!")
  enc, err := Encrypt(privateKey.PublicKey, []byte(mySecretMessage))
  if err != nil {
    t.Error(err)
  }

  dec, err := Decrypt(privateKey, enc)
  if err != nil {
    t.Error(err)
  }

  if bytes.Compare(dec, mySecretMessage) != 0 {
    t.Error("decryption did not produce the same input text")
  }
}
