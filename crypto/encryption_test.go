package crypto

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"testing"
)

var pk, pub = generateKeyPair(4096)
var pk2, pub2 = generateKeyPair(4096)
var password = "Password!"
var message = []byte("Hello! How are you?")
var message2 = []byte("I'm great, and yourself?")

func TestPublicKeyToPem(t *testing.T) {
	_, err := publicKeyToPem(pub)
	if err != nil {
		t.Errorf("err %s", err)

	}
}

func TestEncryptPrivateKey(t *testing.T) {
	_, err := encryptPrivateKey(pk, password)
	if err != nil {
		t.Errorf("err %s", err)

	}
}

func TestPureEncodeDecode(t *testing.T) {
	Priv, _ := rsa.GenerateKey(rand.Reader, 4096)
	pemString := exportRsaPrivateKeyAsPemStr(Priv)

	newPk, err := parseRsaPrivateKeyFromPemStr(pemString)
	if err != nil {
		t.Errorf("err %s", err)

	}

	pemString2 := exportRsaPrivateKeyAsPemStr(newPk)

	if pemString != pemString2 {
		t.Errorf("Encrypted PK is not encrypted PK")

	}
}

func TestPubEncryptDecrypt(t *testing.T) {
	pubBytes, err := publicKeyToPem(pub)
	if err != nil {
		t.Errorf("err %s", err)
	}

	newPub, err := pemToPublicKey(pubBytes)
	if err != nil {
		t.Errorf("err %s", err)
	}

	if !checkEqualPub(pub, newPub) {
		t.Errorf("public bytes/out don't match")
	}
}

func TestPubEncryptDecryptNeg(t *testing.T) {
	pubBytes, err := publicKeyToPem(pub)
	if err != nil {
		t.Errorf("err %s", err)
	}

	newPub, err := pemToPublicKey(pubBytes)
	if err != nil {
		t.Errorf("err %s", err)
	}

	if checkEqualPub(pub2, newPub) {
		t.Errorf("everything is the same for some reason")
	}
}

func TestPKThereAndBackAgain(t *testing.T) {
	encryptedPK, err := encryptPrivateKey(pk, password)
	if err != nil {
		t.Errorf("err %s", err)
	}

	newPk, err := decrpytPrivateKey(encryptedPK, password)
	if err != nil {
		t.Errorf("err %s", err)
	}

	if !checkEqualPk(pk, newPk) {
		t.Errorf("EncryptedPK is not encrypted PK")
	}
}

func TestPKThereAndBackAgainNegative(t *testing.T) {
	encryptedPK, err := encryptPrivateKey(pk, password)
	if err != nil {
		t.Errorf("err %s", err)
	}

	newPk, err := decrpytPrivateKey(encryptedPK, password)
	if err != nil {
		t.Errorf("err %s", err)
	}

	if checkEqualPk(pk2, newPk) {
		t.Errorf("Everything is the same for some reason")
	}
}

func TestSignAndVerify(t *testing.T) {
	signed, err := SignMessage(pk, message)
	if err != nil {
		t.Errorf("err %s", err)
	}

	if !verifyMessage(pub, message, signed) {
		t.Errorf("signed message not verified")
	}
}

func TestSignAndVerifyNegative(t *testing.T) {
	signed, err := SignMessage(pk, message)
	if err != nil {
		t.Errorf("err %s", err)
	}

	if verifyMessage(pub, message2, signed) {
		t.Errorf("these should not be the same")
	}

	if verifyMessage(pub2, message, signed) {
		t.Errorf("these should not be the same")
	}
}

func checkEqualPk(a, b *rsa.PrivateKey) bool {
	ma := x509.MarshalPKCS1PrivateKey(a)
	mb := x509.MarshalPKCS1PrivateKey(b)
	return bytes.Equal(ma, mb)
}

func checkEqualPub(a, b *rsa.PublicKey) bool {
	ma := x509.MarshalPKCS1PublicKey(a)
	mb := x509.MarshalPKCS1PublicKey(b)
	return bytes.Equal(ma, mb)
}
