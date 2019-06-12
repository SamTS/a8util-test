package crypto

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	a8Util "gitlab.com/autom8.network/go-a8-util"
	"golang.org/x/crypto/sha3"
	"io"
)

var pkBits = 256

// generateKeyPair generates a new key pair
func generateKeyPair(bits int) (*rsa.PrivateKey, *rsa.PublicKey) {
	privkey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		a8Util.Log.Error(err)
	}
	return privkey, &privkey.PublicKey
}

func SignMessage(pk *rsa.PrivateKey, message []byte) ([]byte, error) {
	r := rand.Reader

	hash := sha3.New256()
	hash.Write(message)
	hashedMessage := hash.Sum(nil)

	psOptions := &rsa.PSSOptions{
		SaltLength: 256,
	}

	result, err := rsa.SignPSS(r, pk, crypto.SHA3_256, hashedMessage, psOptions)
	if err != nil {
		return nil, err
	}

	return result, nil
}

func verifyMessage(pub *rsa.PublicKey, message []byte, signature []byte) bool {
	hash := sha3.New256() //hashedMessage, []byte(initialMessage))
	hash.Write(message)
	hashedMessage := hash.Sum(nil)

	psOptions := &rsa.PSSOptions{
		SaltLength: 256,
	}

	err := rsa.VerifyPSS(pub, crypto.SHA3_256, hashedMessage, signature, psOptions)
	if err != nil {
		return false
	}
	return true
}

func VerifyMessage(pubString string, message []byte, signature []byte) bool {
	pub, err := pemToPublicKey([]byte(pubString))
	if err != nil {
		return false
	}

	return verifyMessage(pub, message, signature)
}

func hashData(key string) string {
	hasher := md5.New()
	hasher.Write([]byte(key))
	return hex.EncodeToString(hasher.Sum(nil))
}

func encryptData(data []byte, password string) ([]byte, error) {
	hashedPw := hashData(password)

	block, err := aes.NewCipher([]byte(hashedPw))
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext, nil

}

func decryptData(data []byte, password string) ([]byte, error) {
	hashedPw := hashData(password)
	block, err := aes.NewCipher([]byte(hashedPw))
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// PublicKeyToBytes public key to bytes
func publicKeyToPem(pub *rsa.PublicKey) ([]byte, error) {
	//	pubASN1, err := x509.MarshalPKIXPublicKey(pub)
	pubASN1 := x509.MarshalPKCS1PublicKey(pub)

	pubBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubASN1,
	})

	return pubBytes, nil
}

// PublicKeyToBytes public key to bytes
func pemToPublicKey(pemBytes []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("no data decoded from input string")
	}

	pub, err := x509.ParsePKCS1PublicKey(block.Bytes)

	if err != nil {
		return nil, err
	}

	return pub, nil
}

func privateKeyToPem(pk *rsa.PrivateKey) ([]byte, error) {
	ASN1DER := x509.MarshalPKCS1PrivateKey(pk)

	privateBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: ASN1DER,
	})

	return privateBytes, nil
}

func PemToPrivateKey(pemPk []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemPk)
	if block == nil {
		return nil, fmt.Errorf("no data decoded from input string")
	}

	pk, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return pk, nil
}

func encryptPrivateKey(pk *rsa.PrivateKey, password string) ([]byte, error) {
	priBytes, err := privateKeyToPem(pk)
	if err != nil {
		return nil, err
	}

	encrypted, err := encryptData(priBytes, password)
	if err != nil {
		return nil, err
	}

	return encrypted, nil
}

func decrpytPrivateKey(encrpytedPK []byte, password string) (*rsa.PrivateKey, error) {
	pkBytes, err := decryptData(encrpytedPK, password)
	if err != nil {
		return nil, err
	}

	pk, err := PemToPrivateKey(pkBytes)
	if err != nil {
		return nil, err
	}

	return pk, nil
}

func exportRsaPrivateKeyAsPemStr(privkey *rsa.PrivateKey) string {
	privKeyBytes := x509.MarshalPKCS1PrivateKey(privkey)
	privKeyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: privKeyBytes,
		},
	)
	return string(privKeyPem)
}

func parseRsaPrivateKeyFromPemStr(privPEM string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(privPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing the key")
	}

	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return priv, nil
}

func CreateEncryptedPK(password string) ([]byte, []byte, error) {
	pk, pub := generateKeyPair(pkBits)

	pubBytes, err := publicKeyToPem(pub)
	if err != nil {
		return nil, nil, err
	}

	encryptedPK, err := encryptPrivateKey(pk, password)

	return encryptedPK, pubBytes, err
}

func GetPemFromEncrypted(password string, encryptedPK []byte) ([]byte, error) {
	pk, err := decrpytPrivateKey(encryptedPK, password)
	if err != nil {
		return nil, err
	}

	return privateKeyToPem(pk)
}
