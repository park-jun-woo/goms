package algorithm

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

type RSA256 struct {
}

func (rsa256 *RSA256) GetAlg() string {
	return "RSA256"
}

func (rsa256 *RSA256) GetAlgIndex() uint32 {
	return 1
}

// Encrypt 메서드: RSA-OAEP를 사용하여 payload를 암호화합니다.
func (rsa256 *RSA256) Encrypt(key string, payload []byte) ([]byte, error) {
	// 공개키 체크
	if key == "" {
		return nil, errors.New("public key is empty")
	}

	// PEM 디코딩: 공개키 PEM 블록 추출
	block, _ := pem.Decode([]byte(key))
	if block == nil {
		return nil, errors.New("failed to decode PEM block containing public key")
	}

	// 공개키 파싱 (PKIX 형식으로 인코딩된 경우)
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	// RSA 공개키 타입 변환
	pub, ok := pubInterface.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not RSA public key")
	}

	// RSA-OAEP 암호화 (SHA-256 해시 사용)
	hash := sha256.New()
	encrypted, err := rsa.EncryptOAEP(hash, rand.Reader, pub, payload, nil)
	if err != nil {
		return nil, err
	}

	return encrypted, nil
}

// Decrypt 메서드: RSA-OAEP를 사용하여 encrypted를 복호화합니다.
func (rsa256 *RSA256) Decrypt(key string, encrypted []byte) ([]byte, error) {
	// 개인키 체크
	if key == "" {
		return nil, errors.New("private key is empty")
	}

	// PEM 디코딩: 개인키 PEM 블록 추출
	block, _ := pem.Decode([]byte(key))
	if block == nil {
		return nil, errors.New("failed to decode PEM block containing private key")
	}

	// 먼저 PKCS#1 형식으로 개인키 파싱 시도
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		// PKCS#1 파싱에 실패하면 PKCS#8 형식으로 파싱 시도
		key, err2 := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err2 != nil {
			return nil, errors.New("failed to parse private key")
		}
		var ok bool
		priv, ok = key.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("not RSA private key")
		}
	}

	// RSA-OAEP 복호화 (SHA-256 해시 사용)
	hash := sha256.New()
	decrypted, err := rsa.DecryptOAEP(hash, rand.Reader, priv, encrypted, nil)
	if err != nil {
		return nil, err
	}

	return decrypted, nil
}

// RSA256 키 생성
func GenerateSecretRSA256() (string, string, error) {
	// RSA 개인키 생성
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", err
	}

	// 개인키를 PKCS#1 DER 형식으로 인코딩 후 PEM 블록으로 변환
	privDER := x509.MarshalPKCS1PrivateKey(privKey)
	privBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privDER,
	}
	privPEM := pem.EncodeToMemory(privBlock)

	// 공개키를 PKIX (X.509) DER 형식으로 인코딩 후 PEM 블록으로 변환
	pubDER, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return "", "", err
	}
	pubBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubDER,
	}
	pubPEM := pem.EncodeToMemory(pubBlock)

	// PEM 문자열 반환
	return string(pubPEM), string(privPEM), nil
}
