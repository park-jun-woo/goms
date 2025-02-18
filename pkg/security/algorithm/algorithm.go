package algorithm

import (
	"fmt"
	"time"
)

// Algorithm 인터페이스: 암호화/복호화 메서드를 정의
type Algorithm interface {
	Encrypt(payload []byte) ([]byte, error)
	Decrypt(tokenBody []byte) ([]byte, error)
}

// Secret 구조체: 개인키, 공개키, 추가 정보를 포함
type Secret struct {
	KID        uint32    `json:"kid"`
	Alg        string    `json:"alg"`
	PublicKey  string    `json:"publicKey"`
	PrivateKey string    `json:"privateKey"`
	Expire     time.Time `json:"expire"`
}

// GetAlgorithm은 alg 문자열에 따라 적절한 Algorithm 구현체를 반환합니다.
func GetAlgorithm(secret *Secret) (Algorithm, error) {
	switch secret.Alg {
	case "RSA256":
		return &RSA256{}, nil
	// 다른 알고리즘이 추가된다면 케이스를 확장합니다.
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", secret.Alg)
	}
}

func GenerateSecret(alg string, kid uint32, expire string) (*Secret, error) {
	switch alg {
	case "RSA256":
		secret, err := GenerateSecretRSA256(kid, expire)
		if err != nil {
			return nil, err
		}
		return secret, nil
	// 다른 알고리즘이 추가된다면 케이스를 확장합니다.
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", alg)
	}
}
