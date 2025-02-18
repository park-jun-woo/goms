package security

import (
	"fmt"

	"parkjunwoo.com/goms/pkg/security/algorithm"
)

// Algorithm 인터페이스: 암호화/복호화 메서드를 정의
type AlgorithmInterface interface {
	GetAlg() string
	GetAlgIndex() uint32
	Encrypt(key string, payload []byte) ([]byte, error)
	Decrypt(key string, encrypted []byte) ([]byte, error)
}

func GetIndexByAlg(alg string) (uint32, error) {
	switch alg {
	case "RSA256":
		return 1, nil
	// 다른 알고리즘이 추가된다면 케이스를 확장합니다.
	default:
		return 0, fmt.Errorf("unsupported algorithm: %s", alg)
	}
}

func GetAlgByIndex(index uint32) (string, error) {
	switch index {
	case 1:
		return "RSA256", nil
	// 다른 알고리즘이 추가된다면 케이스를 확장합니다.
	default:
		return "", fmt.Errorf("unsupported algorithm index: %d", index)
	}
}

// GetAlgorithm은 alg 문자열에 따라 적절한 AlgorithmInterface 구현체를 반환합니다.
func GetAlgorithm(secret *Secret) (AlgorithmInterface, error) {
	switch secret.Alg {
	case "RSA256":
		return &algorithm.RSA256{}, nil
	// 다른 알고리즘이 추가된다면 케이스를 확장합니다.
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", secret.Alg)
	}
}

func GenerateSecret(alg string) (string, string, error) {
	switch alg {
	case "RSA256":
		publicKey, privateKey, err := algorithm.GenerateSecretRSA256()
		if err != nil {
			return "", "", err
		}
		return publicKey, privateKey, nil
	// 다른 알고리즘이 추가된다면 케이스를 확장합니다.
	default:
		return "", "", fmt.Errorf("unsupported algorithm: %s", alg)
	}
}
