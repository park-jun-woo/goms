package security

import (
	"encoding/json"
	"time"
)

type SecretManagerInterface interface {
	GetSecretLatest() (*Secret, error)
	GetSecret(kid uint32) (*Secret, error)
}

// SecretManager 구조체: 키 페어를 관리
type SecretManager struct {
	secretMap map[uint32]Secret
	host      string
	port      uint16
	sid       string
	saToken   string
}

// Secret 구조체: 개인키, 공개키, 추가 정보를 포함
type Secret struct {
	SID        string    `json:"sid"`
	KID        uint32    `json:"kid"`
	Alg        string    `json:"alg"`
	PublicKey  string    `json:"publicKey"`
	PrivateKey string    `json:"privateKey"`
	CreateTime time.Time `json:"createTime"`
	ExpireTime time.Time `json:"expireTime"`
}

// 시크릿 데이터 JSON 구조체
type SecretResponse struct {
	Secrets []Secret `json:"secrets"`
}

func requestSecret(host string, port uint16, sid string, saToken string) ([]byte, error) {
	// 시크릿 데이터 요청

	// 시크릿 데이터를 JSON 문자열로 반환
	return nil, nil
}

// NewSecretManager 함수: 주어진 경로에서 시크릿 데이터를 읽어 SecretManager를 생성
func NewSecretManager(host string, port uint16, sid string, saToken string) *SecretManager {
	// SecretManager 생성
	sm := &SecretManager{
		secretMap: make(map[uint32]Secret),
		host:      host,
		port:      port,
		sid:       sid,
		saToken:   saToken,
	}
	// https://host에서 시크릿 데이터를 요청
	secretJsonString, err := requestSecret(host, port, sid, saToken)

	if err != nil {
		return nil
	}
	// 시크릿 데이터 JSON 문자열을 파싱
	var secretData SecretResponse
	err = json.Unmarshal(secretJsonString, &secretData)
	if err != nil {
		return nil
	}
	// secretData.Secrets를 순회하며
	for _, secret := range secretData.Secrets {
		// secretMap[kid]에 저장
		sm.secretMap[secret.KID] = secret
	}
	// SecretManager를 반환
	return sm
}

// GetSecret 메서드: 주어진 kid에 해당하는 키 페어를 반환
func (sm *SecretManager) GetSecret(kid uint32) (*Secret, error) {
	secret, ok := sm.secretMap[kid]
	if !ok {
		return nil, nil
	}
	return &secret, nil
}
