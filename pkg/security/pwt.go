package security

// PWT 구조체: 암호화/복호화 기능에 키 매니저를 포함
type PWT struct {
	sm SecretManagerInterface
}

// Create 메서드: 주어진 설정에 맞게 payload를 암호화하여 PWT 토큰을 생성합니다.
func (pwt *PWT) Create(config uint8, payload []byte) (string, error) {

}

// Parse 메서드: token을 검증하고 해석합니다.
func (pwt *PWT) Parse(token string) ([]byte, error) {

}
