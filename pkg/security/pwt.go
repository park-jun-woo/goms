package security

// PWT 구조체: 암호화/복호화 기능에 키 매니저를 포함
type PWT struct {
	sm SecretManagerInterface
}
