package security

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"time"

	"parkjunwoo.com/goms/pkg/file"
)

// SelfSignedCertFile는 주어진 도메인명과 조직명으로 인증서를 생성하고 파일로 저장합니다.
func SelfSignedCertFile(dnsname string, organizationName string, expire string, certPath string, keyPath string) error {
	// 파일이 존재하면 생성하지 않음
	if file.FileExists(certPath) && file.FileExists(keyPath) {
		return nil
	}
	// 인증서 생성
	cert, key, err := SelfSignedCert(dnsname, organizationName, expire)
	if err != nil {
		return err
	}
	// 파일 락
	file.LockFile(certPath, file.LOCK_EX)
	file.LockFile(keyPath, file.LOCK_EX)
	// CERT 파일로 저장
	err = os.WriteFile(certPath, []byte(cert), 0644)
	if err != nil {
		file.LockFile(certPath, file.LOCK_UN)
		file.LockFile(keyPath, file.LOCK_UN)
		return err
	}
	// KEY 파일로 저장
	err = os.WriteFile(keyPath, []byte(key), 0644)
	if err != nil {
		file.LockFile(certPath, file.LOCK_UN)
		file.LockFile(keyPath, file.LOCK_UN)
		return err
	}
	file.LockFile(certPath, file.LOCK_UN)
	file.LockFile(keyPath, file.LOCK_UN)
	// 성공
	return nil
}

// SelfSignedCert는 주어진 도메인명과 조직명으로 인증서를 생성합니다.
// string CERT, string KEY, error 반환
func SelfSignedCert(dnsname string, organizationName string, expire string) (string, string, error) {
	// 개인키 생성
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", err
	}
	// 만료 기간 설정
	expireTime, err := time.ParseDuration(expire)
	if err != nil {
		return "", "", err
	}
	//SerialNumber 랜덤생성
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", "", err
	}
	// 인증서 템플릿 생성 (localhost 용으로 설정)
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   dnsname,
			Organization: []string{organizationName},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(expireTime),

		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		// DNS를 지정
		DNSNames: []string{dnsname},
	}
	// 인증서 생성
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return "", "", err
	}
	// 인증서와 개인키를 PEM 형식으로 변환
	certString := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})
	// 개인키를 PEM 형식으로 변환
	keyString := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	})
	// 문자열로 변환하여 반환
	return string(certString), string(keyString), nil
}
