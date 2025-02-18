package security

import (
	"math"
	"time"

	"parkjunwoo.com/goms/pkg/pack"
)

type PackedWebToken struct {
	version    uint8
	kid        uint32
	alg        uint16
	payload    []byte
	createTime time.Time
	expireTime time.Time
}

// Create 메서드: 주어진 설정에 맞게 payload를 암호화하여 PWT 토큰을 생성합니다.
func CreatePWT(version uint8, kid uint32, alg string, expire string, payload []byte, secret *Secret) (string, error) {
	//유효기간
	expireDuration, err := time.ParseDuration(expire)
	if err != nil {
		return "", err
	}
	//알고리즘 기본값 RSA256이면 알고리즘을 따로 표시 안함.
	algIndex, err := GetIndexByAlg(alg)
	if err != nil {
		return "", err
	}
	if algIndex == 1 {
		version, err = pack.SetBitUint8(version, 4, 1, 1)
	} else {
		version, err = pack.SetBitUint8(version, 4, 1, 0)
	}
	if err != nil {
		return "", err
	}
	//kid저장하는데 uint32가 필요하면 version 설정값 변경
	if kid > uint32(math.MaxUint16) {
		version, err = pack.SetBitUint8(version, 5, 1, 1)
	} else {
		version, err = pack.SetBitUint8(version, 5, 1, 0)
	}
	if err != nil {
		return "", err
	}
	//PWT 생성 시간
	createTime := time.Now()
	//PWT 만료시간
	expireTime := createTime.Add(expireDuration)
	//PWT 만료시간 uint로 변환
	expireUnix := expireTime.Unix()
	//PWT 만료시간을 저장하는데 uint64가 필요하면 version 설정값 변경
	if expireUnix < 0 || expireUnix > int64(math.MaxUint32) {
		version, err = pack.SetBitUint8(version, 6, 1, 1)
	} else {
		version, err = pack.SetBitUint8(version, 6, 1, 0)
	}
	if err != nil {
		return "", err
	}
	payloadLen := len(payload)
	if payloadLen < 0 || payloadLen > int(math.MaxUint16) {
		version, err = pack.SetBitUint8(version, 7, 1, 1)
	} else {
		version, err = pack.SetBitUint8(version, 7, 1, 0)
	}
	if err != nil {
		return "", err
	}
	//
	return "", nil
}

// Parse 메서드: token을 검증하고 해석합니다.
func ParsePWT(sm SecretManagerInterface, token string) (*PackedWebToken, error) {

	return nil, nil
}
