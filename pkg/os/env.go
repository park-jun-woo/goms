package os

import "os"

// getEnv는 환경 변수 값이 없으면 기본값을 반환합니다.
func GetEnv(key, def string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return def
}
