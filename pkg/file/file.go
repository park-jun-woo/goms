package file

import (
	"fmt"
	"os"

	"github.com/gofrs/flock"
)

const (
	LOCK_SH = 1 << iota // 공유락: 1
	LOCK_EX             // 배타락: 2
	LOCK_NB             // 논블로킹: 4
	LOCK_UN             // 잠금 해제: 8
)

// LockFile는 lockPath를 기준으로 락을 처리합니다.
// flags 값에 따라 아래 동작을 합니다:
// - LOCK_EX: 배타락을 획득 (LOCK_NB와 함께 사용하면 논블로킹 모드)
// - LOCK_SH: 공유락을 획득 (LOCK_NB와 함께 사용하면 논블로킹 모드)
// - LOCK_UN: 이미 획득한 락을 해제합니다.
// 주의: LOCK_UN는 다른 플래그와 함께 사용할 수 없습니다.
func LockFile(lockPath string, flags int) (*flock.Flock, error) {
	fileLock := flock.New(lockPath)

	// Unlock 요청인 경우
	if flags&LOCK_UN != 0 {
		if err := fileLock.Unlock(); err != nil {
			return nil, fmt.Errorf("failed to unlock %s: %w", lockPath, err)
		}
		return fileLock, nil
	}

	// exclusive lock
	if flags&LOCK_EX != 0 {
		if flags&LOCK_NB != 0 {
			locked, err := fileLock.TryLock()
			if err != nil {
				return nil, fmt.Errorf("failed to try exclusive lock on %s: %w", lockPath, err)
			}
			if !locked {
				return nil, fmt.Errorf("exclusive lock on %s could not be acquired in non-blocking mode", lockPath)
			}
		} else {
			if err := fileLock.Lock(); err != nil {
				return nil, fmt.Errorf("failed to acquire exclusive lock on %s: %w", lockPath, err)
			}
		}
		return fileLock, nil
	}

	// shared lock
	if flags&LOCK_SH != 0 {
		if flags&LOCK_NB != 0 {
			locked, err := fileLock.TryRLock()
			if err != nil {
				return nil, fmt.Errorf("failed to try shared lock on %s: %w", lockPath, err)
			}
			if !locked {
				return nil, fmt.Errorf("shared lock on %s could not be acquired in non-blocking mode", lockPath)
			}
		} else {
			if err := fileLock.RLock(); err != nil {
				return nil, fmt.Errorf("failed to acquire shared lock on %s: %w", lockPath, err)
			}
		}
		return fileLock, nil
	}

	return nil, fmt.Errorf("invalid lock flags provided")
}

// FileExists 함수는 주어진 경로의 파일 존재 여부를 반환합니다.
func FileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
