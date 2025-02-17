package file

import (
	"fmt"

	"github.com/gofrs/flock"
)

// LockFile 락 파일 경로(lockPath)를 기반으로 파일 잠금을 시도합니다.
// blocking이 true이면 락을 획득할 때까지 대기하고,
// blocking이 false이면 non-blocking 방식으로 락을 시도합니다.
func LockFile(lockPath string, blocking bool) (*flock.Flock, error) {
	fileLock := flock.New(lockPath)
	if blocking {
		if err := fileLock.Lock(); err != nil {
			return nil, fmt.Errorf("failed to acquire blocking lock on %s: %w", lockPath, err)
		}
	} else {
		locked, err := fileLock.TryLock()
		if err != nil {
			return nil, fmt.Errorf("failed to try non-blocking lock on %s: %w", lockPath, err)
		}
		if !locked {
			return nil, fmt.Errorf("non-blocking lock on %s could not be acquired", lockPath)
		}
	}
	return fileLock, nil
}

// UnlockFile 주어진 flock.Flock 객체에 대해 잠금을 해제합니다.
func UnlockFile(fileLock *flock.Flock) error {
	if err := fileLock.Unlock(); err != nil {
		return fmt.Errorf("failed to unlock: %w", err)
	}
	return nil
}
