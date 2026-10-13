package computer

import (
	"fmt"
	"os"
	"path/filepath"
)

func processIdentity(pid int32, bundle string) (string, string, error) {
	path, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return "", "", err
	}
	exe := filepath.Base(path)
	if bundle == "" {
		bundle = exe
	}
	return bundle, exe, nil
}
