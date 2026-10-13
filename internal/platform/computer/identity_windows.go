package computer

import (
	"golang.org/x/sys/windows"
	"path/filepath"
)

func processIdentity(pid int32, bundle string) (string, string, error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return "", "", err
	}
	defer windows.CloseHandle(h)
	buf := make([]uint16, 32768)
	n := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &n); err != nil {
		return "", "", err
	}
	exe := filepath.Base(windows.UTF16ToString(buf[:n]))
	if bundle == "" {
		bundle = exe
	}
	return bundle, exe, nil
}
