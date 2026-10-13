package computer

func processIdentity(_ int32, bundle string) (string, string, error) {
	if bundle == "" {
		return "", "", fail(CodeNoApp, "CUA omitted application identity")
	}
	return bundle, "", nil
}
