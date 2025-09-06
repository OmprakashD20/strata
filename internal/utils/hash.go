package utils

// Checks if a string is a valid SHA-1 hash (40 hex characters)
func IsValidHash(hash string) bool {
    if len(hash) != 40 {
        return false
    }
    for _, c := range hash {
        if !((c >= '0' && c <= '9') ||
             (c >= 'a' && c <= 'f') ||
             (c >= 'A' && c <= 'F')) {
            return false
        }
    }
    return true
}

// Compares two SHA-1 hashes and returns true if they are equal
func CompareHashes(hash1, hash2 string) bool {
	if len(hash1) != len(hash2) {
		return false
	}
	
	for i := range hash1 {
		if hash1[i] != hash2[i] {
			return false
		}
	}
	
	return true
}