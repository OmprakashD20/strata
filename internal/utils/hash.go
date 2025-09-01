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
