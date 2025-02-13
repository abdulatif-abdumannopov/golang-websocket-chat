package authorization_tools

import (
	"crypto/rand"
	"encoding/base64"
	"golang.org/x/crypto/argon2"
)

func GenerateSalt(length int) (string, error) {
	salt := make([]byte, length)

	_, err := rand.Read(salt)
	if err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(salt), nil
}

func HashPassword(password string, salt string) (string, error) {
	hash := argon2.IDKey([]byte(password), []byte(salt),
		1, 64*1024, 1, 32)
	return base64.URLEncoding.EncodeToString(append([]byte(salt), hash...)), nil
}

func VerifyPassword(password string, storedHash string, salt string) (bool, error) {
	checkHash, err := HashPassword(password, salt)

	if err != nil {
		return false, err
	}
	return checkHash == storedHash, nil
}
