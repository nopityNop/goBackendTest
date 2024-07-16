package handlers

import (
	"regexp"

	"golang.org/x/crypto/bcrypt"
)

func ValidateUsername(username string) bool {
	re := regexp.MustCompile(`^[a-zA-Z0-9]{4,16}$`)
	return re.MatchString(username)
}

func ValidatePassword(password string) bool {
	re := regexp.MustCompile(`^[a-zA-Z0-9!@#$%^&*()\\\/;:]{6,}$`)
	return re.MatchString(password)
}

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}
