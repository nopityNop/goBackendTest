package handlers

import (
	"regexp"

	"testProject/database"

	"golang.org/x/crypto/bcrypt"
)

func ValidateUsername(username string) bool {
	re := regexp.MustCompile(`^[a-zA-Z0-9]{4,16}$`)
	return re.MatchString(username)
}

func IsUsernameTaken(username string) bool {
	var existingUser database.User
	result := database.DB.Where("username = ?", username).First(&existingUser)
	return result.Error == nil
}

func ValidatePassword(password string) bool {
	re := regexp.MustCompile(`^[a-zA-Z0-9!@#$%^&*()\\\/;:_\-\.,]{6,}$`)
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
