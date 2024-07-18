package handlers

import (
	"net/http"
	"testProject/database"

	"github.com/gin-gonic/gin"
)

func Register(c *gin.Context) {
	username := c.PostForm("username")
	password := c.PostForm("password")

	if !ValidateUsername(username) || !ValidatePassword(password) {
		c.HTML(http.StatusBadRequest, "register.html", gin.H{
			"error": "Invalid username or password format",
		})
		return
	}

	if IsUsernameTaken(username) {
		c.HTML(http.StatusBadRequest, "register.html", gin.H{
			"error": "Username already taken",
		})
		return
	}

	hashedPassword, err := HashPassword(password)
	if err != nil {
		c.HTML(http.StatusInternalServerError, "register.html", gin.H{
			"error": "Failed to hash password",
		})
		return
	}

	user := database.User{Username: username, Password: hashedPassword}
	result := database.DB.Create(&user)
	if result.Error != nil {
		c.HTML(http.StatusInternalServerError, "register.html", gin.H{
			"error": "Failed to register user",
		})
		return
	}

	c.Redirect(http.StatusFound, "/login")
}
