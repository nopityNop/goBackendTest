package handlers

import (
	"log"
	"net/http"

	"testProject/database"
	"testProject/middleware"

	"github.com/gin-gonic/gin"
)

func Login(c *gin.Context) {
	username := c.PostForm("username")
	password := c.PostForm("password")

	var user database.User
	result := database.DB.Where("username = ?", username).First(&user)
	if result.Error != nil || !CheckPasswordHash(password, user.Password) {
		c.HTML(http.StatusUnauthorized, "login.html", gin.H{
			"error": "Invalid username or password",
		})
		return
	}

	token, err := middleware.GenerateJWT(username)
	if err != nil {
		c.HTML(http.StatusInternalServerError, "login.html", gin.H{
			"error": "Failed to generate token",
		})
		return
	}

	log.Println("Setting token for user:", username)
	log.Println("Setting cookie on domain:", c.Request.Host)
	c.SetCookie("token", token, 3600*24, "/", c.Request.Host, false, true)
	c.Redirect(http.StatusFound, "/dashboard")
}

func Logout(c *gin.Context) {
	c.SetCookie("token", "", -1, "/", c.Request.Host, false, true)
	c.HTML(http.StatusOK, "logout.html", nil)
}

func UpdateUsername(c *gin.Context) {
	currentUsername, exists := c.Get("username")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	var req struct {
		NewUsername string `json:"new_username"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	if !ValidateUsername(req.NewUsername) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid username format"})
		return
	}

	if IsUsernameTaken(req.NewUsername) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Username already taken"})
		return
	}

	var user database.User
	result := database.DB.Where("username = ?", currentUsername).First(&user)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "User not found"})
		return
	}

	user.Username = req.NewUsername
	result = database.DB.Save(&user)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update username"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Username updated successfully"})
}
