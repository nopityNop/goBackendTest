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
