package main

import (
	"net/http"
	"testProject/database"
	"testProject/handlers"
	"testProject/middleware"

	"github.com/gin-gonic/gin"
)

func main() {

	database.LoadEnv()

	database.InitDB()

	r := gin.Default()
	r.SetTrustedProxies(nil)
	r.LoadHTMLGlob("templates/*")
	r.Static("/static", "./static")

	r.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "index.html", nil)
	})
	r.GET("/register", func(c *gin.Context) {
		c.HTML(http.StatusOK, "register.html", nil)
	})
	r.POST("/register", handlers.Register)
	r.GET("/login", func(c *gin.Context) {
		c.HTML(http.StatusOK, "login.html", nil)
	})
	r.POST("/login", handlers.Login)
	r.GET("/dashboard", middleware.AuthenticateJWT(), handlers.Dashboard)
	r.GET("/manage-account", middleware.AuthenticateJWT(), handlers.ManageAccount)
	r.GET("/logout", handlers.Logout)

	auth := r.Group("/")
	auth.Use(middleware.AuthenticateJWT())
	{
		auth.POST("/update-username", handlers.UpdateUsername)
	}

	r.Run(":8080")
}
