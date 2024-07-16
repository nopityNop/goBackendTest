package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func Dashboard(c *gin.Context) {
	username := c.MustGet("username").(string)
	c.HTML(http.StatusOK, "dashboard.html", gin.H{
		"username": username,
	})
}
