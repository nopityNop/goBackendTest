package main

import (
	"log"
	"net/http"
	"os"
	"regexp"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var (
	db           *gorm.DB
	jwtSecretKey = []byte("your_secret_key")
	err          error
)

// User model
type User struct {
	gorm.Model
	Username string `gorm:"unique"`
	Password string
}

// JWT Claims
type Claims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

// Initialize database connection
func initDB() {
	dsn := "host=" + os.Getenv("DB_HOST") +
		" user=" + os.Getenv("DB_USER") +
		" password=" + os.Getenv("DB_PASSWORD") +
		" dbname=" + os.Getenv("DB_NAME") +
		" port=" + os.Getenv("DB_PORT") +
		" sslmode=disable TimeZone=Asia/Shanghai"

	db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatal("Failed to connect to database: ", err)
	}

	err = db.AutoMigrate(&User{})
	if err != nil {
		log.Fatal("Failed to migrate database: ", err)
	}
}

// Load environment variables
func loadEnv() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}
}

// Validate username
func validateUsername(username string) bool {
	re := regexp.MustCompile("^[a-zA-Z0-9]{4,16}$")
	return re.MatchString(username)
}

// Validate password
func validatePassword(password string) bool {
	re := regexp.MustCompile("^[a-zA-Z0-9!@#$%^&*()\\\\/;:]{6,}$")
	return re.MatchString(password)
}

// Hash password
func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

// Check hashed password
func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// Generate JWT token
func generateJWT(username string) (string, error) {
	expirationTime := time.Now().Add(24 * time.Hour)
	claims := &Claims{
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtSecretKey)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

// Middleware to authenticate JWT
func authenticateJWT() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString, err := c.Cookie("token")
		if err != nil {
			log.Println("No token found in cookies")
			c.Redirect(http.StatusFound, "/login")
			c.Abort()
			return
		}

		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtSecretKey, nil
		})
		if err != nil || !token.Valid {
			log.Println("Invalid token:", err)
			c.Redirect(http.StatusFound, "/login")
			c.Abort()
			return
		}

		log.Println("Token is valid for user:", claims.Username)
		c.Set("username", claims.Username)
		c.Next()
	}
}

// Register route handler
func register(c *gin.Context) {
	username := c.PostForm("username")
	password := c.PostForm("password")

	var usernameError, passwordError string

	if !validateUsername(username) {
		usernameError = "Invalid username. It should be 4-16 characters long and contain only alphanumeric characters."
	}

	if !validatePassword(password) {
		passwordError = "Invalid password. It should be alphanumeric and can contain symbols !@#$%^&*()\\/;: with a minimum length of 6 characters."
	}

	if usernameError != "" || passwordError != "" {
		c.HTML(http.StatusBadRequest, "register.html", gin.H{
			"usernameError": usernameError,
			"passwordError": passwordError,
		})
		return
	}

	hashedPassword, _ := hashPassword(password)
	user := User{Username: username, Password: hashedPassword}
	result := db.Create(&user)
	if result.Error != nil {
		c.HTML(http.StatusInternalServerError, "register.html", gin.H{
			"usernameError": "Username already exists",
		})
		return
	}
	c.Redirect(http.StatusFound, "/")
}

// Login route handler
func login(c *gin.Context) {
	username := c.PostForm("username")
	password := c.PostForm("password")

	var usernameError, passwordError string

	if !validateUsername(username) {
		usernameError = "Invalid username."
	}

	if !validatePassword(password) {
		passwordError = "Invalid password."
	}

	if usernameError != "" || passwordError != "" {
		c.HTML(http.StatusBadRequest, "login.html", gin.H{
			"usernameError": usernameError,
			"passwordError": passwordError,
		})
		return
	}

	var user User
	result := db.Where("username = ?", username).First(&user)
	if result.Error != nil || !checkPasswordHash(password, user.Password) {
		c.HTML(http.StatusUnauthorized, "login.html", gin.H{
			"usernameError": "Invalid username or password",
		})
		return
	}

	token, err := generateJWT(username)
	if err != nil {
		c.HTML(http.StatusInternalServerError, "login.html", gin.H{
			"usernameError": "Failed to generate token",
		})
		return
	}

	log.Println("Setting token for user:", username)
	log.Println("Setting cookie on domain:", c.Request.Host)
	c.SetCookie("token", token, 3600*24, "/", c.Request.Host, false, true)
	c.Redirect(http.StatusFound, "/dashboard")
}

// Logout route handler
func logout(c *gin.Context) {
	c.SetCookie("token", "", -1, "/", c.Request.Host, false, true)
	c.HTML(http.StatusOK, "logout.html", nil)
}

// Dashboard route handler
func dashboard(c *gin.Context) {
	username := c.MustGet("username").(string)
	c.HTML(http.StatusOK, "dashboard.html", gin.H{
		"username": username,
	})
}

func main() {
	// Load environment variables
	loadEnv()

	// Initialize database connection
	initDB()

	// Initialize Gin router
	r := gin.Default()
	r.SetTrustedProxies(nil)
	r.LoadHTMLGlob("templates/*")
	r.Static("/static", "./static")

	// Define routes
	r.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "index.html", nil)
	})
	r.GET("/register", func(c *gin.Context) {
		c.HTML(http.StatusOK, "register.html", nil)
	})
	r.POST("/register", register)
	r.GET("/login", func(c *gin.Context) {
		c.HTML(http.StatusOK, "login.html", nil)
	})
	r.POST("/login", login)
	r.GET("/dashboard", authenticateJWT(), dashboard)
	r.GET("/logout", logout)

	// Run the server
	r.Run(":8080")
}
