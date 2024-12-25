package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"fyp/jwt"
	"io"
	"os"
	"strings"

	"net/http"

	"github.com/gin-contrib/gzip"
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

const BCRYPT_COST = 10

var db *pgxpool.Pool
var secret []byte

func init() {
	// https://pkg.go.dev/github.com/jackc/pgx/v5/pgxpool#ParseConfig
	// https://pkg.go.dev/github.com/jackc/pgx/v5@v5.7.1#ParseConfig
	dbConfig, err := pgxpool.ParseConfig(os.Getenv("DB_URL"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "couldn't parse db config:\n %v\n", err)
		os.Exit(1)
	}
	pool, err1 := pgxpool.NewWithConfig(context.Background(), dbConfig)
	err2 := pool.Ping(context.Background())
	if err1 != nil || err2 != nil {
		fmt.Fprintf(os.Stderr, "cnable to connect to database:\n %v\n", errors.Join(err1, err2))
		os.Exit(1)
	}
	db = pool
	fmt.Fprintln(os.Stderr, "database init complete")

	if s := os.Getenv("JWT_SECRET"); s != "" {
		secret, err = base64.StdEncoding.DecodeString(s)
		if err != nil {
			fmt.Fprintf(os.Stderr, "couldn't read token:\n %v\n", err)
			os.Exit(1)
		}
	} else {
		secret, err = MakeSecret()
		if err != nil {
			fmt.Fprintf(os.Stderr, "couldn't generate token:\n %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Token: ", base64.StdEncoding.EncodeToString(secret))
	}
}

func Authorized(c *gin.Context) {
	header := c.GetHeader("Authorization")
	if header == "" {
		c.Header("WWW-Authenticate", "Bearer")
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	auth := strings.Fields(header)
	if auth[0] != "Bearer" {
		c.Header("WWW-Authenticate", "Bearer")
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	token, err := jwt.Parse[SessionClaims](auth[1], secret)
	if !token.Claims.Verify() {
		err = errors.New("invalid token")
	}
	if err != nil {
		c.Header("WWW-Authenticate", "Bearer")
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	c.Set("user_id", token.Claims.UserID)

	c.Next()
}

func Verified(c *gin.Context) {
  if !s.email_verified && !s.phone_verified {
    c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unverified account"})
    return
  }
}

func ErrorHandler(w io.Writer) func(c *gin.Context) {
	return func(c *gin.Context) {
		c.Next()
		if len(c.Errors) != 0 {
			// HMM
			errs := make([]error, len(c.Errors))
			for i, err := range c.Errors {
				errs[i] = err.Err
			}
			joined := errors.Join(errs...)
			fmt.Fprintln(w, joined)
			c.AbortWithStatusJSON(-1, gin.H{"error": "unknown error"})
		}
	}
}

func RegisterInstructor(c *gin.Context) {
}

func RegisterStudent(c *gin.Context) {
}

func main() {
	r := gin.Default()
	r.Use(gzip.Gzip(gzip.DefaultCompression, gzip.WithExcludedExtensions([]string{".*"})))
	r.POST("/login", Login)
	r.POST("/signup", Signup)
	r.POST("/reset", ResetPassword)

	r.POST("/mfa/send", SendMFA)
	r.POST("/mfa/verify", VerifyMFA)
	r.POST("/mfa/resend", ResendMFA)

	errorHandler := ErrorHandler(gin.DefaultWriter)
	students := r.Group("/students")
	students.POST("/register", errorHandler, Authorized, RegisterStudent)

	instructors := r.Group("/instructors")
	instructors.POST("/register", errorHandler, Authorized, RegisterInstructor)

	r.Run()
}
