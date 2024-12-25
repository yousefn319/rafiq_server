package main

import (
  "context"
  "errors"
  "fmt"
  "fyp/jwt"
  "fyp/totp"
  "strings"

  "math/rand"
  "net/http"
  "net/mail"
  "strconv"
  "time"

  "github.com/gin-gonic/gin"
  "github.com/jackc/pgx/v5"
  "github.com/jackc/pgxutil"
  "github.com/nyaruka/phonenumbers"
  "golang.org/x/crypto/bcrypt"
)

func NormalizeEmail(email string) (string, error) {
  normalized := strings.ToLower(strings.TrimSpace(email))
  idx := strings.LastIndexByte(normalized, '@')
  normalized = strings.ReplaceAll(normalized[:idx], ".", "") + normalized[idx:] // Gmail's conventions
  address, err := mail.ParseAddress(normalized)
  return address.Address, err
}

func Signup(c *gin.Context) {
  type SignupRequest struct {
    Name        string     `db:"name" json:"name"`
    Email       string     `db:"-" json:"email"`
    Gender      *string    `db:"gender" json:"gender"`
    PhoneNumber *string    `db:"-" json:"phone_number"`
    Password    string     `db:"-" json:"password"`
    DateOfBirth *time.Time `db:"date_of_birth" json:"date_of_birth"`
  }

  var req SignupRequest
  if err := c.ShouldBindJSON(&req); err != nil {
    c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid json"})
    return
  }
  if len(req.Password) < 8 {
    c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "minimum password length is 8 characters"})
    return
  }

  email, err := NormalizeEmail(req.Email)
  if err != nil {
    c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid email address"}) // More specific?
    return
  }

  tx, err := db.Begin(context.Background())
  if err != nil {
    c.AbortWithError(http.StatusInternalServerError, ToPgError(err))
    return
  }
  defer tx.Rollback(context.Background())

  pwhash, err := bcrypt.GenerateFromPassword([]byte(req.Password), BCRYPT_COST)
  if err != nil {
    if errors.Is(err, bcrypt.ErrPasswordTooLong) {
      c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "maximum password length is 72 characters"})
    } else {
      c.AbortWithError(http.StatusInternalServerError, err)
    }
    return
  }

  values := StructToValueMap(req)
  values["email"] = email
  values["pwhash"] = pwhash
  if req.PhoneNumber != nil {
    pn, err := phonenumbers.ParseAndKeepRawInput(*req.PhoneNumber, "EG")
    if err != nil || phonenumbers.IsValidNumber(pn) {
      fmt.Println(err)
      c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid phone number"})
      return
    }
    values["phone_number"] = phonenumbers.Format(pn, phonenumbers.E164)
  }

  err = pgxutil.InsertRow(context.Background(), tx, "users", values)
  if err != nil {
    err := ToPgError(err)
    if err.Code == "23505" {
      c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "user already exists"})
    } else if err.Code == "22001" {
      c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "name field too long"})
    } else if err.Code == "22P02" {
      c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid gender"})
    } else {
      c.AbortWithError(http.StatusInternalServerError, err)
    }
    return
  }

  if err := tx.Commit(context.Background()); err != nil {
    c.AbortWithError(http.StatusInternalServerError, err)
    return
  }
  c.Status(http.StatusCreated)
}

func Login(c *gin.Context) {
  type LoginRequest struct {
    Email       *string `json:"email"`
    PhoneNumber *string `json:"phone_number"`
    Password    string  `json:"password"`
  }

  var req LoginRequest
  if err := c.ShouldBindJSON(&req); err != nil {
    c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid json"})
    return
  }

  var rows pgx.Rows
  if req.Email != nil {
    rows, _ = db.Query(context.Background(), "SELECT id, pwhash FROM users WHERE email = $1", *req.Email)
  } else if req.PhoneNumber != nil {
    rows, _ = db.Query(context.Background(), "SELECT id, pwhash FROM users WHERE phone_number = $1", *req.PhoneNumber)
  } else {
    c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "must include email or phone number"})
    return
  }

  s, err := pgx.CollectRows(rows, pgx.RowTo[struct { id int64; pwhash []byte }])
  if err != nil {
    c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "user doesn't exist"})
    return
  }
  if err := bcrypt.CompareHashAndPassword(s[0].pwhash, []byte(req.Password)); err != nil {
    c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "wrong password"})
    return
  }

  claims := SessionClaims{
    BaseClaims: BaseClaims{
      ID:        rand.Int(),
      Issuer:    "rafiq.com",
      IssuedAt:  time.Now(),
      ExpiresAt: time.Now().Add(time.Hour * 24 * 365),
    },
    UserID: s[0].id,
  }
  token, err := jwt.Create(claims, secret)
  if err != nil {
    c.AbortWithError(http.StatusInternalServerError, err)
    return
  }
  c.JSON(http.StatusOK, gin.H{"token": token})
}

func Resend(c *gin.Context) {
  type ResendRequest struct {
    Token string
  }
  var req ResendRequest
  if err := c.ShouldBindJSON(&req); err != nil {
    c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid json"})
    return
  }
  // token, err := jwt.Parse[MFAClaims](req.Token, secret)
}

func SendMFA(c *gin.Context) {
}

func ResendMFA(c *gin.Context) {
}

func VerifyMFA(c *gin.Context) {
}

func Verify(c *gin.Context) {
  type VerifyRequest struct {
    Passcode string
    Token    string
  }
  var req VerifyRequest
  if err := c.ShouldBindJSON(&req); err != nil {
    c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid json"})
    return
  }

  // token, err := jwt.Parse[MFAClaims](req.Token, secret)
  // if err != nil || !token.Claims.Verify() {
  //   c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid token"})
  //   return
  // }

  // if passcode, err := strconv.Atoi(req.Passcode); err != nil || !totp.Validate(token.Claims.Secret, time.Now(), token.Claims.Duration, passcode) {
  //   c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid passcode"})
  //   return
  // }
  // switch token.Claims.RequestType {
  // case "verification":

  // }
}
