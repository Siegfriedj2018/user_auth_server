package utils

import (
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	"brightlight/auth-api/models"

	"github.com/golang-jwt/jwt/v5"
)

// Generate a new JWT token for the given email
func GenerateJWT(userId int) (string, error) {
	expirationTime := time.Now().Add(time.Duration(GetJwtExpiration()) * time.Hour)

	// Create the token Claims
	claims := &jwt.RegisteredClaims{
		Subject: strconv.Itoa(userId),
		Issuer: "auth.brightlight-capstone.com",
		ExpiresAt: jwt.NewNumericDate(expirationTime),
		IssuedAt: jwt.NewNumericDate(time.Now()),
	}
	
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	// Sign the token with the secret key
	tokenString, err := token.SignedString([]byte(os.Getenv("JWT_SECRET")))
	if err != nil {
		return "Failed to sign token: ", err
	}

	return tokenString, nil
}

// This gets the expiration from the .env file for the JWT
func GetJwtExpiration() int {
	expiration, err := parseInt(os.Getenv("JWT_EXPIRATION"))
	if err != nil {
		return 24
	}

	return expiration
}

// helper function to parse integers
func parseInt(value string) (int, error) {
	if value == "" {
		return 0, fmt.Errorf("empty value")
	}
	var result int
	_, err := fmt.Sscan(value, &result)
	return result, err
}

func DecodeVerifyJWT(tokenString string) (*models.Claims, error) {
	tokenClaims := &models.Claims{}

	verifiedToken, err := jwt.ParseWithClaims(tokenString, tokenClaims, func(token *jwt.Token) (interface{}, error) {
		// Check the signing method (`alg` in the header)
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		
		// Return the secret key used for signing (must be []byte for HMAC)
		return []byte(os.Getenv("JWT_SECRET")), nil
	})

	// Error handling here but not sure if frontend has support
	if err != nil {
		log.Println(fmt.Errorf("some errr happened: %w", err))
		return nil, err
	}

	// Token is verified
	if !verifiedToken.Valid {
		log.Println("Token is invalid")
		return nil, errors.New("token is invalid")
	}

	// Token is Volid
	return tokenClaims, nil
}