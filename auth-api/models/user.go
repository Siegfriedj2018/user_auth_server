package models

import (
	// "time"

	"github.com/golang-jwt/jwt/v5"
)

// User struct to represent a user in the system
type User struct {
	ID         int    `json:"id"`
	Firstname  string `json:"firstName"`
	Lastname   string `json:"lastName"`
	Username   string `json:"username"`
	Email      string `json:"email"`
	Accesscode string `json:"accessCode"`
	Usertype   string `json:"userType"`
	// The password should not be returned in JSON responses
	Password string `json:"-"`
}

// struct for updating the user email or password
type UserUpdate struct {
	UserToken   string `json:"token"`
	NewEmail    string `json:"email"`
	NewPassword string `json:"password"`
}

// model for how the jwt should look
type Claims struct {
	// UserID   	int    `json:"userId"`
	// Issuer    string `json:"issuer"`
	// ExpiresAt time.Time
	// IssuedAt  time.Time
	jwt.RegisteredClaims
}
