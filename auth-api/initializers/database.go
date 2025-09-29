package initializers

import (
	"brightlight/auth-api/models"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"os"

	"golang.org/x/crypto/bcrypt"
)

var DB *sql.DB

// InitDB initializes the database connection for the models package
func InitDB() {
	log.Printf("Starting database connection...")
	var db *sql.DB
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		log.Fatal("DATABASE_URL environment not set, check .env file...")
	}

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		log.Fatal("Error connecting/opening database: ", err)
	}
	DB = db
}

// CreateUser creates a new user in the database
func CreateUser(user *models.User) (int, error) {
	_, err := GetUserByEmail(user.Email)
	if err == nil {
		return -1, errors.New("email already exists")
	}

	// some other db error
	if err.Error() != "user not found" {
		return -1, err
	}

	// Hash the user's password before storing
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		return -1, err
	}

	// Insert the new user into the database
	sqlRes := DB.QueryRow("INSERT INTO users (username, password, firstname, lastname, email, accesscode, usertype) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id", 
										user.Username,
										string(hashedPassword),
										user.Firstname,
										user.Lastname,
										user.Email,
										user.Accesscode,
										user.Usertype,
								)
	userId := 0					
	err = sqlRes.Scan(&userId)
	return userId, err
}

// GetUserByEmail retrieves a user from the database by their email
func GetUserByEmail(email string) (*models.User, error) {
	user := &models.User{}
	row := DB.QueryRow("SELECT * FROM users WHERE email = $1", email)

	err := row.Scan(&user.ID,
									&user.Firstname,
									&user.Lastname,
									&user.Username,
									&user.Email,
									&user.Accesscode,
									&user.Usertype,
									&user.Password,
								)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.New("user not found")
		}
		return nil, err
	}

	return user, nil
}

func GetUserByID(id string) (*models.User, error) {
	user := &models.User{}
	row := DB.QueryRow("SELECT * FROM users WHERE id = $1", id)

	err := row.Scan(&user.ID,
									&user.Firstname,
									&user.Lastname,
									&user.Username,
									&user.Email,
									&user.Accesscode,
									&user.Usertype,
									&user.Password,
								)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.New("user not found")
		}
		return nil, err
	}

	return user, nil
}

// UpdateUserEmail updates the email address for a given user ID.
// It returns a success message or an error.
func UpdateUserEmail(userID int, newEmail string) (string, error) {
	// Check if the new email is already taken by *another* user
	existingUser, err := GetUserByEmail(newEmail)
	if err == nil {
		// Email found, check if it belongs to the current user or someone else
		if existingUser.ID != userID {
			return "", fmt.Errorf("email '%s' is already in use by another user", newEmail)
		}
		// If it's the same user, we can technically allow it (it's a no-op update)
		// or return success early: return "user email is already set to this value", nil

	} else if err.Error() != "user not found" {
		// An unexpected database error occurred during the email check
		log.Printf("Error checking existing email '%s' for user ID %d: %v", newEmail, userID, err)
		return "", fmt.Errorf("database error checking email: %w", err)
	}
	// If err is "user not found", the email is available - proceed.

	// Perform the update
	result, err := DB.Exec("UPDATE users SET email = $1 WHERE id = $2", newEmail, userID)
	if err != nil {
		log.Printf("Error executing email update for user ID %d: %v", userID, err)
		return "", fmt.Errorf("database error updating email: %w", err)
	}

	// Check if any row was actually updated
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		// This error is less common but possible
		log.Printf("Error getting rows affected after email update for user ID %d: %v", userID, err)
		return "", fmt.Errorf("database error checking update result: %w", err)
	}

	if rowsAffected == 0 {
		// No rows were updated, likely means the user ID didn't exist
		return "", fmt.Errorf("user with ID %d not found for update", userID)
	}

	// Return success message
	return "user updated successfully", nil
}

// UpdateUserPassword updates the password for a given user ID.
// It expects the password to be already hashed.
// It returns a success message or an error.
func UpdateUserPassword(userID int, hashedPassword string) (string, error) {
	// Perform the update
	// We trust the hashedPassword is correct as per the function contract
	// log.Println("what was passed in: ", userID, hashedPassword)
	result, err := DB.Exec("UPDATE users SET password = $1 WHERE id = $2", hashedPassword, userID)
	if err != nil {
		log.Printf("Error executing password update for user ID %d: %v", userID, err)
		return "", fmt.Errorf("database error updating password: %w", err)
	}

	// Check if any row was actually updated
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		// This error is less common but possible
		log.Printf("Error getting rows affected after password update for user ID %d: %v", userID, err)
		return "", fmt.Errorf("database error checking update result: %w", err)
	}

	if rowsAffected == 0 {
		return "", fmt.Errorf("user with ID %d not found for password update", userID)
	}

	// Return success message
	// log.Printf("Successfully updated password for user ID %d", userID)
	return "user password updated successfully", nil
}