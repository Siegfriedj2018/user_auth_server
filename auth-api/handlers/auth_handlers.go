package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"


	"brightlight/auth-api/initializers"
	"brightlight/auth-api/models"
	"brightlight/auth-api/utils"

	"golang.org/x/crypto/bcrypt"
)

// Register handles the user signup process
func Register(w http.ResponseWriter, r *http.Request) {
	var user models.User

	// Decodes the incoming json
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		log.Println("THere was an error decoding the user:", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"message": "User not created, Failed to decode"})
		return
	}

	// adds user to database if not already
	sqlRes, err := initializers.CreateUser(&user)
	if err != nil {
		log.Println("THere was an error creating user:", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// writes in the header and encodes json confirmation and returns the userID
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"message": "User created successfully", "userId": strconv.Itoa(sqlRes)})
}

// Login handles the user login process
func Login(w http.ResponseWriter, r *http.Request) {
	var creds 	models.User
	
	// Decodes the incoming json
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		log.Println("THere was an error decoding the user:", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Gets the user by verifying if the users exist in the database
	user, err := initializers.GetUserByEmail(creds.Email)
	if err != nil {
		log.Println("THere was an error getting the user:", err)
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Verifies if the entered password is the same by comparing hashes
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(creds.Password)); err != nil {
		log.Println("THere was an error validating the password:", err)
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Generate JWT token upon successful login
	tokenString, err := utils.GenerateJWT(user.ID)
	if err != nil {
		log.Println("error from generate: ", err)
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	// Respond with the JWT token
	json.NewEncoder(w).Encode(map[string]string{"token": tokenString})
}

func Update(w http.ResponseWriter, r *http.Request) {
	var newCreds models.UserUpdate

	if err := json.NewDecoder(r.Body).Decode(&newCreds); err != nil {
		log.Println("Error in decoding the json: ", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	claims, err := utils.DecodeVerifyJWT(newCreds.UserToken)
	if err != nil {
		log.Println("Failed to decode JWT:", err)
		http.Error(w, "Error with decoding: ", http.StatusBadRequest)
		return
	}
  
	user, err := initializers.GetUserByID(claims.Subject)
	if err != nil {
		log.Println("There was an error getting the user:", err)
		http.Error(w, "Error finding user", http.StatusUnauthorized)
		return
	}

	var updatedUser string
	if newCreds.NewEmail != "" {
		updatedUser, err = initializers.UpdateUserEmail(user.ID, newCreds.NewEmail)
		if err != nil {
			log.Println("Updating email failed:", err)
			http.Error(w, "Error updating email", http.StatusBadRequest)
			return
		}
	}

	// log.Println(newCreds)
	if newCreds.NewPassword != "" {
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newCreds.NewPassword), bcrypt.DefaultCost)
		if err != nil {
			log.Println("Failed to hash new password:", err)
			http.Error(w, "Error hashing pasword", http.StatusBadRequest)
			return
		}

		updatedUser, err = initializers.UpdateUserPassword(user.ID, string(hashedPassword))
		if err != nil {
			log.Println("Failed to update new password:", err)
			http.Error(w, "Error updating pasword", http.StatusBadRequest)
			return
		}
	}

	json.NewEncoder(w).Encode(map[string]string{"message": updatedUser})
}

// func Verify(userEmail string, userName string, token string) bool {
// 	from := mail.NewEmail("brightlight-capstone", "login@brightlight-capstone.com")
// 	subject := "Your verification code"
// 	to := mail.NewEmail(userName, userEmail)
// 	plainTextContent := "Your verification code is: " + token
// 	// htmlContent := "<strong>and easy to do anywhere, even with Go</strong>"
// 	message := mail.NewSingleEmail(from, subject, to, plainTextContent, )
// 	client := sendgrid.NewSendClient(os.Getenv("SENDGRID_API_KEY"))
// 	response, err := client.Send(message)
// 	if err != nil {
// 		log.Println(err)
// 		return false
// 	} else {
// 		log.Println(response.StatusCode)
// 		log.Println(response.Body)
// 		log.Println(response.Headers)
// 		return true
// 	}
// }

// func generateToken(length int) (string, error) {
// 	b := make([]byte, length)
// 	_, err := rand.Read(b)
// 	if err != nil {
// 			return "", err
// 	}
// 	return base64.URLEncoding.EncodeToString(b), nil
// }
