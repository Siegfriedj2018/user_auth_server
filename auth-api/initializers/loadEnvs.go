package initializers

import (
	"log"

	"github.com/joho/godotenv"
)

func LoadEnvs() {
	log.Printf("Creating env vars...")
	err := godotenv.Load("./initializers/.env")
	
	if err != nil {
		log.Fatal("Error loading .env file, ", err)
	}
}