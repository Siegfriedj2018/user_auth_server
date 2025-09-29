package main

import (
	// "fmt"
	"log"
	"net/http"
	"os"
	// "flag"
	// "crypto/tls"
	
	"brightlight/auth-api/handlers"
	// "brightlight/auth-api/middleware"
	// "brightlight/auth-api/models"
	"brightlight/auth-api/initializers"

	"github.com/gorilla/mux"
	_ "github.com/lib/pq"
)

func Init() {
	initializers.LoadEnvs()
	initializers.InitDB()
}

func main() {
	Init()
	defer initializers.DB.Close()

	// certFile := flag.String("certfile", "cert.pem", "certificate Pem file")
	// keyfile := flag.String("keyfile", "key.pem", "Key Pem file")
	// flag.Parse()

	router := mux.NewRouter()

	// Unprotected endpoints, Post Methods
	router.HandleFunc("/register", handlers.Register).Methods("POST")
	router.HandleFunc("/login", handlers.Login).Methods("POST")
	router.HandleFunc("/update", handlers.Update).Methods("PATCH")
	// r.HandleFunc("/verify", handlers.Verify).Method("POST")

	// Protected endpoints, These endpoints require a JWT token
	// api := router.PathPrefix("api").Subrouter()
	// api.Use(middleware.JWTMiddleware) // jwt applied here
	// api.HandleFunc("/user/<email>", initializers.GetUserByEmail(email))

	// this defines the address the server will run at and sets up tls support
	addr := "localhost:" + os.Getenv("PORT")
	if addr == "" {
		addr = "localhost:32443"
	}

	srv := &http.Server{
		Addr: addr,
		Handler: router,
	}

	
	log.Printf("Starting server at %s\n", addr)
	// this line lauches the server on tls ip:port
	log.Fatal(srv.ListenAndServe())
}