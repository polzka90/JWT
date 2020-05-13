package main

import (
	"log"
	"net/http"

	"github.com/polzka90/jwt/authentication"
)

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/login", authentication.Login)
	mux.HandleFunc("/validate", authentication.ValidateToken)

	log.Println("Listen on http://localhost:8080")
	http.ListenAndServe(":8080", mux)
}
