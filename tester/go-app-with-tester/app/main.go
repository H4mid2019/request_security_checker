package main

import (
	"log"
	"net/http"

	"github.com/yourusername/go-app-with-tester/app/handlers"
)

func main() {
	http.HandleFunc("/auth", handlers.AuthHandler)
	log.Println("Starting server on port 5000...")
	err := http.ListenAndServe(":5000", nil)
	if err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}