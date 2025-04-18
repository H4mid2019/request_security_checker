package handlers

import (
	"encoding/json"
	"net/http"
)

type AuthResponse struct {
	Message string `json:"message"`
}

func AuthCheckHandler(w http.ResponseWriter, r *http.Request) {
	response := AuthResponse{Message: "Authentication successful"}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}