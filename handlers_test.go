package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHealthHandler(t *testing.T) {
	app := &App{}

	req, err := http.NewRequest("GET", "/health", nil)
	if err != nil {
		t.Fatalf("Erro ao criar requisição de teste: %v", err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(app.healthHandler)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Status esperado %d, recebido %d", http.StatusOK, rr.Code)
	}

	var response map[string]string
	if err := json.NewDecoder(rr.Body).Decode(&response); err != nil {
		t.Fatalf("Erro ao decodificar JSON de resposta: %v", err)
	}

	if response["status"] != "ok" {
		t.Errorf("Resposta esperada status='ok', recebido '%s'", response["status"])
	}
}

func TestMasterKeyAuthMiddleware(t *testing.T) {
	app := &App{MasterKey: "test-secret-master-key"}

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("authorized"))
	})

	protectedHandler := app.masterKeyAuthMiddleware(nextHandler)

	// Caso 1: Sem header ou chave inválida -> 403 Forbidden
	reqForbidden, _ := http.NewRequest("POST", "/keys", nil)
	reqForbidden.Header.Set("Authorization", "Bearer invalid-key")
	rrForbidden := httptest.NewRecorder()
	protectedHandler.ServeHTTP(rrForbidden, reqForbidden)

	if rrForbidden.Code != http.StatusForbidden {
		t.Errorf("Status esperado para chave inválida: %d, recebido: %d", http.StatusForbidden, rrForbidden.Code)
	}

	// Caso 2: Chave correta -> 200 OK
	reqOK, _ := http.NewRequest("POST", "/keys", nil)
	reqOK.Header.Set("Authorization", "Bearer test-secret-master-key")
	rrOK := httptest.NewRecorder()
	protectedHandler.ServeHTTP(rrOK, reqOK)

	if rrOK.Code != http.StatusOK {
		t.Errorf("Status esperado para chave correta: %d, recebido: %d", http.StatusOK, rrOK.Code)
	}
}
