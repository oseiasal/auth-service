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

func TestTelemetryAndChaosInjection(t *testing.T) {
	app := &App{}
	telemetry := InitTelemetry("auth-service-test")

	mux := http.NewServeMux()
	mux.HandleFunc("/health", app.healthHandler)
	mux.HandleFunc("/validate", app.validateKeyHandler)
	handler := telemetry.Middleware(mux)

	// 1. Verificar propagação W3C traceparent em /health
	reqHealth, _ := http.NewRequest("GET", "/health", nil)
	reqHealth.Header.Set("traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
	rrHealth := httptest.NewRecorder()
	handler.ServeHTTP(rrHealth, reqHealth)

	if rrHealth.Code != http.StatusOK {
		t.Fatalf("Esperado 200 em /health, recebido %d", rrHealth.Code)
	}
	if tp := rrHealth.Header().Get("traceparent"); tp == "" {
		t.Errorf("Esperado header traceparent na resposta")
	}

	// 2. Ativar Chaos Fault Injection (/chaos/fail?enable=true)
	reqChaosOn, _ := http.NewRequest("POST", "/chaos/fail?enable=true", nil)
	rrChaosOn := httptest.NewRecorder()
	handler.ServeHTTP(rrChaosOn, reqChaosOn)
	if rrChaosOn.Code != http.StatusOK {
		t.Fatalf("Esperado 200 ao ativar /chaos/fail, recebido %d", rrChaosOn.Code)
	}

	// 3. Rota de negócio (/validate) deve retornar HTTP 500 durante o Chaos
	reqVal, _ := http.NewRequest("GET", "/validate", nil)
	rrVal := httptest.NewRecorder()
	handler.ServeHTTP(rrVal, reqVal)
	if rrVal.Code != http.StatusInternalServerError {
		t.Errorf("Esperado HTTP 500 em /validate com chaos ativo, recebido %d", rrVal.Code)
	}

	// 4. Desativar Chaos (/chaos/fail?enable=false) e verificar /metrics
	reqChaosOff, _ := http.NewRequest("POST", "/chaos/fail?enable=false", nil)
	rrChaosOff := httptest.NewRecorder()
	handler.ServeHTTP(rrChaosOff, reqChaosOff)

	reqMetrics, _ := http.NewRequest("GET", "/metrics", nil)
	rrMetrics := httptest.NewRecorder()
	handler.ServeHTTP(rrMetrics, reqMetrics)
	if rrMetrics.Code != http.StatusOK {
		t.Errorf("Esperado 200 em /metrics, recebido %d", rrMetrics.Code)
	}
}

