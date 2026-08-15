package main

import (
	"strings"
	"testing"
)

func TestGenerateAPIKey(t *testing.T) {
	key, err := generateAPIKey()
	if err != nil {
		t.Fatalf("Erro inesperado ao gerar chave de API: %v", err)
	}

	if !strings.HasPrefix(key, "tm_key_") {
		t.Errorf("A chave gerada deveria iniciar com prefixo 'tm_key_', recebido: %s", key)
	}

	// 7 caracteres do prefixo + 64 caracteres hex (32 bytes) = 71
	if len(key) != 71 {
		t.Errorf("Tamanho esperado da chave: 71 caracteres, recebido: %d", len(key))
	}
}

func TestHashAPIKey(t *testing.T) {
	key := "tm_key_0123456789abcdef"
	hash1 := hashAPIKey(key)
	hash2 := hashAPIKey(key)

	if hash1 == "" {
		t.Fatal("Hash retornado não deveria ser vazio")
	}

	if hash1 != hash2 {
		t.Errorf("O hash da chave deve ser determinístico. hash1=%s, hash2=%s", hash1, hash2)
	}

	// SHA-256 em hex tem 64 caracteres
	if len(hash1) != 64 {
		t.Errorf("Tamanho esperado do hash: 64 caracteres, recebido: %d", len(hash1))
	}
}
