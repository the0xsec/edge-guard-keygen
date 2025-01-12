package main

import (
	"fmt"
	"log"

	keyGenerator "github.com/the0xsec/edge-guard-keygen/internal/generator"
)

func main() {
	keyPair, err := keyGenerator.GenerateKey(32)

	if err != nil {
		log.Fatalf("failed to generate key: %v", err)
	}

	if err := keyPair.Validate(); err != nil {
		log.Fatalf("Key failed to pass validation stage: %v", err)
	}

	fmt.Printf("Generated Key ID: %s\n", keyPair.ID)
	fmt.Printf("Created At: %s\n", keyPair.CreatedTime)
	fmt.Printf("Encoded Key: %s\n", keyPair.EncodedKey)
}
