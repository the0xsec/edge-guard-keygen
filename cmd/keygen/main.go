// cmd/keygen/main.go
package main

import (
	"flag"
	"fmt"
	"log"

	doppler "github.com/the0xsec/edge-guard-keygen/internal/doppler"
	keyGenerator "github.com/the0xsec/edge-guard-keygen/internal/generator"
)

func main() {
	var (
		project = flag.String("project", "", "Doppler project name")
		config  = flag.String("config", "", "Doppler config name")
		command = flag.String("command", "generate", "Command to execute: generate, list, rotate")
		keyID   = flag.String("key-id", "", "Key ID for rotation")
	)

	flag.Parse()

	if *project == "" || *config == "" {
		log.Fatal("Doppler project and config are required")
	}

	client := doppler.InitClient(*project, *config)

	switch *command {
	case "generate":
		if err := generateKey(client); err != nil {
			log.Fatalf("Failed to generate key: %v", err)
		}

	case "list":
		if err := listKeys(client); err != nil {
			log.Fatalf("Failed to list keys: %v", err)
		}

	case "rotate":
		if *keyID == "" {
			log.Fatal("Key ID is required for rotation")
		}
		if err := rotateKey(client, *keyID); err != nil {
			log.Fatalf("Failed to rotate key: %v", err)
		}

	default:
		log.Fatalf("Unknown command: %s", *command)
	}
}

func generateKey(client *doppler.Client) error {
	keyPair, err := keyGenerator.GenerateKey(32)
	if err != nil {
		return fmt.Errorf("failed to generate key: %w", err)
	}

	if err := keyPair.Validate(); err != nil {
		return fmt.Errorf("key validation failed: %w", err)
	}

	if err := client.StoreKey(keyPair); err != nil {
		return fmt.Errorf("failed to store key: %w", err)
	}

	fmt.Printf("Successfully generated and stored key with ID: %s\n", keyPair.ID)
	return nil
}

func listKeys(client *doppler.Client) error {
	keys, err := client.ListKeys()
	if err != nil {
		return fmt.Errorf("failed to list keys: %w", err)
	}

	fmt.Println("Current Keys:")
	for _, key := range keys {
		status := "INACTIVE"
		if key.Active {
			status = "ACTIVE"
		}
		fmt.Printf("- ID: %s\n  Status: %s\n  Created: %s\n",
			key.ID,
			status,
			key.CreatedTime.Format("2006-01-02 15:04:05"),
		)
		if !key.Active {
			fmt.Printf("  Rotated: %s\n", key.RotatedTime.Format("2006-01-02 15:04:05"))
		}
		fmt.Println()
	}
	return nil
}

func rotateKey(client *doppler.Client, keyID string) error {
	if err := client.RotateKey(keyID); err != nil {
		return fmt.Errorf("failed to rotate key: %w", err)
	}

	fmt.Printf("Successfully rotated key: %s\n", keyID)
	return nil
}
