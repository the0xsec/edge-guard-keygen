package main

import (
	"flag"
	"fmt"
	"log"

	doppler "github.com/the0xsec/edge-guard-keygen/internal/doppler"
	keyGenerator "github.com/the0xsec/edge-guard-keygen/internal/generator"
)

func main() {

	dProject := flag.String("project", "", "Doppler Project Name")
	dConfig := flag.String("config", "", "Doppler Config Name")
	flag.Parse()

	if *dProject == "" || *dConfig == "" {
		log.Fatal("Doppler project or config are empty in your call")
	}

	client := doppler.InitClient(*dProject, *dConfig)

	keyPair, err := keyGenerator.GenerateKey(32)
	if err != nil {
		log.Fatalf("failed to generate key: %v", err)
	}

	if err := keyPair.Validate(); err != nil {
		log.Fatalf("Key failed to pass validation stage: %v", err)
	}

	if err := client.StoreKey(keyPair); err != nil {
		log.Fatalf("failed to store the key in Doppler: %v", err)
	}

	if err := client.VerifyKeyPlacement(keyPair.ID); err != nil {
		log.Fatalf("Failed to verify the key: %v", err)
	}

	fmt.Printf("Generated Key ID: %s\n", keyPair.ID)
	fmt.Printf("Created At: %s\n", keyPair.CreatedTime)
	fmt.Printf("Encoded Key: %s\n", keyPair.EncodedKey)
}
