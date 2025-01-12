// internal/doppler/client.go
package doppler

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	keyGenerator "github.com/the0xsec/edge-guard-keygen/internal/generator"
)

type Client struct {
	Project   string
	Config    string
	KeyPrefix string
}

type KeyMetadata struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	Active    bool      `json:"active"`
	Version   int       `json:"version"`
}

func InitClient(project, config string) *Client {
	return &Client{
		Project:   project,
		Config:    config,
		KeyPrefix: "JWT_SIGNING_KEY", // Updated to uppercase
	}
}

func (c *Client) StoreKey(keyPair *keyGenerator.KeyPair) error {
	// Create Doppler-compatible secret names
	keyName := fmt.Sprintf("%s_%s", c.KeyPrefix, keyPair.ID)

	// Store the key itself
	if err := c.setSecret(keyName, keyPair.EncodedKey); err != nil {
		return fmt.Errorf("failed to store key: %w", err)
	}

	// Store metadata
	metadata := KeyMetadata{
		ID:        keyPair.ID,
		CreatedAt: keyPair.CreatedTime,
		Active:    true,
		Version:   1,
	}

	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	metadataName := fmt.Sprintf("%s_%s_METADATA", c.KeyPrefix, keyPair.ID)
	if err := c.setSecret(metadataName, string(metadataJSON)); err != nil {
		return fmt.Errorf("failed to store metadata: %w", err)
	}

	return nil
}

func (c *Client) setSecret(name, value string) error {
	// Ensure the secret name is compliant with Doppler's naming rules
	name = strings.ToUpper(name)

	cmd := exec.Command("doppler", "secrets", "set",
		name, value,
		"--project", c.Project,
		"--config", c.Config,
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("doppler CLI error: %s: %w", string(output), err)
	}

	return nil
}

func (c *Client) VerifyKeyPlacement(keyID string) error {
	keyName := fmt.Sprintf("%s_%s", c.KeyPrefix, strings.ToUpper(keyID))

	cmd := exec.Command("doppler", "secrets", "get",
		keyName,
		"--project", c.Project,
		"--config", c.Config,
		"--plain",
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to verify key storage: %w", err)
	}

	if len(output) == 0 {
		return fmt.Errorf("key not found in Doppler")
	}

	return nil
}
