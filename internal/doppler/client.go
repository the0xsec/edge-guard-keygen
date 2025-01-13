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

type KeyStatus struct {
	ID                string    `json:"id"`
	CreatedTime       time.Time `json:"created_time"`
	Active            bool      `json:"active"`
	Version           int       `json:"version"`
	RotatedTime       time.Time `json:"rotated_time,omitempty"`
	RotatedFromID     string    `json:"rotated_from_id,omitempty"`
	LastUsed          time.Time `json:"last_used,omitempty"`
	MarkedForDeletion bool      `json:"marked_for_deletion,omitempty"`
}

type DopplerSecrets struct {
	Keys   map[string]interface{} `json:"keys,omitempty"`
	Values map[string]string      `json:"values,omitempty"`
}

func (c *Client) ListKeys() ([]KeyStatus, error) {
	// Using --no-file to get raw output instead of writing to file
	cmd := exec.Command("doppler", "secrets",
		"download",
		"--project", c.Project,
		"--config", c.Config,
		"--format", "json",
		"--no-file",
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to download secrets: %w: %s", err, string(output))
	}

	var secretsMap map[string]string
	if err := json.Unmarshal(output, &secretsMap); err != nil {
		return nil, fmt.Errorf("failed to parse secrets: %w", err)
	}

	var keys []KeyStatus
	for name, value := range secretsMap {

		if strings.HasPrefix(name, c.KeyPrefix) && strings.HasSuffix(name, "_METADATA") {
			var status KeyStatus
			if err := json.Unmarshal([]byte(value), &status); err != nil {
				fmt.Printf("Warning: Could not parse metadata for %s: %v\n", name, err)
				continue
			}
			keys = append(keys, status)
		}
	}

	return keys, nil
}

func (c *Client) RotateKey(oldKeyID string) error {
	newKey, err := keyGenerator.GenerateKey(32)
	if err != nil {
		return fmt.Errorf("failed to generate a new key: %w", err)
	}

	if err := newKey.Validate(); err != nil {
		return fmt.Errorf("failed to validate the new key: %w", err)
	}

	if err := c.StoreKey(newKey); err != nil {
		return fmt.Errorf("failed to store new key: %w", err)
	}

	oldMetaName := fmt.Sprintf("%s_%s_METADATA", c.KeyPrefix, oldKeyID)
	oldMetadata := KeyStatus{
		ID:            oldKeyID,
		Active:        false,
		RotatedTime:   time.Now(),
		RotatedFromID: newKey.ID,
	}

	oldMetadataJSON, err := json.Marshal(oldMetadata)
	if err != nil {
		return fmt.Errorf("failed to marshal old key metadata: %w", err)
	}

	if err := c.setSecret(oldMetaName, string(oldMetadataJSON)); err != nil {
		return fmt.Errorf("failed to update old key metadata: %w", err)
	}
	return nil
}

func InitClient(project, config string) *Client {
	return &Client{
		Project:   project,
		Config:    config,
		KeyPrefix: "JWT_SIGNING_KEY", // Doppler requires the names to be uppercase...
	}
}

func (c *Client) StoreKey(keyPair *keyGenerator.KeyPair) error {
	keyName := fmt.Sprintf("%s_%s", c.KeyPrefix, keyPair.ID)

	if err := c.setSecret(keyName, keyPair.EncodedKey); err != nil {
		return fmt.Errorf("failed to store key: %w", err)
	}

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

func (c *Client) CleanupOldKeys(maxAge time.Duration, dryRun bool) ([]string, error) {
	keys, err := c.ListKeys()
	if err != nil {
		return nil, fmt.Errorf("failed to list keys: %w", err)
	}
	var keyAge time.Duration
	var keyToDelete []string

	rightNow := time.Now()

	for _, key := range keys {
		if key.Active {
			continue
		}

		switch {
		case !key.LastUsed.IsZero():
			keyAge = rightNow.Sub(key.LastUsed)
		case !key.RotatedTime.IsZero():
			keyAge = rightNow.Sub(key.RotatedTime)
		default:
			keyAge = rightNow.Sub(key.CreatedTime)
		}

		if keyAge > maxAge {
			keyToDelete = append(keyToDelete, key.ID)
		}
	}

	if dryRun {
		return keyToDelete, nil
	}

	for _, keyID := range keyToDelete {
		keyName := fmt.Sprintf("%s_%s", c.KeyPrefix, keyID)
		metadataName := fmt.Sprintf("%s_%s_METADATA", c.KeyPrefix, keyID)

		if err := c.deleteSecret(keyName); err != nil {
			return keyToDelete, fmt.Errorf("failed to delete key %s: %w", keyID, err)
		}

		if err := c.deleteSecret(metadataName); err != nil {
			return keyToDelete, fmt.Errorf("failed to delete metadata for key %s: %w", keyID, err)
		}
	}
	return keyToDelete, nil
}

func (c *Client) deleteSecret(name string) error {
	cmd := exec.Command("doppler", "secrets", "delete",
		"delete",
		name,
		"--project", c.Project,
		"--config", c.Config,
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to delete secret %s: %w: %s", name, err, string(output))
	}
	return nil
}
