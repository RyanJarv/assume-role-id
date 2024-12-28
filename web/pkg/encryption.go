package pkg

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

// Encrypt a plaintext string using AES-GCM
func Encrypt(plaintext string, key []byte) (string, error) {
	// Convert key and plaintext to byte slices
	// Create a new AES cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher block: %w", err)
	}

	// Create a GCM instance from the cipher block
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate a random nonce
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt the plaintext
	ciphertext := aesGCM.Seal(nil, nonce, []byte(plaintext), nil)

	// Concatenate nonce and ciphertext
	finalCiphertext := append(nonce, ciphertext...)

	// Encode the result as Base64 for easy storage/transmission
	return base64.RawURLEncoding.EncodeToString(finalCiphertext), nil
}

// Decrypt a Base64-encoded ciphertext using AES-GCM
func Decrypt(ciphertext string, key []byte) (string, error) {
	cipherBytes, err := base64.RawURLEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", fmt.Errorf("failed to decode ciphertext: %w", err)
	}

	// Create a new AES cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher block: %w", err)
	}

	// Create a GCM instance from the cipher block
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	// Extract nonce and actual ciphertext
	nonceSize := aesGCM.NonceSize()
	if len(cipherBytes) < nonceSize {
		return "", errors.New("ciphertext too short")
	}
	nonce, cipherText := cipherBytes[:nonceSize], cipherBytes[nonceSize:]

	// Decrypt the ciphertext
	plainBytes, err := aesGCM.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return "", fmt.Errorf("decryption failed: %w", err)
	}

	// Convert plaintext to string and return
	return string(plainBytes), nil
}
