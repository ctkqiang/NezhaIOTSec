package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"nezha_iot_sec/pkg/model"
)

const (
	keySize    = 32
	nonceSize  = 12
	pbkdf2Iter = 600000
)

var (
	ErrDecrypt    = errors.New("vault: decryption failed")
	ErrKeySize    = errors.New("vault: key must be 32 bytes")
	ErrPassphrase = errors.New("vault: passphrase must not be empty")
)

var passphraseSalt = []byte("nezhaiot/v1/passphrase-salt")

type Vault struct {
	mu      sync.RWMutex
	aead    cipher.AEAD
	key     []byte
	entries [][]byte
}

func New(key []byte) (*Vault, error) {
	if len(key) != keySize {
		return nil, ErrKeySize
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("vault: create cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("vault: create gcm: %w", err)
	}

	owned := make([]byte, len(key))
	copy(owned, key)

	return &Vault{aead: aead, key: owned}, nil
}

func (v *Vault) Add(finding model.Finding) error {
	plain, err := json.Marshal(finding)
	if err != nil {
		return fmt.Errorf("vault: encode finding: %w", err)
	}

	sealed, err := v.Seal(plain, AAD("finding"))
	if err != nil {
		return err
	}

	v.mu.Lock()
	defer v.mu.Unlock()
	v.entries = append(v.entries, sealed)

	return nil
}

func (v *Vault) Snapshot() ([]model.Finding, error) {
	v.mu.RLock()
	sealed := make([][]byte, len(v.entries))
	for i, entry := range v.entries {
		sealed[i] = append([]byte(nil), entry...)
	}
	v.mu.RUnlock()

	findings := make([]model.Finding, 0, len(sealed))

	for _, entry := range sealed {
		plain, err := v.Open(entry, AAD("finding"))
		if err != nil {
			return nil, err
		}

		var finding model.Finding
		if err := json.Unmarshal(plain, &finding); err != nil {
			return nil, fmt.Errorf("vault: decode finding: %w", err)
		}

		findings = append(findings, finding)
	}

	return findings, nil
}

func (v *Vault) Len() int {
	v.mu.RLock()
	defer v.mu.RUnlock()

	return len(v.entries)
}

func (v *Vault) Reset() {
	v.mu.Lock()
	defer v.mu.Unlock()

	for _, entry := range v.entries {
		zero(entry)
	}

	v.entries = nil
}

func (v *Vault) Close() {
	v.mu.Lock()
	defer v.mu.Unlock()

	zero(v.key)
	v.key = nil
	v.aead = nil

	for _, entry := range v.entries {
		zero(entry)
	}

	v.entries = nil
}

func (v *Vault) Seal(plain, aad []byte) ([]byte, error) {
	v.mu.RLock()
	aead := v.aead
	v.mu.RUnlock()

	if aead == nil {
		return nil, ErrDecrypt
	}

	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("vault: read nonce: %w", err)
	}

	return aead.Seal(nonce, nonce, plain, aad), nil
}

func (v *Vault) Open(sealed, aad []byte) ([]byte, error) {
	v.mu.RLock()
	aead := v.aead
	v.mu.RUnlock()

	if aead == nil {
		return nil, ErrDecrypt
	}

	if len(sealed) < nonceSize {
		return nil, ErrDecrypt
	}

	plain, err := aead.Open(nil, sealed[:nonceSize], sealed[nonceSize:], aad)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecrypt, err)
	}

	return plain, nil
}

func EphemeralKey() ([]byte, error) {
	key := make([]byte, keySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("vault: generate key: %w", err)
	}

	return key, nil
}

func PassphraseKey(passphrase string) ([]byte, error) {
	if passphrase == "" {
		return nil, ErrPassphrase
	}

	key, err := pbkdf2.Key(sha256.New, passphrase, passphraseSalt, pbkdf2Iter, keySize)
	if err != nil {
		return nil, fmt.Errorf("vault: derive key: %w", err)
	}

	return key, nil
}

func AAD(name string) []byte {
	return []byte("nezhaiot/v1/" + name)
}

func zero(data []byte) {
	for i := range data {
		data[i] = 0
	}
}
