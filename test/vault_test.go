package test

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"nezha_iot_sec/pkg/model"
	"nezha_iot_sec/pkg/vault"
)

func sampleFinding() model.Finding {
	return model.Finding{
		IP:       "10.0.0.7",
		Port:     502,
		Service:  "Modbus-TCP",
		Severity: model.SeverityHigh,
		Detail:   "Modbus PLC Confirmed (FC 0x2B device identification)",
		MAC:      "aa:bb:cc:dd:ee:ff",
		FoundAt:  time.Now().UTC().Truncate(time.Millisecond),
	}
}

func TestVaultRoundTrip(t *testing.T) {
	t.Parallel()

	key, err := vault.EphemeralKey()
	if err != nil {
		t.Fatalf("EphemeralKey failed: %v", err)
	}

	store, err := vault.New(key)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	defer store.Close()

	original := sampleFinding()

	if err := store.Add(original); err != nil {
		t.Fatalf("Add failed: %v", err)
	}

	if store.Len() != 1 {
		t.Fatalf("Len = %d, want 1", store.Len())
	}

	snapshot, err := store.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot failed: %v", err)
	}

	if len(snapshot) != 1 {
		t.Fatalf("Snapshot returned %d findings", len(snapshot))
	}

	if snapshot[0] != original {
		t.Fatalf("round trip mismatch:\n got %+v\nwant %+v", snapshot[0], original)
	}
}

func TestVaultRejectsBadKeySizes(t *testing.T) {
	t.Parallel()

	for _, size := range []int{0, 16, 31, 33, 64} {
		if _, err := vault.New(make([]byte, size)); !errors.Is(err, vault.ErrKeySize) {
			t.Fatalf("New(%d bytes) error = %v, want ErrKeySize", size, err)
		}
	}
}

func TestVaultCiphertextIsNotPlaintext(t *testing.T) {
	t.Parallel()

	key, err := vault.EphemeralKey()
	if err != nil {
		t.Fatalf("EphemeralKey failed: %v", err)
	}

	store, err := vault.New(key)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	defer store.Close()

	sealed, err := store.Seal([]byte("mqtt-anonymous-credential"), vault.AAD("finding"))
	if err != nil {
		t.Fatalf("Seal failed: %v", err)
	}

	if bytes.Contains(sealed, []byte("mqtt-anonymous-credential")) {
		t.Fatal("ciphertext leaks the plaintext")
	}

	if len(sealed) <= 12 {
		t.Fatalf("sealed payload too short: %d", len(sealed))
	}
}

func TestVaultRejectsWrongAAD(t *testing.T) {
	t.Parallel()

	key, err := vault.EphemeralKey()
	if err != nil {
		t.Fatalf("EphemeralKey failed: %v", err)
	}

	store, err := vault.New(key)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	defer store.Close()

	sealed, err := store.Seal([]byte("payload"), vault.AAD("finding"))
	if err != nil {
		t.Fatalf("Seal failed: %v", err)
	}

	if _, err := store.Open(sealed, vault.AAD("results")); !errors.Is(err, vault.ErrDecrypt) {
		t.Fatalf("Open with a foreign aad returned %v, want ErrDecrypt", err)
	}
}

func TestVaultRejectsForeignKey(t *testing.T) {
	t.Parallel()

	firstKey, err := vault.EphemeralKey()
	if err != nil {
		t.Fatalf("EphemeralKey failed: %v", err)
	}

	secondKey, err := vault.EphemeralKey()
	if err != nil {
		t.Fatalf("EphemeralKey failed: %v", err)
	}

	first, err := vault.New(firstKey)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	defer first.Close()

	second, err := vault.New(secondKey)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	defer second.Close()

	sealed, err := first.Seal([]byte("secret"), vault.AAD("results"))
	if err != nil {
		t.Fatalf("Seal failed: %v", err)
	}

	if _, err := second.Open(sealed, vault.AAD("results")); err == nil {
		t.Fatal("a foreign key must not decrypt the payload")
	}
}

func TestVaultResetAndClose(t *testing.T) {
	t.Parallel()

	key, err := vault.EphemeralKey()
	if err != nil {
		t.Fatalf("EphemeralKey failed: %v", err)
	}

	store, err := vault.New(key)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	if err := store.Add(sampleFinding()); err != nil {
		t.Fatalf("Add failed: %v", err)
	}

	store.Reset()

	if store.Len() != 0 {
		t.Fatalf("Len after Reset = %d", store.Len())
	}

	snapshot, err := store.Snapshot()
	if err != nil || len(snapshot) != 0 {
		t.Fatalf("Snapshot after Reset = %v, %v", snapshot, err)
	}

	store.Close()

	if _, err := store.Seal([]byte("x"), vault.AAD("results")); !errors.Is(err, vault.ErrDecrypt) {
		t.Fatalf("Seal after Close = %v, want ErrDecrypt", err)
	}

	if _, err := store.Open([]byte("0123456789ab"), vault.AAD("results")); !errors.Is(err, vault.ErrDecrypt) {
		t.Fatalf("Open after Close = %v, want ErrDecrypt", err)
	}
}

func TestEphemeralKeyIsRandom(t *testing.T) {
	t.Parallel()

	first, err := vault.EphemeralKey()
	if err != nil {
		t.Fatalf("EphemeralKey failed: %v", err)
	}

	second, err := vault.EphemeralKey()
	if err != nil {
		t.Fatalf("EphemeralKey failed: %v", err)
	}

	if len(first) != 32 {
		t.Fatalf("key length = %d, want 32", len(first))
	}

	if bytes.Equal(first, second) {
		t.Fatal("two ephemeral keys are identical")
	}
}

func TestPassphraseKey(t *testing.T) {
	t.Parallel()

	first, err := vault.PassphraseKey("correct horse battery staple")
	if err != nil {
		t.Fatalf("PassphraseKey failed: %v", err)
	}

	second, err := vault.PassphraseKey("correct horse battery staple")
	if err != nil {
		t.Fatalf("PassphraseKey failed: %v", err)
	}

	if len(first) != 32 {
		t.Fatalf("key length = %d, want 32", len(first))
	}

	if !bytes.Equal(first, second) {
		t.Fatal("PassphraseKey is not deterministic")
	}

	other, err := vault.PassphraseKey("correct horse battery stapler")
	if err != nil {
		t.Fatalf("PassphraseKey failed: %v", err)
	}

	if bytes.Equal(first, other) {
		t.Fatal("different passphrases produced the same key")
	}

	if _, err := vault.PassphraseKey(""); !errors.Is(err, vault.ErrPassphrase) {
		t.Fatalf("empty passphrase = %v, want ErrPassphrase", err)
	}
}

func TestAADNamespaces(t *testing.T) {
	t.Parallel()

	if bytes.Equal(vault.AAD("finding"), vault.AAD("results")) {
		t.Fatal("aad namespaces must differ")
	}

	if !bytes.HasPrefix(vault.AAD("finding"), []byte("nezhaiot/v1/")) {
		t.Fatalf("unexpected aad prefix: %q", vault.AAD("finding"))
	}
}
