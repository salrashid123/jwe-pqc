package jwepqc

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

var ()

const (
	kmsPrivateKey = "gcpkms://projects/core-eso/locations/global/keyRings/kem_kr/cryptoKeys/kem_key_1/cryptoKeyVersions/1"
	kmsPublicKey  = "example/certs/pub-ml-kem-768-kms.pem"

	bareSeedPublicPEM768  = "example/certs/pub-ml-kem-768-bare-seed.pem"
	bareSeedPrivatePEM768 = "example/certs/bare-seed-768.pem"

	seedPrivPrivatePEM768 = "example/certs/seed-only-768.pem"
)

func TestEncryptDecrypt768(t *testing.T) {

	pubPEMBytes, err := os.ReadFile(bareSeedPublicPEM768)
	require.NoError(t, err)

	privPEMBytes, err := os.ReadFile(bareSeedPrivatePEM768)
	require.NoError(t, err)

	k, err := Encapsulate(&EncapsulateConfig{
		PublicKey: pubPEMBytes,
		Type:      MLKEM_768,
	})
	require.NoError(t, err)

	rkey, err := Decapsulate(&DecapsulateConfig{
		PrivateKey:    privPEMBytes,
		KEMCipherText: k.KEMCipherText,
		Salt:          k.Salt,
		Type:          MLKEM_768,
	})
	require.NoError(t, err)

	require.Equal(t, rkey.DerivedKey, k.DerivedKey)
}

func TestEncryptDecryptGCPKMS(t *testing.T) {

	pubPEMBytes, err := os.ReadFile(kmsPublicKey)
	require.NoError(t, err)

	saJSON := os.Getenv("CICD_SA_JSON")

	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "cert.json")

	err = os.WriteFile(filePath, []byte(saJSON), 0644)
	require.NoError(t, err)

	os.Setenv("GOOGLE_APPLICATION_CREDENTIALS", filePath)
	k, err := Encapsulate(&EncapsulateConfig{
		PublicKey: pubPEMBytes,
		Type:      MLKEM_768,
	})
	require.NoError(t, err)

	rkey, err := Decapsulate(&DecapsulateConfig{
		PrivateKey:    []byte(kmsPrivateKey),
		KEMCipherText: k.KEMCipherText,
		Salt:          k.Salt,
		Type:          MLKEM_768,
		GCPKMS:        true,
	})
	require.NoError(t, err)

	require.Equal(t, rkey.DerivedKey, k.DerivedKey)
}
