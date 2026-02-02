package jwepqc

import (
	"context"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io"
	"strings"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"golang.org/x/crypto/hkdf"
)

const ()

type KEMType int

// Declare the constants using iota
const (
	UNKNOWN    KEMType = iota // 0
	MLKEM_512                 // 1
	MLKEM_768                 // 2
	MLKEM_1024                // 3
)

// configuration  for sealing data
type EncapsulateConfig struct {
	PublicKey []byte  // PEM public key in bytes
	Type      KEMType // type of KEM to use
}

type EncapsulateResponse struct {
	DerivedKey    []byte // Derived key from sharedSecret
	KEMCipherText []byte // KEM Ciphertext
	Salt          []byte // salt used in HKDF
	Alg           string
}

type DecapsulateConfig struct {
	PrivateKey    []byte  // PEM private key in bytes
	Type          KEMType // type of KEM to use
	KEMCipherText []byte  // kem ciphertext
	Salt          []byte  // salt used in HKDF
	GCPKMS        bool    // toggle if the PrivateKey is decodeable as GCPKMS URI
}

type DecapsulateResponse struct {
	DerivedKey []byte // Derived key from sharedSecret
}

// encrypts some data using PQC public key
func Encapsulate(val *EncapsulateConfig) (EncapsulateResponse, error) {
	// acquire the ML-kem public key in PEM format
	pubPEMblock, rest := pem.Decode(val.PublicKey)
	if len(rest) != 0 {
		return EncapsulateResponse{}, fmt.Errorf("jwe-pqc: error decoding provided as PEM")
	}
	var pkix pkixPubKey
	if rest, err := asn1.Unmarshal(pubPEMblock.Bytes, &pkix); err != nil {
		return EncapsulateResponse{}, fmt.Errorf("jwe-pqc: error unmarshaling public PEM to asn1: %w", err)
	} else if len(rest) != 0 {
		return EncapsulateResponse{}, fmt.Errorf("jwe-pqc: error unmarshaling publicKey PEM; rest not null")
	}

	var kemCipherText []byte
	var kemSharedSecret []byte
	var alg string

	// initialize an encapsulation key based on the type
	// then acquire the kem ciphertext and the sharedkey
	switch pkix.Algorithm.Algorithm.String() {
	case mlkem768_OID.String():
		ek, err := mlkem.NewEncapsulationKey768(pkix.PublicKey.Bytes)
		if err != nil {
			return EncapsulateResponse{}, fmt.Errorf("jwe-pqc: error creating encapsulation key %v", err)
		}
		alg = "ML-KEM-768"
		kemSharedSecret, kemCipherText = ek.Encapsulate()
	case mlkem1024_OID.String():
		ek, err := mlkem.NewEncapsulationKey1024(pkix.PublicKey.Bytes)
		if err != nil {
			return EncapsulateResponse{}, fmt.Errorf("jwe-pqc: error creating encapsulation key %v", err)
		}
		alg = "ML-KEM-1024"
		kemSharedSecret, kemCipherText = ek.Encapsulate()
	default:
		return EncapsulateResponse{}, fmt.Errorf("jwe-pqc: error unsupported algorithm %s", pkix.Algorithm.Algorithm.String())
	}

	// run a kdf on the sharedSecret
	salt := make([]byte, sha256.New().Size())
	_, err := rand.Read(salt)
	if err != nil {
		return EncapsulateResponse{}, fmt.Errorf("jwe-pqc: error generating salt %v", err)
	}

	kdf := hkdf.New(sha256.New, kemSharedSecret, salt, nil)
	derivedKey := make([]byte, 32)
	_, err = io.ReadFull(kdf, derivedKey)
	if err != nil {
		return EncapsulateResponse{}, fmt.Errorf("jwe-pqc: error deriving key %v", err)
	}

	return EncapsulateResponse{
		DerivedKey:    derivedKey,
		KEMCipherText: kemCipherText,
		Salt:          salt,
		Alg:           alg,
	}, nil
}

// encrypts some data using PQC private key
func Decapsulate(val *DecapsulateConfig) (DecapsulateResponse, error) {

	// decapsulate the sharedKey from the kemCipherText
	var sharedKey []byte
	if val.GCPKMS {
		kmsName := ""
		if strings.HasPrefix(string(val.PrivateKey), "gcpkms://") {
			kmsName = strings.TrimPrefix(string(val.PrivateKey), "gcpkms://")
		} else {
			return DecapsulateResponse{}, fmt.Errorf("jwe-pqc: unsupported kms prefix %s", string(val.PrivateKey))
		}
		ctx := context.Background()
		client, err := kms.NewKeyManagementClient(ctx)
		if err != nil {
			return DecapsulateResponse{}, fmt.Errorf("jwe-pqc: error creating GCP KMS client %v", err)
		}
		defer client.Close()

		resp, err := client.Decapsulate(ctx, &kmspb.DecapsulateRequest{
			Name:       kmsName,
			Ciphertext: val.KEMCipherText,
		})
		if err != nil {
			return DecapsulateResponse{}, fmt.Errorf("jwe-pqc: error decapsulating with KMS %v", err)
		}
		sharedKey = resp.SharedSecret

	} else {
		// extract the private ML-KEM key
		prPEMblock, rest := pem.Decode(val.PrivateKey)
		if len(rest) != 0 {
			return DecapsulateResponse{}, fmt.Errorf("jwe-pqc: error decoding PEM:")
		}

		var prkix pkixPrivKey
		if rest, err := asn1.Unmarshal(prPEMblock.Bytes, &prkix); err != nil {
			return DecapsulateResponse{}, fmt.Errorf("jwe-pqc: failed to unmarshal private key")
		} else if len(rest) != 0 {
			return DecapsulateResponse{}, fmt.Errorf("jwe-pqc: failed to decode private key PEM rest")
		}

		// now create a decapsulationKey based on the declared type
		//  then acquire the raw (decrypted) sharedKey
		switch prkix.Algorithm.Algorithm.String() {
		case mlkem768_OID.String():
			dk, err := mlkem.NewDecapsulationKey768(prkix.PrivateKey)
			if err != nil {
				return DecapsulateResponse{}, fmt.Errorf("jwe-pqc: error reading mlkem private PEM: %w", err)
			}

			sharedKey, err = dk.Decapsulate(val.KEMCipherText)
			if err != nil {
				return DecapsulateResponse{}, fmt.Errorf("jwe-pqc: error decapsulating: %w", err)
			}
		case mlkem1024_OID.String():
			dk, err := mlkem.NewDecapsulationKey1024(prkix.PrivateKey)
			if err != nil {
				return DecapsulateResponse{}, fmt.Errorf("jwe-pqc: error reading mlkem private PEM: %w", err)
			}

			sharedKey, err = dk.Decapsulate(val.KEMCipherText)
			if err != nil {
				return DecapsulateResponse{}, fmt.Errorf("jwe-pqc: error decapsulating: %w", err)
			}
		default:
			return DecapsulateResponse{}, fmt.Errorf("jwe-pqc: error unsupported algorithm %s", prkix.Algorithm.Algorithm.String())
		}

	}

	// run a kdf
	kdf := hkdf.New(sha256.New, sharedKey, val.Salt, nil)
	derivedKey := make([]byte, 32)
	_, err := io.ReadFull(kdf, derivedKey)
	if err != nil {
		return DecapsulateResponse{}, fmt.Errorf("jwe-pqc: error deriving key %v", err)
	}

	return DecapsulateResponse{
		DerivedKey: derivedKey,
	}, nil
}
