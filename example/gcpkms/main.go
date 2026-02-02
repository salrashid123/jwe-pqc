package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/lestrrat-go/jwx/v3/jwk"
	jwepqc "github.com/salrashid123/jwe-pqc"
)

const ()

var (
	publicKey     = flag.String("publicKey", "certs/pub-ml-kem-768-kms.pem", "Public Key")
	kmsURI        = flag.String("kmsURI", "gcpkms://projects/core-eso/locations/global/keyRings/kem_kr/cryptoKeys/kem_key_1/cryptoKeyVersions/1", "PrivateKey Key on KMS")
	dataToEncrypt = flag.String("dataToEncrypt", "Lorem Ipsum", "data to encrypt")
)

func main() {
	os.Exit(run())
}

func run() int {
	flag.Parse()

	pubPEMBytes, err := os.ReadFile(*publicKey)
	if err != nil {
		fmt.Printf("error reading public key %v", err)
		return 1
	}

	k, err := jwepqc.Encapsulate(&jwepqc.EncapsulateConfig{
		PublicKey: pubPEMBytes,
		Type:      jwepqc.MLKEM_768,
	})
	if err != nil {
		fmt.Printf("error encapsulating %v", err)
		return 1
	}
	fmt.Printf("root encryption key: %s\n", hex.EncodeToString(k.DerivedKey))

	h := jwe.NewHeaders()

	h.Set("ek", base64.StdEncoding.EncodeToString(k.KEMCipherText))
	h.Set("pqc_salt", base64.StdEncoding.EncodeToString(k.Salt))
	h.Set("pqc_alg", k.Alg)

	fromRawKey, err := jwk.Import(k.DerivedKey)
	if err != nil {
		fmt.Printf("failed to acquire raw key from jwk.Key: %s", err)
		return 1
	}
	encrypted, err := jwe.Encrypt([]byte(*dataToEncrypt), jwe.WithKey(jwa.DIRECT(), fromRawKey, jwe.WithPerRecipientHeaders(h)), jwe.WithContentEncryption(jwa.A256GCM()))
	if err != nil {
		fmt.Printf("Error encrypting %v\n", err)
		return 1
	}

	jm, err := jwe.Parse(encrypted)
	if err != nil {
		fmt.Printf("Error parsing %v\n", err)
		return 1
	}
	b, err := jm.MarshalJSON()
	if err != nil {
		fmt.Printf("error marshalling json %v\n", err)
		return 1
	}
	var prettyJSON bytes.Buffer

	err = json.Indent(&prettyJSON, b, "", "  ")
	if err != nil {
		fmt.Printf("indent error: %s", err)
		return 1
	}

	fmt.Println(prettyJSON.String())

	/// now decrypt

	var kem_cipher_text []byte
	var salt []byte
	var kemtype jwepqc.KEMType
	for _, r := range jm.Recipients() {

		// read the headers and extract the sealed key and parent type
		h := r.Headers()
		var tkey string
		err := h.Get("ek", &tkey)
		if err != nil {
			fmt.Printf("error getting header  %v\n", err)
			return 1
		}

		// decode
		kem_cipher_text, err = base64.StdEncoding.DecodeString(tkey)
		if err != nil {
			fmt.Printf("error decoding key %v\n", err)
			return 1
		}

		var psalt string
		err = h.Get("pqc_salt", &psalt)
		if err != nil {
			fmt.Printf("Error getting header  %v\n", err)
			return 1
		}

		salt, err = base64.StdEncoding.DecodeString(psalt)
		if err != nil {
			fmt.Printf("error decoding salt %v\n", err)
			return 1
		}

		var pt string
		err = h.Get("pqc_alg", &pt)
		if err != nil {
			fmt.Printf("Error getting header  %v\n", err)
			return 1
		}

		switch pt {
		case "ML-KEM-768":
			kemtype = jwepqc.MLKEM_768
		case "ML-KEM-1024":
			kemtype = jwepqc.MLKEM_1024
		default:
			fmt.Printf("unknown kemtype key type  %v\n", pt)
			return 1
		}
	}

	rkey, err := jwepqc.Decapsulate(&jwepqc.DecapsulateConfig{
		PrivateKey:    []byte(*kmsURI),
		KEMCipherText: kem_cipher_text,
		Salt:          salt,
		Type:          kemtype,
		GCPKMS:        true, // <<< must be set to true
	})
	if err != nil {
		fmt.Printf("error decapsulating error: %s", err)
		return 1
	}

	fmt.Printf("decrypted root key: %s\n", hex.EncodeToString(rkey.DerivedKey))

	rRawKey, err := jwk.Import(rkey.DerivedKey)
	if err != nil {
		fmt.Printf("failed to acquire raw key from jwk.Key: %s", err)
		return 1
	}

	d, err := jwe.Decrypt(encrypted, jwe.WithKey(jwa.DIRECT(), rRawKey))
	if err != nil {
		fmt.Printf("Decrypt error %v\n", err)
		return 1
	}
	fmt.Printf("decrypted %s\n", string(d))

	return 0
}
