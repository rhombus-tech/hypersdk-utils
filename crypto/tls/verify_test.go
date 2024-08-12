package tls

import (
	
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/rhombus-tech/hypersdk-utils/common/signers/memory"
	"github.com/ava-labs/hypersdk/tree/main/crypto"

	func TestVerifyCertificate(t *testing.T) {
		require := require.New(t)
	
		cert, err := Generate("my-common-name")
		require.NoError(err, "Generate")
	
		signer := memory.NewFromRuntime(cert.PrivateKey.(ed25519.PrivateKey))
		signer2 := memory.NewTestSigner("common/crypto/tls: test signer")
	
		rawCerts := cert.Certificate
		err = VerifyCertificate(rawCerts, VerifyOptions{
			CommonName: "my-common-name",
			Keys: map[signature.PublicKey]bool{
				signer.Public(): true,
			},
		})
		require.NoError(err, "VerifyCertificate")
	
		err = VerifyCertificate(rawCerts, VerifyOptions{
			CommonName:       "my-common-name",
			AllowUnknownKeys: true,
		})
		require.NoError(err, "VerifyCertificate")
	
		err = VerifyCertificate(nil, VerifyOptions{
			CommonName:         "my-common-name",
			AllowNoCertificate: true,
		})
		require.NoError(err, "VerifyCertificate")
	
		err = VerifyCertificate(rawCerts, VerifyOptions{
			CommonName: "other-common-name",
			Keys: map[signature.PublicKey]bool{
				signer.Public(): true,
			},
		})
		require.Error(err, "VerifyCertificate should fail with mismatched common name")
	
		err = VerifyCertificate(rawCerts, VerifyOptions{
			CommonName: "my-common-name",
			Keys: map[signature.PublicKey]bool{
				signer2.Public(): true,
			},
		})
		require.Error(err, "VerifyCertificate should fail with mismatched public key")
	}"
	"github.com/ava-labs/hypersdk/tree/main/crypto"
)

func TestVerifyCertificate(t *testing.T) {
	require := require.New(t)

	cert, err := Generate("my-common-name")
	require.NoError(err, "Generate")

	signer := memory.NewFromRuntime(cert.PrivateKey.(ed25519.PrivateKey))
	signer2 := memory.NewTestSigner("common/crypto/tls: test signer")

	rawCerts := cert.Certificate
	err = VerifyCertificate(rawCerts, VerifyOptions{
		CommonName: "my-common-name",
		Keys: map[signature.PublicKey]bool{
			signer.Public(): true,
		},
	})
	require.NoError(err, "VerifyCertificate")

	err = VerifyCertificate(rawCerts, VerifyOptions{
		CommonName:       "my-common-name",
		AllowUnknownKeys: true,
	})
	require.NoError(err, "VerifyCertificate")

	err = VerifyCertificate(nil, VerifyOptions{
		CommonName:         "my-common-name",
		AllowNoCertificate: true,
	})
	require.NoError(err, "VerifyCertificate")

	err = VerifyCertificate(rawCerts, VerifyOptions{
		CommonName: "other-common-name",
		Keys: map[signature.PublicKey]bool{
			signer.Public(): true,
		},
	})
	require.Error(err, "VerifyCertificate should fail with mismatched common name")

	err = VerifyCertificate(rawCerts, VerifyOptions{
		CommonName: "my-common-name",
		Keys: map[signature.PublicKey]bool{
			signer2.Public(): true,
		},
	})
	require.Error(err, "VerifyCertificate should fail with mismatched public key")
}"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/memory"
)

func TestVerifyCertificate(t *testing.T) {
	require := require.New(t)

	cert, err := Generate("my-common-name")
	require.NoError(err, "Generate")

	signer := memory.NewFromRuntime(cert.PrivateKey.(ed25519.PrivateKey))
	signer2 := memory.NewTestSigner("common/crypto/tls: test signer")

	rawCerts := cert.Certificate
	err = VerifyCertificate(rawCerts, VerifyOptions{
		CommonName: "my-common-name",
		Keys: map[signature.PublicKey]bool{
			signer.Public(): true,
		},
	})
	require.NoError(err, "VerifyCertificate")

	err = VerifyCertificate(rawCerts, VerifyOptions{
		CommonName:       "my-common-name",
		AllowUnknownKeys: true,
	})
	require.NoError(err, "VerifyCertificate")

	err = VerifyCertificate(nil, VerifyOptions{
		CommonName:         "my-common-name",
		AllowNoCertificate: true,
	})
	require.NoError(err, "VerifyCertificate")

	err = VerifyCertificate(rawCerts, VerifyOptions{
		CommonName: "other-common-name",
		Keys: map[signature.PublicKey]bool{
			signer.Public(): true,
		},
	})
	require.Error(err, "VerifyCertificate should fail with mismatched common name")

	err = VerifyCertificate(rawCerts, VerifyOptions{
		CommonName: "my-common-name",
		Keys: map[signature.PublicKey]bool{
			signer2.Public(): true,
		},
	})
	require.Error(err, "VerifyCertificate should fail with mismatched public key")
}