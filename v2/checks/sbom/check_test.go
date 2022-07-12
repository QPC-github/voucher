package sbom

import (
	"testing"

	"github.com/docker/distribution/reference"
	sbomgcr "github.com/grafeas/voucher/v2/sbomgcr"
	"github.com/opencontainers/go-digest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHasSBOM(t *testing.T) {
	mockService := sbomgcr.NewMockGCRService("sha256-3dd2d9fea757f4ce163674a681c8795fcb64dbc29d3490f3f2f135fd52f5e242.att", "../../sbomgcr/fixtures/hansel-sbom-oci")
	mockSBOMClient := sbomgcr.NewClient(mockService)
	mockCheck := check{sbomClient: mockSBOMClient}

	img, digest := "ghcr.io/shopify/hansel", "sha256:3dd2d9fea757f4ce163674a681c8795fcb64dbc29d3490f3f2f135fd52f5e242"
	ref := getCanonicalRef(t, img, digest)
	sbom, err := mockCheck.hasSBOM(ref)

	assert.NoError(t, err, "hasSBOM")
	assert.True(t, sbom)
}

func getCanonicalRef(t *testing.T, img string, digestStr string) reference.Canonical {
	named, err := reference.ParseNamed(img)
	require.NoError(t, err, "named")
	canonicalRef, err := reference.WithDigest(named, digest.Digest(digestStr))
	require.NoError(t, err, "canonicalRef")
	return canonicalRef
}
