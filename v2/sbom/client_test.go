package sbom

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetSBOM(t *testing.T) {
	mockService := NewMockGCRService("sha256-3dd2d9fea757f4ce163674a681c8795fcb64dbc29d3490f3f2f135fd52f5e242.att", "fixtures/hansel-sbom-oci")

	client := NewClient(mockService)
	ctx := context.Background()

	boms, err := client.GetSBOM(ctx, "ghcr.io/shopify/hansel", "sha256-3dd2d9fea757f4ce163674a681c8795fcb64dbc29d3490f3f2f135fd52f5e242.att")
	assert.NoError(t, err)
	isSBOM := strings.Contains(boms.Metadata.Component.Name, "ghcr.io/shopify/hansel")
	assert.True(t, isSBOM)
}

func TestGetSBOMCycloneDX(t *testing.T) {
	mockService := NewMockGCRService("sha256-2b3aea0c1886b78bbc5abe7ee54a9fbf04984fe17bb92092c10edaad6eb3f8fe.att", "fixtures/debian-bullseye")

	client := NewClient(mockService)
	ctx := context.Background()

	boms, err := client.GetSBOM(ctx, "ghcr.io/thepwagner-org", "sha256-2b3aea0c1886b78bbc5abe7ee54a9fbf04984fe17bb92092c10edaad6eb3f8fe.att")
	assert.NoError(t, err)
	isSBOM := strings.Contains(boms.Metadata.Component.Name, "ghcr.io/thepwagner-org")
	assert.True(t, isSBOM)
}
