package vulnerabilities

import (
	"testing"

	"github.com/docker/distribution/reference"
	sbomgcr "github.com/grafeas/voucher/v2/sbom"
	"github.com/opencontainers/go-digest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHasVulnerabilities(t *testing.T) {
	mockService := sbomgcr.NewMockGCRService("sha256-3dd2d9fea757f4ce163674a681c8795fcb64dbc29d3490f3f2f135fd52f5e242.att", "../../sbomgcr/fixtures/hansel-sbom-oci")
	mockSBOMClient := sbomgcr.NewClient(mockService)
	mockCheck := check{sbomClient: mockSBOMClient}

	img, digest := "ghcr.io/shopify/hansel", "sha256:3dd2d9fea757f4ce163674a681c8795fcb64dbc29d3490f3f2f135fd52f5e242"
	ref := getCanonicalRef(t, img, digest)
	hasVuln, _ := mockCheck.hasAListedVulnerability(ref)

	assert.Empty(t, hasVuln)
}

func getCanonicalRef(t *testing.T, img string, digestStr string) reference.Canonical {
	named, err := reference.ParseNamed(img)
	require.NoError(t, err, "named")
	canonicalRef, err := reference.WithDigest(named, digest.Digest(digestStr))
	require.NoError(t, err, "canonicalRef")
	return canonicalRef
}

func TestSetVulnerabilitiesList(t *testing.T) {
	mockService := sbomgcr.NewMockGCRService("sha256-3dd2d9fea757f4ce163674a681c8795fcb64dbc29d3490f3f2f135fd52f5e242.att", "../../sbom/fixtures/hansel-sbom-oci")
	mockSBOMClient := sbomgcr.NewClient(mockService)
	fakeList := []string{"CVE-2022-27191"}
	mockCheck := check{sbomClient: mockSBOMClient}
	mockCheck.SetFailOnVulnerabilitiesList(fakeList)
	for _, cve := range fakeList {
		assert.Contains(t, mockCheck.failOnVulnerabilities, cve)
	}
}

func TestHasAListedVulnerability(t *testing.T) {
	mockService := sbomgcr.NewMockGCRService("sha256-3dd2d9fea757f4ce163674a681c8795fcb64dbc29d3490f3f2f135fd52f5e242.att", "../../sbom/fixtures/hansel-sbom-oci")
	mockSBOMClient := sbomgcr.NewClient(mockService)
	mockCheck := check{sbomClient: mockSBOMClient}

	fakeList := []string{"CVE-2022-27191"}
	img, digest := "ghcr.io/shopify/hansel", "sha256:3dd2d9fea757f4ce163674a681c8795fcb64dbc29d3490f3f2f135fd52f5e242"
	ref := getCanonicalRef(t, img, digest)

	mockCheck.SetFailOnVulnerabilitiesList(fakeList)
	check, err := mockCheck.hasAListedVulnerability(ref)

	assert.NotEmpty(t, check, "failed check on TestHasAListedVulnerability")
	require.NoError(t, err, "vulnerabilities should be found")
}

func TestHasNotAListedVulnerability(t *testing.T) {
	mockService := sbomgcr.NewMockGCRService("sha256-3dd2d9fea757f4ce163674a681c8795fcb64dbc29d3490f3f2f135fd52f5e242.att", "../../sbom/fixtures/hansel-sbom-oci")
	mockSBOMClient := sbomgcr.NewClient(mockService)
	mockCheck := check{sbomClient: mockSBOMClient}

	fakeList := []string{}
	img, digest := "ghcr.io/shopify/hansel", "sha256:3dd2d9fea757f4ce163674a681c8795fcb64dbc29d3490f3f2f135fd52f5e242"
	ref := getCanonicalRef(t, img, digest)

	mockCheck.SetFailOnVulnerabilitiesList(fakeList)
	check, err := mockCheck.hasAListedVulnerability(ref)

	assert.Empty(t, check, "failed check on TestHasNotAListedVulnerability")
	require.NoError(t, err, "vulnerabilities found in TestHasNotAListedVulnerability")
}
