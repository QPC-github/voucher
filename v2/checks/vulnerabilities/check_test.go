package vulnerabilities

import (
	"testing"

	"github.com/docker/distribution/reference"
	sbomgcr "github.com/grafeas/voucher/v2/sbomgcr"
	"github.com/opencontainers/go-digest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHasVulnerabilities(t *testing.T) {
	mockService := sbomgcr.NewMockGCRService("sha256-551182244aa6ab6997900bc04dd4e170ef13455c068360e93fc7b149eb2bc45f.att", "../../sbomgcr/fixtures/clouddo-sbom-oci")
	mockSBOMClient := sbomgcr.NewClient(mockService)
	mockCheck := check{sbomClient: mockSBOMClient}

	img, digest := "gcr.io/shopify-codelab-and-demos/sbom-lab/apps/production/clouddo-ui@sha256:551182244aa6ab6997900bc04dd4e170ef13455c068360e93fc7b149eb2bc45f", "sha256:551182244aa6ab6997900bc04dd4e170ef13455c068360e93fc7b149eb2bc45f"
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
	mockService := sbomgcr.NewMockGCRService("sha256-551182244aa6ab6997900bc04dd4e170ef13455c068360e93fc7b149eb2bc45f.att", "../../sbomgcr/fixtures/clouddo-sbom-oci")
	mockSBOMClient := sbomgcr.NewClient(mockService)
	fakeList := []string{"CVE-2022-1337", "CVE-2022-22564"}
	mockCheck := check{sbomClient: mockSBOMClient}
	mockCheck.SetFailOnVulnerabilitiesList(fakeList)
	for _, cve := range fakeList {
		assert.Contains(t, mockCheck.failOnVulnerabilities, cve)
	}
}

func TestSetVulnerabilitiesList2(t *testing.T) {
	mockService := sbomgcr.NewMockGCRService("sha256-551182244aa6ab6997900bc04dd4e170ef13455c068360e93fc7b149eb2bc45f.att", "../../sbomgcr/fixtures/clouddo-sbom-oci")
	mockSBOMClient := sbomgcr.NewClient(mockService)
	mockCheck := check{sbomClient: mockSBOMClient}

	fakeList := []string{"CVE-2022-28893", "CVE-2022-28390"}
	img, digest := "gcr.io/shopify-codelab-and-demos/sbom-lab/apps/production/clouddo-ui@sha256:551182244aa6ab6997900bc04dd4e170ef13455c068360e93fc7b149eb2bc45f", "sha256:551182244aa6ab6997900bc04dd4e170ef13455c068360e93fc7b149eb2bc45f"
	ref := getCanonicalRef(t, img, digest)

	mockCheck.SetFailOnVulnerabilitiesList(fakeList)
	check, err := mockCheck.hasAListedVulnerability(ref)

	assert.NotEmpty(t, check, "failed check on TestSetVulnerabilitiesList2")
	require.NoError(t, err, "vulnerabilities should be found")
}

func TestSetVulnerabilitiesListNoVulns(t *testing.T) {
	mockService := sbomgcr.NewMockGCRService("sha256-551182244aa6ab6997900bc04dd4e170ef13455c068360e93fc7b149eb2bc45f.att", "../../sbomgcr/fixtures/clouddo-sbom-oci")
	mockSBOMClient := sbomgcr.NewClient(mockService)
	mockCheck := check{sbomClient: mockSBOMClient}

	fakeList := []string{}
	img, digest := "gcr.io/shopify-codelab-and-demos/sbom-lab/apps/production/clouddo-ui@sha256:551182244aa6ab6997900bc04dd4e170ef13455c068360e93fc7b149eb2bc45f", "sha256:551182244aa6ab6997900bc04dd4e170ef13455c068360e93fc7b149eb2bc45f"
	ref := getCanonicalRef(t, img, digest)

	mockCheck.SetFailOnVulnerabilitiesList(fakeList)
	check, err := mockCheck.hasAListedVulnerability(ref)

	assert.Empty(t, check, "failed check on TestSetVulnerabilitiesListNoVulns")
	require.NoError(t, err, "vulnerabilities found in TestSetVulnerabilitiesListNoVulns")
}
