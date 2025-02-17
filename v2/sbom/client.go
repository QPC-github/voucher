package sbom

import (
	"context"
	"fmt"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/docker/distribution/reference"
	"github.com/google/go-containerregistry/pkg/name"
	goregistryv1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/google"
	voucher "github.com/grafeas/voucher/v2"
	sbompayload "github.com/grafeas/voucher/v2/sbom/payload"
)

// TODO: once https://github.com/in-toto/in-toto-golang/pull/169 is released
// we should remove this and use the in-toto-golang media type
const (
	MediaTypeDSSE = "application/vnd.dsse.envelope.v1+json"
)

// Client connects to GCR
type Client struct {
	service GCRService
}

// GetVulnerabilities returns the detected vulnerabilities for the Image described by voucher.ImageData.
func (c *Client) GetVulnerabilities(ctx context.Context, ref reference.Canonical) (vulnerabilities []voucher.Vulnerability, err error) {
	return []voucher.Vulnerability{}, nil
}

// GetSBOM gets the SBOM for the passed image.
func (c *Client) GetSBOM(ctx context.Context, imageName, tag string) (cyclonedx.BOM, error) {
	repository, err := name.NewRepository(imageName)

	if err != nil {
		return cyclonedx.BOM{}, fmt.Errorf("error getting repository name: %w", err)
	}

	tags, err := c.service.ListTags(ctx, repository)

	if err != nil {
		return cyclonedx.BOM{}, fmt.Errorf("error listing tags: %w", err)
	}

	sbomDigest, err := GetSBOMDigestWithTag(imageName, tags, tag)

	if err != nil {
		return cyclonedx.BOM{}, fmt.Errorf("error getting digest with tag: %w, are you sure the image: %s, has an sbom, check your images for one with this tag: %s?", err, imageName, tag)
	}

	sbomName := imageName + "@" + sbomDigest
	sbom, err := c.service.PullImage(sbomName)

	if err != nil {
		return cyclonedx.BOM{}, fmt.Errorf("error pulling image from gcr with crane: %w", err)
	}

	cycloneDX, err := GetSBOMFromImage(sbom)

	if err != nil {
		return cyclonedx.BOM{}, fmt.Errorf("error getting SBOM from image: %w", err)
	}

	return cycloneDX, nil
}

// GetSBOMDigestWithTag gets the sbom digest using a repo and tag.
func GetSBOMDigestWithTag(repoName string, allTags *google.Tags, tagToMatch string) (string, error) {
	for digest, manifest := range allTags.Manifests {
		for _, t := range manifest.Tags {
			if tagToMatch == t {
				return digest, nil
			}
		}
	}
	return "", fmt.Errorf("no digest found in Client.GetSBOMDigestWithTag")
}

func GetSBOMFromImage(image goregistryv1.Image) (cyclonedx.BOM, error) {
	var cyclonedxBOM cyclonedx.BOM

	layer, err := image.Layers()
	if err != nil {
		return cyclonedxBOM, fmt.Errorf("error getting layers from image %w", err)
	}

	if len(layer) == 0 {
		return cyclonedxBOM, fmt.Errorf("no layers found in image")
	}

	readCloser, _ := layer[0].Uncompressed()
	defer readCloser.Close()

	// Get the media type of the Manifest
	// TODO: This is a temporary fix until we support multiple media types
	// TODO: Eventually make the matching to be switch case based on the media type
	mediaType, err := layer[0].MediaType()
	if err != nil {
		return cyclonedxBOM, fmt.Errorf("error getting media type of manifest %w", err)
	}

	// Only supports DSSE for now
	// TODO: Add support for SBOM cyclonedx.MediaType
	if string(mediaType) != MediaTypeDSSE {
		return cyclonedxBOM, fmt.Errorf("media type is not DSSE, skipping")
	}

	envelope, err := sbompayload.GetEnvelopeFromReader(readCloser)

	if err != nil {
		return cyclonedxBOM, fmt.Errorf("error getting envelope %w", err)
	}

	// Parse the envelope and get the sbom
	err = sbompayload.GetSBOMFromEnvelope(envelope, &cyclonedxBOM)
	if err != nil {
		return cyclonedxBOM, fmt.Errorf("error getting sbom from envelope %w", err)
	}

	return cyclonedxBOM, nil
}

// NewClient creates a new sbomgcr
func NewClient(service GCRService) *Client {
	client := &Client{service: service}
	return client
}
