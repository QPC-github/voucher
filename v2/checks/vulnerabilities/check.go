package vulnerabilities

import (
	"context"
	"strings"

	"github.com/grafeas/voucher/v2"
)

// check is a check that verifies if there's an sbom attached with
// the container image
type check struct {
	sbomClient voucher.SBOMClient
}

// SetSBOMClient sets the sbom / gcr client that this check will use
// for its run.
func (c *check) SetSBOMClient(sbomClient voucher.SBOMClient) {
	c.sbomClient = sbomClient
}

// hasSBOM returns true if the passed image has an SBOM attached
func (c *check) hasVulnerabilities(i voucher.ImageData) (bool, error) {
	// 1. image reference -> SBOM
	// 2. SBOM -> look at the "vulnerabilities" key and see if len is greater than zero
	// Parse the image reference
	imageName := i.Name()
	tag := getSBOMTagFromImage(i)

	sbom, err := c.sbomClient.GetSBOM(context.Background(), imageName, tag)
	if err != nil {
		// will return false for now
		// but it is not necessarily correct
		// TODO: this needs to return something.
		return true, err
	}
	vulnCount := len(*sbom.Vulnerabilities)
	return vulnCount > 0, nil
}

// GetSBOMTagFromImage returns the sbom tag from the image
func getSBOMTagFromImage(i voucher.ImageData) string {
	// Parse the image reference
	imageSHA := string(i.Digest())
	tag := strings.Replace(imageSHA, ":", "-", 1) + ".att"
	return tag
}

// check Is it true that there are no vulnerabilites found?
func (c *check) Check(ctx context.Context, i voucher.ImageData) (bool, error) {
	result, err := c.hasVulnerabilities(i)
	// do the error check first
	if err != nil {
		return false, err
	}
	// is it the case there are no vulns
	if !result {
		return true, nil
	}
	// add more
	return false, nil
}

func init() {
	voucher.RegisterCheckFactory("sbom", func() voucher.Check {
		return new(check)
	})
}
