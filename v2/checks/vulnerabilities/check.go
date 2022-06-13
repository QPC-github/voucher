package vulnerabilities

import (
	"context"
	"fmt"
	"strings"

	"github.com/grafeas/voucher/v2"
)

// check is a check that verifies if there's an sbom attached with
// the container image
type check struct {
	sbomClient            voucher.SBOMClient
	failOnVulnerabilities map[string]bool
	failOnSeverity        string
}

type SbomVulnerabilityError struct {
	VulnerabilitiesFound []string
}

func (err SbomVulnerabilityError) Error() string {
	output := fmt.Sprintf("vulnernable to %d vulnerabilities: ", len(err.VulnerabilitiesFound))

	return output + strings.Join(err.VulnerabilitiesFound, ", ")
}

func NewSbomVulnerabilityError(vulnerabilitiesFound []string) error {
	return SbomVulnerabilityError{
		VulnerabilitiesFound: vulnerabilitiesFound,
	}
}

// SetFailOnSeverity set the severity value, e.g. "critical", "high", "low"
func (c *check) SetFailOnSeverity(severity string) {
	c.failOnSeverity = strings.TrimSpace(strings.ToLower(severity))
}

// SetFailOnVulnerabilitiesList set a list of vulnerability CVEs to fail
// on, e.g.: "CVE-2019-12343", "CVE-2022-26594", ...
func (c *check) SetFailOnVulnerabilitiesList(vulnList []string) {
	c.failOnVulnerabilities = make(map[string]bool)
	for _, cve := range vulnList {
		formattedCve := strings.TrimSpace(strings.ToUpper(cve))
		c.failOnVulnerabilities[formattedCve] = true
	}
}

// SetSBOMClient sets the sbom / gcr client that this check will use
// for its run.
func (c *check) SetSBOMClient(sbomClient voucher.SBOMClient) {
	c.sbomClient = sbomClient
}

// hasAListedVulnerability returns true if the passed image has an SBOM attached
func (c *check) hasAListedVulnerability(i voucher.ImageData) ([]string, error) {
	vulnerabilitiesFound := make([]string, 0, len(c.failOnVulnerabilities))
	// 1. image reference -> SBOM
	// 2. SBOM -> look at the "vulnerabilities" key and
	//    see if there are any matching vuln IDs in our list
	imageName := i.Name()
	tag := getSBOMTagFromImage(i)

	sbom, err := c.sbomClient.GetSBOM(context.Background(), imageName, tag)
	if err != nil {
		return nil, err
	}
	for _, vulnerability := range *sbom.Vulnerabilities {
		formattedVulnerabilityID := strings.TrimSpace(strings.ToUpper(vulnerability.ID))
		if _, ok := c.failOnVulnerabilities[formattedVulnerabilityID]; ok {
			vulnerabilitiesFound = append(vulnerabilitiesFound, formattedVulnerabilityID)
		}
	}
	return vulnerabilitiesFound, nil
}

// GetSBOMTagFromImage returns the sbom tag from the image
func getSBOMTagFromImage(i voucher.ImageData) string {
	// Parse the image reference
	imageSHA := string(i.Digest())
	tag := strings.Replace(imageSHA, ":", "-", 1) + ".att"
	return tag
}

// check Is it true that there are no vulnerabilities found
// from the vulnerability list?
func (c *check) Check(ctx context.Context, i voucher.ImageData) (bool, error) {
	vulnerabilitiesFound, err := c.hasAListedVulnerability(i)
	// do the error check first
	if err != nil {
		return false, err
	}
	// is it the case there are no vulns
	if len(vulnerabilitiesFound) > 0 {
		return false, NewSbomVulnerabilityError(vulnerabilitiesFound)
	}
	// add more
	return true, nil
}

func init() {
	voucher.RegisterCheckFactory("vulnerabilities", func() voucher.Check {
		return new(check)
	})
}
