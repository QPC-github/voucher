# Notes
here are some golang lines that might be useful in the future.

```golang

type CycloneDXVulnerability int

const (
	UnknownVulnerabilityFinding CycloneDXVulnerability = iota
	// CVE vulnerability type
	CveVulnerabilityFinding CycloneDXVulnerability = iota
	// DLA vulnerability type
	DebianLtsAdvisoryVulnerabilityFinding CycloneDXVulnerability = iota
	// DSA vulnerability type
	DebianSecurityAdvisoryVulnerabilityFinding CycloneDXVulnerability = iota
	// GHSA vulnerability type
	GithubVulnerabilityFinding CycloneDXVulnerability = iota
	// GMS vulnerability type
	GitlabVulnerabilityFinding CycloneDXVulnerability = iota
	// GO vulnerability type
	GoVulnerabilityFinding CycloneDXVulnerability = iota
	// NSWG vulnerability type
	NpmVulnerabilityFinding CycloneDXVulnerability = iota
)

// type CveVulnerability struct {
// 	Name string
// }

// // What is the vuln name, the package, the severity, and possibly description/what fixes it
// type NpmVulnerability struct {
// 	// Affects.Ref of CycloneDX.Vulnerabilities
// 	Name string
// 	// ID of CycloneDX.Vulnerabilities
// 	VulnerabilityName string
// 	// VulneratilityRating.Severity
// 	Severity    voucher.Severity
// 	Description string
// 	// we'll leave out "what fixes this for now"
// }
// type GithubVulnerability struct {
// 	Name string
// }

//
func GetCycloneSeverityFromVoucherSeverity(severity voucher.Severity) cyclonedx.Severity {
	switch severity {
	case voucher.NegligibleSeverity:
		return cyclonedx.SeverityInfo
	case voucher.LowSeverity:
		return cyclonedx.SeverityLow
	case voucher.MediumSeverity:
		return cyclonedx.SeverityMedium
	case voucher.HighSeverity:
		return cyclonedx.SeverityHigh
	case voucher.CriticalSeverity:
		return cyclonedx.SeverityCritical
	}
	return cyclonedx.SeverityUnknown
}

// getSeverity converts a cycloneDX serverity into a Voucher serverity.
func getSeverity(severity string) voucher.Severity {
	switch cyclonedx.Severity(severity) {
	case cyclonedx.SeverityInfo:
		return voucher.NegligibleSeverity
	case cyclonedx.SeverityLow:
		return voucher.LowSeverity
	case cyclonedx.SeverityMedium:
		return voucher.MediumSeverity
	case cyclonedx.SeverityHigh:
		return voucher.HighSeverity
	case cyclonedx.SeverityCritical:
		return voucher.CriticalSeverity
	}
	return voucher.UnknownSeverity
}

// vulnerabilityToVoucherVulnerability converts a cycloneDX Vulnerability to a Voucher Vulnerability.
// func vulnerabilityToVoucherVulnerability(cycloneVuln cyclonedx.Vulnerability) voucher.Vulnerability {
// 	// vulns := make([]voucher.Vulnerability, 0, len(*cycloneVuln.Ratings))

// 	// for _, rating := range *cycloneVuln.Ratings {
// 	// 	severity := getSeverity(rating.Severity)
// 	// 	vulns = append(vulns, voucher.Vulnerability{
// 	// 		Name:        cycloneVuln.Name,
// 	// 		Severity:    severity,
// 	// 	})
// 	// severity := getSeverity(cycloneVuln.Ratings[0].Severity)
// 	return voucher.Vulnerability{}
// }

func getVulnerabilityType(cycloneVuln cyclonedx.Vulnerability) CycloneDXVulnerability {
	//how to parse a node vulnerability:
	// check first four letters of ID is "NSWG"
	fmt.Printf("ID: %v", cycloneVuln.ID)
	vulnId := strings.Split(cycloneVuln.ID, "-")[0]
	// CVE is very broad and can come from
	// difference security database, e.g. ruby,
	// debian, gitlab, github, etc.
	switch vulnId {
	case "NSWG":
		return NpmVulnerabilityFinding
	case "CVE":
		return CveVulnerabilityFinding
	case "GMS":
		return GitlabVulnerabilityFinding
	case "GHSA":
		return GithubVulnerabilityFinding
	case "DSA":
		return DebianSecurityAdvisoryVulnerabilityFinding
	case "DLA":
		return DebianLtsAdvisoryVulnerabilityFinding
	default:
		return UnknownVulnerabilityFinding
	}
}

// func vulnerabilityToNpmVulnerabilty(cycloneVuln cyclonedx.Vulnerability) (NpmVulnerability, error) {
// 	vulnFindingType := getVulnerabilityType(cycloneVuln)
// 	if vulnFindingType != NpmVulnerabilityFinding {
// 		return NpmVulnerability{}, errors.New("Not an npm vulnerability")
// 	}
// 	severity := voucher.UnknownSeverity
// 	for _, rating := range *cycloneVuln.Ratings {
// 		severity = getSeverity(string(rating.Severity))
// 		break
// 	}
// 	name := ""
// 	for _, affect := range *cycloneVuln.Affects {
// 		name = affect.Ref
// 		break
// 	}
// 	return NpmVulnerability{
// 		// Affects.Ref of CycloneDX.Vulnerabilities
// 		Name: name,
// 		// ID of CycloneDX.Vulnerabilities
// 		VulnerabilityName: cycloneVuln.ID,
// 		// VulneratilityRating.Severity
// 		Severity:    severity,
// 		Description: cycloneVuln.Description,
// 	}, nil
// }
```
