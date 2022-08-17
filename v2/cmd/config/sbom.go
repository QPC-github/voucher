package config

import (
	voucher "github.com/grafeas/voucher/v2"
	"github.com/grafeas/voucher/v2/sbom"
)

func newSBOMClient() voucher.SBOMClient {
	service := sbom.NewGCRService()
	return sbom.NewClient(service)
}
