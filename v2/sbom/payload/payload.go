package payload

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/mitchellh/mapstructure"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
)

const (
	CycloneDXStatementPredicateType = "https://cyclonedx.org/schema"
	CustomStatementPredicateType    = "cosign.sigstore.dev/attestation/v1"
)

// IntotoStatement represents a cyclonedx sbom predicate
type IntotoStatement struct {
	Type          string `json:"_type"`
	PredicateType string `json:"predicateType"`
	Subject       []struct {
		Name   string `json:"name"`
		Digest struct {
			Sha256 string `json:"sha256"`
		} `json:"digest"`
	} `json:"subject"`
	Predicate json.RawMessage `json:"predicate"`
}

func GetEnvelopeFromReader(reader io.Reader) (dsse.Envelope, error) {
	bt, err := io.ReadAll(reader)
	if err != nil {
		return dsse.Envelope{}, fmt.Errorf("error reading envelope: %w", err)
	}

	var envelope dsse.Envelope
	err = json.Unmarshal(bt, &envelope)

	if err != nil {
		return envelope, fmt.Errorf("error unmarshalling into envelope %w", err)
	}

	return envelope, nil
}

func GetSBOMFromEnvelope(envelope dsse.Envelope, cyclonedxBOM *cyclonedx.BOM) error {
	decoded, err := envelope.DecodeB64Payload()
	if err != nil {
		return fmt.Errorf("error decoding b64 payload from envelope: %w", err)
	}

	fmt.Printf("signature payload: %s, %s\n", envelope.Signatures[0].KeyID, b64Decode(envelope.Signatures[0].Sig))
	// Get in-toto statement from envelope
	var intotoStatement IntotoStatement
	err = getPredicatefromEnvelope(decoded, &intotoStatement)
	if err != nil {
		return fmt.Errorf("error getting in-toto statement from envelope: %w", err)
	}

	// Parse the payload according to the predicate type
	// TODO: Once https://github.com/in-toto/in-toto-golang/pull/169 added to the official release
	// we will be able to use the in-toto-golang library to parse the predicate payload
	switch intotoStatement.PredicateType {
	case CycloneDXStatementPredicateType:
		// Structure of the cyclonedx predicate is as follows:
		var cycloneDXPredicate struct {
			Data map[string]interface{} `json:"Data"`
		}

		// Unmarshal the cyclonedx statement into the cyclonedx predicate struct
		err = json.Unmarshal(intotoStatement.Predicate, &cycloneDXPredicate)
		if err != nil {
			return fmt.Errorf("error unmarshalling cyclonedx statement into cyclonedx predicate: %w", err)
		}

		// get the cyclonedx BOM from the cyclonedx predicate
		err = mapstructure.Decode(cycloneDXPredicate.Data, cyclonedxBOM)
		if err != nil {
			return fmt.Errorf("error converting cyclonedx predicate data into cycloneDX BOM: %w", err)
		}
	case CustomStatementPredicateType:
		// Structure of the custom predicate is as follows:
		var customPredicate struct {
			Data      string    `json:"Data"`
			Timestamp time.Time `json:"Timestamp"`
		}
		err = json.Unmarshal([]byte(intotoStatement.Predicate), &customPredicate)
		if err != nil {
			return fmt.Errorf("error getting custom predicate: %w", err)
		}

		// get the custom BOM from the custom predicate
		err = json.Unmarshal([]byte(customPredicate.Data), cyclonedxBOM)
		if err != nil {
			return fmt.Errorf("error converting custom predicate into cycloneDX BOM: %w", err)
		}
	default:
		return fmt.Errorf("unsupported BOM predicate type: %s", intotoStatement.PredicateType)
	}
	return nil
}

func getPredicatefromEnvelope(decodedPayload []byte, intotoStatement *IntotoStatement) error {
	err := json.Unmarshal(decodedPayload, intotoStatement)
	if err != nil {
		return fmt.Errorf("error unmarshalling into in-toto statement from envelope: %w", err)
	}

	return nil
}

func b64Decode(s string) []byte {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		b, err = base64.URLEncoding.DecodeString(s)
		if err != nil {
			return nil
		}
	}

	return b
}
