package containeranalysis

import (
	"context"
	"errors"
	"os"

	containeranalysisapi "cloud.google.com/go/containeranalysis/apiv1"
	grafeasv1 "cloud.google.com/go/grafeas/apiv1"

	"github.com/docker/distribution/reference"
	"github.com/sirupsen/logrus"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
	grafeas "google.golang.org/genproto/googleapis/grafeas/v1"

	voucher "github.com/grafeas/voucher/v2"
	"github.com/grafeas/voucher/v2/attestation"
	"github.com/grafeas/voucher/v2/docker/uri"
	"github.com/grafeas/voucher/v2/repository"
	"github.com/grafeas/voucher/v2/signer"
)

var errCannotAttest = errors.New("cannot create attestations, keyring is empty")

// Client implements voucher.MetadataClient, connecting to containeranalysis Grafeas.
type Client struct {
	containeranalysis *grafeasv1.Client        // The client reference.
	keyring           signer.AttestationSigner // The keyring used for signing metadata.
	binauthProject    string                   // The project that Binauth Notes and Occurrences are written to.
}

// CanAttest returns true if the client can create and sign attestations.
func (g *Client) CanAttest() bool {
	return nil != g.keyring
}

// NewPayloadBody returns a payload body appropriate for this MetadataClient.
func (g *Client) NewPayloadBody(ref reference.Canonical) (string, error) {
	payload, err := attestation.NewPayload(ref).ToString()
	if err != nil {
		return "", err
	}

	return payload, err
}

// AddAttestationToImage adds a new attestation with the passed Attestation
// to the image described by ImageData.
func (g *Client) AddAttestationToImage(ctx context.Context, ref reference.Canonical, attestation voucher.Attestation) (voucher.SignedAttestation, error) {
	if !g.CanAttest() {
		return voucher.SignedAttestation{}, errCannotAttest
	}

	signedAttestation, err := voucher.SignAttestation(g.keyring, attestation)
	if nil != err {
		return voucher.SignedAttestation{}, err
	}

	_, err = g.containeranalysis.CreateOccurrence(
		ctx,
		newOccurrenceAttestation(
			ref,
			signedAttestation,
			g.binauthProject,
		),
	)

	if isAttestionExistsErr(err) {
		err = nil

		signedAttestation.Signature = ""
	}

	return signedAttestation, err
}

// GetAttestations returns all of the attestations associated with an image.
func (g *Client) GetAttestations(ctx context.Context, ref reference.Canonical) ([]voucher.SignedAttestation, error) {
	filterStr := kindFilterStr(ref, grafeas.NoteKind_ATTESTATION)

	var attestations []voucher.SignedAttestation

	log := &logrus.Logger{
		Out:       os.Stderr,
		Formatter: new(logrus.JSONFormatter),
		Hooks:     make(logrus.LevelHooks),
		Level:     logrus.DebugLevel,
	}

	project := projectPath(g.binauthProject)
	req := &grafeas.ListOccurrencesRequest{Parent: project, Filter: filterStr}
	occIterator := g.containeranalysis.ListOccurrences(ctx, req)

	log.Printf("ListOccurrencesRequest from verify: %+v\n", req)
	log.Printf("occ Iterator from verify: %+v\n", occIterator)

	for {
		occ, err := occIterator.Next()
		if nil != err {
			if iterator.Done == err {
				return attestations, nil
			}
			return nil, err
		}

		note, err := g.containeranalysis.GetOccurrenceNote(
			ctx,
			&grafeas.GetOccurrenceNoteRequest{
				Name: occ.GetName(),
			},
		)
		if nil != err {
			return nil, err
		}

		name := getCheckNameFromNoteName(g.binauthProject, note.GetName())

		attestations = append(
			attestations,
			OccurrenceToAttestation(name, occ),
		)
	}
}

// GetVulnerabilities returns the detected vulnerabilities for the Image described by voucher.ImageData.
func (g *Client) GetVulnerabilities(ctx context.Context, ref reference.Canonical) (vulnerabilities []voucher.Vulnerability, err error) {
	filterStr := kindFilterStr(ref, grafeas.NoteKind_VULNERABILITY)

	err = pollForDiscoveries(ctx, g, ref)
	if nil != err {
		return []voucher.Vulnerability{}, err
	}

	project, err := uri.ReferenceToProjectName(ref)
	if nil != err {
		return []voucher.Vulnerability{}, err
	}

	req := &grafeas.ListOccurrencesRequest{Parent: projectPath(project), Filter: filterStr}
	occIterator := g.containeranalysis.ListOccurrences(ctx, req)

	for {
		var occ *grafeas.Occurrence

		occ, err = occIterator.Next()
		if nil != err {
			if iterator.Done == err {
				err = nil
			}

			break
		}

		vuln := OccurrenceToVulnerability(occ)
		vulnerabilities = append(vulnerabilities, vuln)
	}

	return
}

// Close closes the containeranalysis Grafeas client.
func (g *Client) Close() {
	if nil != g.keyring {
		_ = g.keyring.Close()
	}
	g.containeranalysis.Close()
}

// GetBuildDetail gets the BuildDetail for the passed image.
func (g *Client) GetBuildDetail(ctx context.Context, ref reference.Canonical) (repository.BuildDetail, error) {
	var err error

	// 	"jsonPayload": {
	// 	  "msg": "ListOccurrencesRequest from check: parent:\"projects/shopify-codelab-and-demos\"
	// filter:\"resourceUrl=\\\"https://gcr.io/shopify-codelab-and-demos/sbom-lab/apps/production/clouddo-ui@sha256:551182244aa6ab6997900bc04dd4e170ef13455c068360e93fc7b149eb2bc45f\\\"
	//  AND kind=\\\"BUILD\\\"\" \n",
	// 	  "level": "info"

	// TODO, put this back!!!
	filterStr := kindFilterStr(ref, grafeas.NoteKind_BUILD)
	// filterStr := kindFilterStr(ref, grafeas.NoteKind_NOTE_KIND_UNSPECIFIED)

	// project, err := uri.ReferenceToProjectName(ref)
	// if nil != err {
	// 	return repository.BuildDetail{}, err
	// }

	log := &logrus.Logger{
		Out:       os.Stderr,
		Formatter: new(logrus.JSONFormatter),
		Hooks:     make(logrus.LevelHooks),
		Level:     logrus.DebugLevel,
	}

	// TODO: replace the Parent with proper project again
	req := &grafeas.ListOccurrencesRequest{Parent: "projects/shopify-docker-images", Filter: filterStr}
	occIterator := g.containeranalysis.ListOccurrences(ctx, req)

	log.Printf("ListOccurrencesRequest from check: %+v\n", req)
	log.Printf("occ Iterator from check: %+v\n", occIterator)

	occ, err := occIterator.Next()
	if err != nil {
		if err == iterator.Done {
			// TODO: put this back
			// err = &voucher.NoMetadataError{
			// 	Type: voucher.VulnerabilityType,
			// 	Err:  errNoOccurrences,
			// }
			return repository.BuildDetail{
				RepositoryURL: ref.String(),
				Commit:        "",
				BuildCreator:  "",
				BuildURL:      "",
				ProjectID:     "shopify-docker-images",
				Artifacts:     []repository.BuildArtifact{},
			}, nil
		}
		return repository.BuildDetail{}, err
	}

	if _, err := occIterator.Next(); err != iterator.Done {
		return repository.BuildDetail{}, errors.New("Found multiple Grafeas occurrences for " + ref.String())
	}

	return OccurrenceToBuildDetail(occ), nil
}

// NewClient creates a new containeranalysis Grafeas Client.
func NewClient(ctx context.Context, binauthProject string, keyring signer.AttestationSigner) (*Client, error) {
	// These options emulate cloud.google.com/go/containeranalysis/apiv1.NewClient
	grafeasClient, err := grafeasv1.NewClient(ctx, option.WithEndpoint("containeranalysis.googleapis.com:443"), option.WithScopes(containeranalysisapi.DefaultAuthScopes()...))
	if err != nil {
		return nil, err
	}
	client := &Client{
		containeranalysis: grafeasClient,
		keyring:           keyring,
		binauthProject:    binauthProject,
	}

	return client, nil
}
