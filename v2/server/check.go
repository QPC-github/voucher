package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	voucher "github.com/grafeas/voucher/v2"
	"github.com/grafeas/voucher/v2/cmd/config"
	"github.com/grafeas/voucher/v2/repository"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

func (s *Server) handleChecks(w http.ResponseWriter, r *http.Request, name ...string) {
	var imageData voucher.ImageData
	var repositoryClient repository.Client
	var err error

	defer r.Body.Close()

	w.Header().Set("content-type", "application/json")

	requestFields := LogRequests(r)

	imageData, err = handleInput(r)
	if nil != err {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		LogError(err.Error(), err)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), s.serverConfig.TimeoutDuration())
	defer cancel()

	metadataClient, err := config.NewMetadataClient(ctx, s.secrets)
	if nil != err {
		http.Error(w, "server has been misconfigured", http.StatusInternalServerError)
		LogError("failed to create MetadataClient", err)
		return
	}
	defer metadataClient.Close()

	// Initialize repository client if and only if we have a secrets that represents the org repo
	if s.secrets != nil {
		// Get the buildDetail from the metadataClient.
		// If no buildDetail is found, we will skip initializing the repository client.
		buildDetail, buildErr := metadataClient.GetBuildDetail(ctx, imageData)
		if buildErr != nil {
			LogWarning(fmt.Sprintf("could not get image metadata for %s. Skipping repository client initialization", imageData), buildErr, requestFields)
		} else {
			repositoryClient, err = config.NewRepositoryClient(ctx, s.secrets.RepositoryAuthentication, buildDetail.RepositoryURL)
			if err != nil {
				LogWarning("failed to create repository client, continuing without git repo support:", err, requestFields)
			}
		}
	} else {
		log.Warning("failed to create repository client, no secrets configured")
	}

	checksuite, err := config.NewCheckSuite(metadataClient, repositoryClient, name...)
	if nil != err {
		http.Error(w, "server has been misconfigured", http.StatusInternalServerError)
		LogError("failed to create CheckSuite", err)
		return
	}

	var results []voucher.CheckResult

	if viper.GetBool("dryrun") {
		results = checksuite.Run(ctx, s.metrics, imageData)
	} else {
		results = checksuite.RunAndAttest(ctx, metadataClient, s.metrics, imageData)
	}

	checkResponse := voucher.NewResponse(imageData, results)

	LogResult(checkResponse)

	err = json.NewEncoder(w).Encode(checkResponse)
	if nil != err {
		// if all else fails
		http.Error(w, err.Error(), http.StatusInternalServerError)
		LogError("failed to encode respoonse as JSON", err)
		return
	}
}
