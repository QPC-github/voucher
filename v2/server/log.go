package server

import (
	"net/http"

	log "github.com/sirupsen/logrus"

	voucher "github.com/grafeas/voucher/v2"
)

func init() {
	log.SetFormatter(&log.JSONFormatter{})
}

// LogRequests logs the request fields to stdout as Info and returns log fields
func LogRequests(r *http.Request) log.Fields {

	fields := log.Fields{
		"url":       r.URL.String(),
		"path":      r.URL.Path,
		"form":      r.Form,
		"userAgent": r.UserAgent(),
	}

	err := r.ParseForm()

	if err != nil {
		log.WithFields(fields).WithError(err).Info("received request with malformed form")
		return nil
	}

	log.WithFields(fields).Info("received request")
	return fields
}

// LogResult logs each test run as Info
func LogResult(response voucher.Response) {
	for _, result := range response.Results {
		log.WithFields(log.Fields{
			"check":    result.Name,
			"image":    response.Image,
			"passed":   result.Success,
			"attested": result.Attested,
			"error":    result.Err,
		}).Info("Check Result")
	}
}

// LogError logs server errors to stdout as Error
func LogError(message string, err error) {
	log.Errorf("Server error: %s: %s", message, err)
}

// LogWarning logs server errors to stdout as Warning
func LogWarning(message string, err error, fields log.Fields) {

	var warn log.FieldLogger = log.StandardLogger()

	if fields != nil {
		warn = warn.WithFields(fields)
	}

	warn.Warningf("Server warning: %s: %s", message, err)

}

// LogInfo logs server information to stdout as Information.
func LogInfo(message string) {
	log.Infof("Server info: %s", message)
}
