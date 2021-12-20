package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	voucher "github.com/grafeas/voucher/v2"
	"github.com/grafeas/voucher/v2/client"
)

type config struct {
	Server   string
	Username string
	Password string
	Timeout  int
	Check    string
	Auth     string
}

var defaultConfig = &config{}

func getCheck() string {
	return defaultConfig.Check
}

func getVoucherClient() (voucher.Interface, error) {
	options := []client.Option{
		client.WithUserAgent(fmt.Sprintf("voucher-client/%s", version)),
	}
	switch strings.ToLower(defaultConfig.Auth) {
	case "basic":
		options = append(options, client.WithBasicAuth(defaultConfig.Username, defaultConfig.Password))
	case "idtoken":
		options = append(options, client.WithIDTokenAuth())
	case "default-access-token":
		options = append(options, client.WithDefaultTokenAuth())
	default:
		return nil, fmt.Errorf("invalid auth value: %q", defaultConfig.Auth)
	}

	newClient, err := client.NewClient(context.Background(), defaultConfig.Server, options...)
	if err != nil {
		return nil, err
	}
	return newClient, nil
}

func newContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), time.Duration(defaultConfig.Timeout)*time.Second)
}
