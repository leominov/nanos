package main

import (
	"fmt"
	"io"
	"net/http"

	"github.com/hashicorp/vault/api"
)

func NewVaultClient(addr, user, pass, authMethod string, httpCli *http.Client) (*api.Client, error) {
	config := api.Config{
		Address:    addr,
		HttpClient: httpCli,
	}
	client, err := api.NewClient(&config)
	if err != nil {
		return nil, err
	}
	options := map[string]interface{}{
		"password": pass,
	}
	path := fmt.Sprintf("auth/%s/login/%s", authMethod, user)
	secret, err := client.Logical().Write(path, options)
	if err != nil {
		return nil, err
	}
	client.SetToken(secret.Auth.ClientToken)
	return client, nil
}

func kvReadRequest(client *api.Client, path string, params map[string]string) (*api.Secret, error) {
	r := client.NewRequest("GET", "/v1/"+path)
	for k, v := range params {
		r.Params.Set(k, v)
	}
	resp, err := client.RawRequest(r)
	if resp != nil {
		defer resp.Body.Close()
	}
	if resp != nil && resp.StatusCode == 404 {
		secret, parseErr := api.ParseSecret(resp.Body)
		switch parseErr {
		case nil:
		case io.EOF:
			return nil, nil
		default:
			return nil, err
		}
		if secret != nil && (len(secret.Warnings) > 0 || len(secret.Data) > 0) {
			return secret, nil
		}
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return api.ParseSecret(resp.Body)
}
