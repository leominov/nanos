package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/leominov/nanos/pkg/vault"
)

const (
	vaultPrefix = "vault:"
)

var (
	outputFormat = flag.String("o", "text", "Output format (text or json)")
)

func main() {
	flag.Parse()
	raw := flag.Arg(0)
	if !strings.HasPrefix(raw, vaultPrefix) {
		fmt.Fprintf(os.Stderr, "Failed to find %q prefix\n", vaultPrefix)
		os.Exit(1)
	}

	raw = strings.TrimPrefix(raw, vaultPrefix)
	parts := strings.Split(raw, "#")
	if len(parts) < 2 {
		fmt.Fprintln(os.Stderr, "Field name must be specified")
		os.Exit(1)
	}

	client, err := vault.NewVaultClient(
		os.Getenv("VAULT_ADDR"),
		os.Getenv("VAULT_LOGIN"),
		os.Getenv("VAULT_PASSWORD"),
		os.Getenv("VAULT_METHOD"),
		http.DefaultClient,
	)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	var versionParam map[string]string
	if len(parts) == 3 {
		versionParam = map[string]string{
			"version": parts[2],
		}
	}

	secret, err := vault.KVReadRequest(client, parts[0], versionParam)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	if secret == nil {
		fmt.Fprintf(os.Stderr, "No value found at %s\n", parts[1])
		os.Exit(1)
	}

	format := strings.ToLower(*outputFormat)
	if data, ok := secret.Data["data"]; ok && data != nil {
		val := data.(map[string]interface{})[parts[1]]
		var version interface{}
		content := val.(string)
		if m, ok := secret.Data["metadata"]; ok {
			if dataMap, ok := m.(map[string]interface{}); ok {
				version = dataMap["version"]
			}
		}
		switch format {
		case "json":
			bytes, _ := json.MarshalIndent(map[string]interface{}{
				"version": version,
				"content": content,
			}, "", "    ")
			fmt.Fprint(os.Stdout, string(bytes))
		default:
			fmt.Fprint(os.Stdout, content)
		}
		return
	}
	fmt.Fprintln(os.Stderr, "Failed to find data")
}
