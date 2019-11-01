package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
)

const (
	vaultPrefix = "vault:"
)

var (
	outputFormat = flag.String("format", "text", "Output format (text or json)")
)

func main() {
	flag.Parse()
	raw := flag.Arg(0)
	if !strings.HasPrefix(raw, vaultPrefix) {
		os.Exit(1)
	}

	raw = strings.TrimPrefix(raw, vaultPrefix)
	parts := strings.Split(raw, "#")
	if len(parts) < 2 {
		os.Exit(1)
	}

	client, err := NewVaultClient(
		os.Getenv("VAULT_ADDR"),
		os.Getenv("VAULT_LOGIN"),
		os.Getenv("VAULT_PASSWORD"),
		os.Getenv("VAULT_METHOD"),
		http.DefaultClient,
	)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	var versionParam map[string]string
	if len(parts) == 3 {
		versionParam = map[string]string{
			"version": parts[2],
		}
	}

	secret, err := kvReadRequest(client, parts[0], versionParam)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	if secret == nil {
		fmt.Println(fmt.Sprintf("No value found at %s", parts[1]))
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
			fmt.Println(string(bytes))
		default:
			fmt.Printf("Version: %s\n", version)
			fmt.Printf("Content: %s\n", content)
		}
	}
}
