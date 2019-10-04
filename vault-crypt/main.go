package main

import (
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"

	"github.com/hashicorp/vault/api"
	"github.com/odeke-em/drive/src/dcrypto"
)

var (
	flagDecrypt     = flag.Bool("d", false, "Decrypt input file")
	flagKeyLocation = flag.String("k", "", "Key for encoding or decoding input file (base64key://encoded-key, hashivault://transit-key-id?version=latest)")
)

// GetBase64key returns decoded key
func GetBase64key(key string) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return nil, err
	}
	return decoded, nil
}

// GetHashiVault returns exported transit keys
func GetHashiVault(key, version string) ([]byte, error) {
	// On empty the current key will be provided
	if len(version) == 0 {
		version = "latest"
	}

	// Create Client with DefaultConfig
	client, err := api.NewClient(nil)
	if err != nil {
		return nil, err
	}

	client.SetToken(os.Getenv("VAULT_SERVER_TOKEN"))
	err = client.SetAddress(os.Getenv("VAULT_SERVER_URL"))
	if err != nil {
		return nil, err
	}

	// https://www.vaultproject.io/api/secret/transit/index.html#export-key
	route := fmt.Sprintf("transit/export/encryption-key/%s/%s", key, version)
	secret, err := client.Logical().Read(route)
	if err != nil {
		return nil, err
	}
	if secret == nil || secret.Data == nil {
		return nil, errors.New("Vault: secret not found")
	}

	keys, ok := secret.Data["keys"]
	if !ok {
		return nil, errors.New("Vault: keys not found")
	}

	bytes := []byte{}
	for n, k := range keys.(map[string]interface{}) {
		key := k.(string)
		decoded, err := base64.StdEncoding.DecodeString(key)
		if err != nil {
			return nil, fmt.Errorf("Vault: failed to decode %s key", n)
		}
		bytes = append(bytes, decoded...)
	}
	return bytes, nil
}

// GetKey parse and get key for encryption or decryption
func GetKey(location string) ([]byte, error) {
	s, err := url.Parse(location)
	if err != nil {
		return nil, err
	}

	switch s.Scheme {
	case "base64key":
		return GetBase64key(s.Hostname())
	case "hashivault":
		return GetHashiVault(s.Hostname(), s.Query().Get("version"))
	}
	return nil, errors.New("Unsupported key scheme")
}

// Encrypt bytes via secret from reader to writer
func Encrypt(in io.Reader, out io.Writer, secret []byte) error {
	encrypter, err := dcrypto.NewEncrypter(in, secret)
	if err != nil {
		return err
	}
	_, err = io.Copy(out, encrypter)
	if err != nil {
		return err
	}
	return nil
}

// Decrypt bytes via secret from reader to writer
func Decrypt(in io.Reader, out io.Writer, secret []byte) error {
	decrypter, err := dcrypto.NewDecrypter(in, secret)
	if err != nil {
		return err
	}
	_, err = io.Copy(out, decrypter)
	if err != nil {
		return err
	}
	return nil
}

func realMain(args []string) error {
	secret, err := GetKey(*flagKeyLocation)
	if err != nil {
		return err
	}

	inputFilename := args[0]
	outputFilename := args[1]

	// Stat file for reading Mode
	fileInfo, err := os.Stat(inputFilename)
	if err != nil {
		return err
	}

	// Open file for reading
	in, err := os.Open(inputFilename)
	if err != nil {
		return err
	}

	// Open file for writing
	out, err := os.OpenFile(outputFilename, os.O_CREATE|os.O_WRONLY, fileInfo.Mode())
	if err != nil {
		return err
	}

	if *flagDecrypt {
		if err := Decrypt(in, out, secret); err != nil {
			return err
		}
		return nil
	}

	if err := Encrypt(in, out, secret); err != nil {
		return err
	}

	return nil
}

func main() {
	flag.Parse()

	args := flag.Args()
	if len(args) != 2 {
		fmt.Fprintln(flag.CommandLine.Output(), "Usage: vault-crypt [flags] ./input-file ./output-file")
		fmt.Fprintln(flag.CommandLine.Output(), "Options:")
		flag.PrintDefaults()
		return
	}

	err := realMain(args)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
