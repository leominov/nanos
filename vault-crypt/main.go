package main

import (
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"time"

	spin "github.com/briandowns/spinner"
	humanize "github.com/dustin/go-humanize"
	"github.com/hashicorp/vault/api"
	"github.com/odeke-em/drive/src/dcrypto"
)

var (
	flagDecrypt     = flag.Bool("d", false, "Decrypt input file")
	flagKeyLocation = flag.String("k", "", "Key for encoding or decoding input file (base64key://encoded-key, hashivault://transit-key-id?version=latest)")
	spinner         = spin.New(spin.CharSets[11], 100*time.Millisecond)
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

type conterWriter struct {
	t int
	w io.Writer
}

// Encrypt bytes via secret from reader to writer
func Encrypt(in io.Reader, out io.Writer, secret []byte) (int64, error) {
	encrypter, err := dcrypto.NewEncrypter(in, secret)
	if err != nil {
		return 0, err
	}
	n, err := io.Copy(&conterWriter{w: out}, encrypter)
	if err != nil {
		return 0, err
	}
	return n, nil
}

// Decrypt bytes via secret from reader to writer
func Decrypt(in io.Reader, out io.Writer, secret []byte) (int64, error) {
	decrypter, err := dcrypto.NewDecrypter(in, secret)
	if err != nil {
		return 0, err
	}
	n, err := io.Copy(&conterWriter{w: out}, decrypter)
	if err != nil {
		return 0, err
	}
	return n, nil
}

func (c *conterWriter) Write(p []byte) (n int, err error) {
	n, err = c.w.Write(p)
	c.t += n
	spinner.Suffix = fmt.Sprintf(" Writing %s...", humanize.Bytes(uint64(c.t)))
	return
}

func realMain(args []string) error {
	var (
		outputFileMode os.FileMode = 0644
		output         *os.File
		input          *os.File
	)

	secret, err := GetKey(*flagKeyLocation)
	if err != nil {
		return err
	}

	inputFilename := args[0]
	outputFilename := args[1]

	if inputFilename == "-" {
		// Reading from Stdin
		input = os.Stdin
	} else {
		// Stat file for reading Mode
		fileInfo, err := os.Stat(inputFilename)
		if err != nil {
			return err
		}
		outputFileMode = fileInfo.Mode()
		// Open file for reading
		f, err := os.Open(inputFilename)
		if err != nil {
			return err
		}
		input = f
	}

	if outputFilename == "-" {
		// Writing to Stdout
		output = os.Stdout
	} else {
		// Open file for writing
		f, err := os.OpenFile(outputFilename, os.O_CREATE|os.O_WRONLY, outputFileMode)
		if err != nil {
			return err
		}
		output = f
		spinner.Start()
		defer spinner.Stop()
	}

	if *flagDecrypt {
		_, err := Decrypt(input, output, secret)
		if err != nil {
			return err
		}
		return nil
	}

	_, err = Encrypt(input, output, secret)
	if err != nil {
		return err
	}
	return nil
}

func main() {
	flag.Parse()

	args := flag.Args()
	if len(args) != 2 {
		fmt.Fprintln(flag.CommandLine.Output(), "Usage: vault-crypt [options...] ./input-file ./output-file")
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
