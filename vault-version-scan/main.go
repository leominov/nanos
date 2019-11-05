package main

import (
	"encoding/json"
	"flag"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/leominov/nanos/pkg/vault"
	"github.com/sirupsen/logrus"
)

const (
	vaultPrefix = "vault:"
)

var (
	optsInputDir = flag.String("dir", "./", "Directory to search vault:engine/data/path/secret#field#1 entries")
	logLevel     = flag.String("log-level", "info", "Level of logging")

	vaultSecretRE = regexp.MustCompile(`(vault:[\w\/\-\_\#]+)`)
)

func FilePathWalkDir(root string) ([]string, error) {
	var files []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if strings.Contains(path, ".git/") {
			return nil
		}
		if !info.IsDir() {
			files = append(files, path)
		}
		return nil
	})
	return files, err
}

func main() {
	flag.Parse()

	if lvl, err := logrus.ParseLevel(*logLevel); err == nil {
		logrus.SetLevel(lvl)
	}

	files, err := FilePathWalkDir(*optsInputDir)
	if err != nil {
		logrus.Fatal(err)
	}

	client, err := vault.NewVaultClient(
		os.Getenv("VAULT_ADDR"),
		os.Getenv("VAULT_LOGIN"),
		os.Getenv("VAULT_PASSWORD"),
		os.Getenv("VAULT_METHOD"),
		http.DefaultClient,
	)
	if err != nil {
		logrus.Fatal(err)
	}

	logrus.Infof("Files: %d", len(files))
	for _, file := range files {
		b, err := ioutil.ReadFile(file)
		if err != nil {
			logrus.Error(err)
			continue
		}
		matchGroups := vaultSecretRE.FindAllStringSubmatch(string(b), -1)
		if len(matchGroups) == 0 {
			continue
		}
		logrus.Infof("Scanning %s file...", file)
		for _, matchGroup := range matchGroups {
			if len(matchGroup) < 1 {
				continue
			}
			raw := strings.TrimPrefix(matchGroup[1], vaultPrefix)
			logrus.Debugf("Checking %s secret...", raw)
			parts := strings.Split(raw, "#")
			if len(parts) < 3 {
				logrus.Errorf("%s: Version not specified", raw)
				continue
			}
			secret, err := vault.KVReadRequest(client, parts[0], map[string]string{})
			if err != nil {
				logrus.Errorf("%s: %v", raw, err)
				continue
			}
			version, _ := vault.GetSecretData(secret, parts[1])
			if parts[2] != version.(json.Number).String() {
				logrus.Errorf("%s: Latest version: %s", raw, version)
			}
		}
	}
}
