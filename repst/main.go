package main

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
)

func main() {
	separator := "="
	if sep := os.Getenv("SEPARATOR"); len(sep) > 0 {
		separator = sep
	}
	replacers := os.Args[1:]
	payloadRaw, err := GetStdinPayload()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	payload := string(payloadRaw)
	for _, replacer := range replacers {
		data := strings.SplitN(replacer, separator, 2)
		if len(data) != 2 {
			continue
		}
		payload = strings.ReplaceAll(payload, data[0], data[1])
	}
	fmt.Print(payload)
}

func GetStdinPayload() ([]byte, error) {
	reader := bufio.NewReader(os.Stdin)
	b, err := ioutil.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	return b, nil
}
