package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

const (
	vaultPrefix = "vault:"
)

func main() {
	flag.Parse()
	raw := flag.Arg(0)
	if !strings.HasPrefix(raw, vaultPrefix) {
		return
	}
	raw = strings.TrimPrefix(raw, vaultPrefix)
	data := strings.Split(raw, "#")
	if len(data) < 2 {
		return
	}
	args := []string{
		"kv",
		"get",
	}
	if len(data) == 3 {
		args = append(args, fmt.Sprintf("--version=%s", data[2]))
	}
	args = append(args, fmt.Sprintf("--field=%s", data[1]))
	args = append(args, strings.Replace(data[0], "/data/", "/", 1))
	fmt.Printf("$ vault %s\n", strings.Join(args, " "))
	out, err := exec.Command("vault", args...).CombinedOutput()
	if len(out) > 0 {
		fmt.Println(string(out))
	}
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
