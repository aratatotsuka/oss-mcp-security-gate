package main

import (
	"flag"
	"fmt"
	"github.com/aratatotsuka/oss-mcp-security-gate/internal/deploy"
	"os"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		os.Exit(64)
	}
	f := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	root := f.String("path", "", "cache path")
	artifact := f.String("artifact", "", "artifact")
	name := f.String("name", "", "binary archive member")
	out := f.String("output", "", "output")
	version := f.String("version", "", "snapshot version")
	updated := f.String("updated-at", "", "source timestamp")
	f.Parse(os.Args[2:])
	var err error
	switch os.Args[1] {
	case "extract":
		err = deploy.ExtractBinary(*artifact, *name, *out)
	case "snapshot":
		var t time.Time
		t, err = time.Parse(time.RFC3339, *updated)
		if err == nil {
			err = deploy.Snapshot(*root, *version, t)
		}
	case "verify":
		_, err = deploy.VerifyCache(*root)
	default:
		os.Exit(64)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
