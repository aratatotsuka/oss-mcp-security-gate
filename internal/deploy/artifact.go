package deploy

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
)

// ExtractBinary never extracts archive paths to the filesystem. It only writes
// the selected regular executable to one caller-selected destination.
func ExtractBinary(artifact, name, destination string) error {
	f, err := os.Open(artifact)
	if err != nil {
		return err
	}
	defer f.Close()
	var data []byte
	if strings.HasSuffix(artifact, ".tar.gz") {
		gz, err := gzip.NewReader(f)
		if err != nil {
			return err
		}
		defer gz.Close()
		t := tar.NewReader(gz)
		var total int64
		for count := 0; ; count++ {
			h, err := t.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				return err
			}
			p := path.Clean(h.Name)
			if count >= 256 || strings.Contains(h.Name, "\\") || path.IsAbs(p) || p == ".." || strings.HasPrefix(p, "../") || strings.Contains(p, ":") {
				return fmt.Errorf("unsafe archive entry: %q", h.Name)
			}
			if h.Typeflag != tar.TypeReg && h.Typeflag != tar.TypeDir {
				return fmt.Errorf("archive links and special files are prohibited: %q", h.Name)
			}
			if h.Size < 0 || h.Size > 256<<20 {
				return fmt.Errorf("archive member too large")
			}
			total += h.Size
			if total > 512<<20 {
				return fmt.Errorf("archive expansion limit exceeded")
			}
			if h.Typeflag == tar.TypeReg && p == name {
				if data != nil {
					return fmt.Errorf("duplicate scanner binary")
				}
				data, err = io.ReadAll(io.LimitReader(t, (256<<20)+1))
				if err != nil {
					return err
				}
			}
		}
	} else {
		data, err = io.ReadAll(io.LimitReader(f, (256<<20)+1))
		if err != nil {
			return err
		}
	}
	if len(data) == 0 || len(data) > 256<<20 {
		return fmt.Errorf("scanner binary missing or too large")
	}
	if len(data) < 4 || string(data[:4]) != "\x7fELF" {
		return fmt.Errorf("scanner must be a Linux ELF executable")
	}
	return os.WriteFile(destination, data, 0555)
}
