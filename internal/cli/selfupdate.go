package cli

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

const releaseBase = "https://github.com/alexgoller/illumio-plugger/releases/download"

func newSelfUpdateCmd() *cobra.Command {
	var force bool

	cmd := &cobra.Command{
		Use:     "self-update",
		Aliases: []string{"selfupdate"},
		Short:   "Update the plugger CLI to the latest release",
		Long: `Download the latest plugger release for this OS/architecture from GitHub,
verify it against the published SHA256SUMS, and atomically replace the running
binary.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			latest, err := checkLatestRelease()
			if err != nil {
				return fmt.Errorf("checking latest release: %w", err)
			}
			current := strings.TrimPrefix(Version, "v")

			fmt.Printf("Current version: %s\n", current)
			fmt.Printf("Latest version:  %s\n", latest)

			if current == latest && !force {
				fmt.Println("Already up to date.")
				return nil
			}
			if current == "dev" && !force {
				fmt.Println("Running a dev build — use --force to overwrite it with the latest release.")
				return nil
			}

			assetName := assetName()
			tag := "v" + latest
			assetURL := fmt.Sprintf("%s/%s/%s", releaseBase, tag, assetName)
			sumsURL := fmt.Sprintf("%s/%s/SHA256SUMS", releaseBase, tag)

			fmt.Printf("Downloading %s ...\n", assetName)
			binData, err := download(assetURL)
			if err != nil {
				return fmt.Errorf("downloading binary: %w", err)
			}

			fmt.Println("Verifying checksum ...")
			wantSum, err := fetchExpectedSum(sumsURL, assetName)
			if err != nil {
				return fmt.Errorf("fetching checksum: %w", err)
			}
			gotSum := sha256Hex(binData)
			if gotSum != wantSum {
				return fmt.Errorf("checksum mismatch: expected %s, got %s (aborting, binary not replaced)", wantSum, gotSum)
			}

			if err := replaceSelf(binData); err != nil {
				return fmt.Errorf("replacing binary: %w", err)
			}

			fmt.Printf("Updated plugger %s → %s\n", current, latest)
			return nil
		},
	}

	cmd.Flags().BoolVar(&force, "force", false, "update even if already on the latest version or a dev build")
	return cmd
}

// assetName returns the release asset filename for the current platform,
// matching the names produced by the release workflow.
func assetName() string {
	name := fmt.Sprintf("plugger-%s-%s", runtime.GOOS, runtime.GOARCH)
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return name
}

func download(url string) ([]byte, error) {
	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, url)
	}
	return io.ReadAll(resp.Body)
}

// fetchExpectedSum downloads SHA256SUMS and returns the hash for assetName.
func fetchExpectedSum(url, asset string) (string, error) {
	data, err := download(url)
	if err != nil {
		return "", err
	}
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) != 2 {
			continue
		}
		// sha256sum format: "<hash>  <filename>" (filename may have a * prefix)
		if strings.TrimPrefix(fields[1], "*") == asset {
			return fields[0], nil
		}
	}
	return "", fmt.Errorf("no checksum for %s in SHA256SUMS", asset)
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// replaceSelf atomically swaps the running executable with new contents.
// It writes to a temp file in the same directory (so os.Rename stays on one
// filesystem) and renames it over the current binary. On Windows a running
// executable can't be overwritten, so the current binary is moved aside first.
func replaceSelf(newData []byte) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		return err
	}
	dir := filepath.Dir(exe)

	tmp, err := os.CreateTemp(dir, ".plugger-update-*")
	if err != nil {
		return fmt.Errorf("creating temp file (need write access to %s): %w", dir, err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op if the rename succeeded

	if _, err := tmp.Write(newData); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0755); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}

	if runtime.GOOS == "windows" {
		// Can't overwrite a running .exe; move it aside, then rename the new one in.
		old := exe + ".old"
		_ = os.Remove(old)
		if err := os.Rename(exe, old); err != nil {
			return err
		}
		if err := os.Rename(tmpName, exe); err != nil {
			_ = os.Rename(old, exe) // best-effort rollback
			return err
		}
		_ = os.Remove(old) // may fail while running; harmless leftover
		return nil
	}

	return os.Rename(tmpName, exe)
}
