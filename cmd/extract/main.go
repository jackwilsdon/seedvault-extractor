package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/google/tink/go/streamingaead/subtle"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/pbkdf2"
	"io"
	"os"
	"path/filepath"
	"strconv"
)

const (
	typeKVBackup   = 1
	typeFullBackup = 2
)

func main() {
	if len(os.Args) != 3 {
		_, _ = fmt.Fprintf(os.Stderr, "usage: %s path-to-backup mnemonic\n", filepath.Base(os.Args[0]))
		os.Exit(1)
	}

	backupPath := os.Args[1]
	metadataPath := filepath.Join(backupPath, ".backup.metadata")
	_, err := os.Stat(metadataPath)
	if errors.Is(err, os.ErrNotExist) {
		_, _ = fmt.Fprintln(os.Stderr, "error: not a backup (missing .backup.metadata)")
		os.Exit(1)
	} else if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "error: failed to stat %q: %s\n", metadataPath, err)
		os.Exit(1)
	}

	metadataFile, err := os.Open(metadataPath)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "error: failed to open %q: %s\n", metadataPath, err)
		os.Exit(1)
	}
	defer func() {
		_ = metadataFile.Close()
	}()

	metadataReader := bufio.NewReader(metadataFile)
	version, err := metadataReader.ReadByte()
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "error: failed to read version from %q: %s\n", metadataPath, err)
		os.Exit(1)
	}
	if version != 1 {
		_, _ = fmt.Fprintf(os.Stderr, "error: unsupported version %d (only version 1 is supported)\n", version)
		os.Exit(1)
	}

	debug := os.Getenv("DEBUG") == "1"
	if debug {
		fmt.Printf("version: %d\n", version)
	}

	backupName := filepath.Base(backupPath)
	token, err := strconv.ParseUint(backupName, 10, 64)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "error: failed to parse backup name %q: %s\n", backupName, err)
		os.Exit(1)
	}

	if debug {
		fmt.Printf("token: %d\n", token)
	}

	seed := mnemonicToSeed(os.Args[2])
	if debug {
		fmt.Printf("seed: %s\n", hex.EncodeToString(seed))
	}

	key := hkdfExpand(seed[32:], []byte("app data key"), 32)
	if debug {
		fmt.Printf("key: %s\n", hex.EncodeToString(key))
	}

	associatedData := make([]byte, 10)
	associatedData[0] = version
	binary.BigEndian.PutUint64(associatedData[2:], token)
	metadataBytes, err := decrypt(metadataReader, key, associatedData)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "error: failed to decrypt metadata: %s\n", err)
		os.Exit(1)
	}
	if debug {
		fmt.Printf("metadata: %s\n", string(metadataBytes))
	}

	var metadataMap map[string]json.RawMessage
	if err := json.Unmarshal(metadataBytes, &metadataMap); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "error: failed to unmarshal metadata: %s\n", err)
		os.Exit(1)
	}

	metadataMetaBytes, ok := metadataMap["@meta@"]
	if !ok {
		_, _ = fmt.Fprintf(os.Stderr, "error: missing @meta@ key\n")
		os.Exit(1)
	}
	var metadataMeta struct {
		Version byte   `json:"version"`
		Salt    string `json:"salt"`
	}
	if err := json.Unmarshal(metadataMetaBytes, &metadataMeta); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "error: failed to unmarshal @meta@: %s\n", err)
		os.Exit(1)
	}
	if metadataMeta.Version != version {
		_, _ = fmt.Fprintf(os.Stderr, "error: @meta@ version %d does not match metadata file version %d\n", metadataMeta.Version, version)
		os.Exit(1)
	}

	for packageName, packageMetaBytes := range metadataMap {
		if packageName == "@meta@" {
			continue
		}

		err = func() error {
			var packageMeta struct {
				BackupType string `json:"backupType"`
				State      string `json:"state"`
			}
			if err := json.Unmarshal(packageMetaBytes, &packageMeta); err != nil {
				return fmt.Errorf("failed to unmarshal metadata: %w", err)
			}
			if packageMeta.State != "" {
				fmt.Printf("skipping %q (unsupported state %q)\n", packageName, packageMeta.State)
				return nil
			}
			if packageMeta.BackupType != "KV" && packageMeta.BackupType != "FULL" {
				fmt.Printf("skipping %q (unsupported backup type %q)\n", packageName, packageMeta.BackupType)
				return nil
			}

			h := sha256.Sum256([]byte(metadataMeta.Salt + packageName))
			packagePath := filepath.Join(backupPath, base64.RawURLEncoding.EncodeToString(h[:]))
			packageFile, err := os.Open(packagePath)
			if err != nil {
				return fmt.Errorf("failed to open %q: %w", packagePath, err)
			}
			defer func() {
				_ = packageFile.Close()
			}()

			packageReader := bufio.NewReader(packageFile)
			packageVersion, err := packageReader.ReadByte()
			if err != nil {
				return fmt.Errorf("failed to read version from %q: %w", packagePath, err)
			}
			if packageVersion != version {
				return fmt.Errorf("%q version %d does not match metadata file version %d", packagePath, packageVersion, version)
			}

			var type_ byte
			if packageMeta.BackupType == "KV" {
				type_ = typeKVBackup
			} else {
				type_ = typeFullBackup
			}

			packageBytes, err := decrypt(packageReader, key, getAdditionalData(version, type_, packageName))
			if err != nil {
				return fmt.Errorf("failed to decrypt %q: %w", packagePath, err)
			}

			var ext string
			if packageMeta.BackupType == "KV" {
				r, err := gzip.NewReader(bytes.NewReader(packageBytes))
				if err != nil {
					return fmt.Errorf("failed to decompress %q: %w", packagePath, err)
				}
				if packageBytes, err = io.ReadAll(r); err != nil {
					return fmt.Errorf("failed to decompress %q: %w", packagePath, err)
				}
				ext = ".sqlite"
			} else {
				ext = ".tar"
			}

			outPath := packageName + ext
			if err := os.WriteFile(outPath, packageBytes, 0777); err != nil {
				return fmt.Errorf("failed to write %q: %w", outPath, err)
			}
			return nil
		}()
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "error: failed to extract %q: %s\n", packageName, err)
			os.Exit(1)
		}
	}
}

func mnemonicToSeed(mnemonic string) []byte {
	return pbkdf2.Key([]byte(mnemonic), []byte("mnemonic"), 2048, 64, sha512.New)
}

func hkdfExpand(secretKey, info []byte, outLengthBytes int64) []byte {
	r := hkdf.Expand(sha256.New, secretKey, info)
	k := make([]byte, outLengthBytes)
	if _, err := io.ReadFull(r, k); err != nil {
		panic("failed to read HKDF: " + err.Error())
	}
	return k
}

func getAdditionalData(version byte, type_ byte, packageName string) []byte {
	ad := make([]byte, 2+len(packageName))
	ad[0] = version
	ad[1] = type_
	copy(ad[2:], packageName)
	return ad
}

func decrypt(r *bufio.Reader, key []byte, associatedData []byte) ([]byte, error) {
	a, err := subtle.NewAESGCMHKDF(key, "SHA256", 32, 1<<20, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to create AESGCMHKDF: %w", err)
	}
	dr, err := a.NewDecryptingReader(r, associatedData)
	if err != nil {
		return nil, fmt.Errorf("failed to create decrypting reader: %w", err)
	}
	data, err := io.ReadAll(dr)
	if err != nil {
		return nil, fmt.Errorf("failed to read decrypted data: %w", err)
	}
	return data, nil
}
