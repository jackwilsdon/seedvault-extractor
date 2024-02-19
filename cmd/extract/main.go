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
	"github.com/jackwilsdon/seedvault-extractor/internal"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/pbkdf2"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	typeKVBackup   = 1
	typeFullBackup = 2
)

func main() {
	if len(os.Args) < 3 {
		printHelp()
	}

	userPath    := os.Args[1]
	userPhrase  := os.Args[2]
	userPackage := ""
	userFlagListPackages  := false
	userFlagDebugMode := false
	userFlagCheckOnly := false

	if os.Getenv("DEBUG") == "1" {
		userFlagDebugMode = true
	}

	for argNum, argValue := range os.Args {
		if argValue == "--list" {
			userFlagListPackages = true
		} else if argValue == "--debug" {
			userFlagDebugMode = true
		} else if argValue == "--check" {
			userFlagCheckOnly = true
		} else if argValue == "--package" {
			if len(os.Args)-1 > argNum {
				userPackage = os.Args[argNum+1]
			} else {
				fmt.Println("error: --package flag must be followed by a package name\n")
				os.Exit(1)
			}
		}
	}

	if userFlagDebugMode {
		fmt.Printf("USER INPUT -- userFlagListPackages: '%t'\n", userFlagListPackages)
		fmt.Printf("USER INPUT -- userFlagDebugMode:    '%t'\n", userFlagDebugMode)
		fmt.Printf("USER INPUT -- userFlagCheckOnly:    '%t'\n", userFlagCheckOnly)
		fmt.Printf("USER INPUT -- userPath:             '%s'\n", userPath)
		fmt.Printf("USER INPUT -- userPhrase:           '%s'\n", userPhrase)
		fmt.Printf("USER INPUT -- userPackage:          '%s'\n", userPackage)
	}

	metadataPath := filepath.Join(userPath, ".backup.metadata")
	if userFlagDebugMode {
		fmt.Printf("metadataPath: %s\n", metadataPath)
	}

	_, err := os.Stat(metadataPath)
	if errors.Is(err, os.ErrNotExist) {
		_, _ = fmt.Fprintln(os.Stderr, "error: not a backup (missing .backup.metadata)")
		os.Exit(1)
	} else if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "error: failed to stat %q: %s\n", metadataPath, err)
		os.Exit(1)
	}

	metadataFile, err := os.Open(metadataPath)
	if userFlagDebugMode {
		fmt.Printf("metadataFile: %s\n", metadataFile)
	}
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "error: failed to open %q: %s\n", metadataPath, err)
		os.Exit(1)
	}
	defer func() {
		_ = metadataFile.Close()
	}()

	metadataReader := bufio.NewReader(metadataFile)
	if userFlagDebugMode {
		fmt.Printf("metadataReader: %s\n", metadataReader)
	}

	version, err := metadataReader.ReadByte()
	if userFlagDebugMode {
		fmt.Printf("userPath: %s\n", version)
	}
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "error: failed to read version from %q: %s\n", metadataPath, err)
		os.Exit(1)
	}
	if version != 1 {
		_, _ = fmt.Fprintf(os.Stderr, "error: unsupported version %d (only version 1 is supported)\n", version)
		os.Exit(1)
	}

	if userFlagDebugMode {
		fmt.Printf("version: %d\n", version)
	}

	backupName := filepath.Base(userPath)
	if userFlagDebugMode {
		fmt.Printf("backupName: %s\n", backupName)
	}

	token, err := strconv.ParseUint(backupName, 10, 64)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "error: failed to parse backup name %q: %s\n", backupName, err)
		os.Exit(1)
	}

	if userFlagDebugMode {
		fmt.Printf("token: %d\n", token)
	}

	seed, err := mnemonicToSeed(userPhrase)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "error: failed to read seed from mnemonic: %s\n", err)
		os.Exit(1)
	}
	if userFlagDebugMode {
		fmt.Printf("seed: %s\n", hex.EncodeToString(seed))
	}

	key := hkdfExpand(seed[32:], []byte("app data key"), 32)
	if userFlagDebugMode {
		fmt.Printf("key: %s\n", hex.EncodeToString(key))
	}

	associatedData := make([]byte, 10)
	associatedData[0] = version
	binary.BigEndian.PutUint64(associatedData[2:], token)
	if userFlagDebugMode {
		fmt.Printf("associatedData: %s\n", associatedData)
	}
	metadataBytes, err := decrypt(metadataReader, key, associatedData)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "error: failed to decrypt metadata: %s\n", err)
		os.Exit(1)
	}
	if userFlagDebugMode {
		fmt.Printf("metadata: %s\n", string(metadataBytes))
	}

	var metadataMap map[string]json.RawMessage
	if err := json.Unmarshal(metadataBytes, &metadataMap); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "error: failed to unmarshal metadata: %s\n", err)
		os.Exit(1)
	}

	metadataMetaBytes, ok := metadataMap["@meta@"]
	if userFlagDebugMode {
		fmt.Printf("metadataMetaBytes: %s\n", metadataMetaBytes)
	}
	if !ok {
		_, _ = fmt.Fprintf(os.Stderr, "error: missing @meta@ key\n")
		os.Exit(1)
	}
	var metadataMeta struct {
		Version byte   `json:"version"`
		Salt    string `json:"salt"`
	}
	if userFlagDebugMode {
		fmt.Printf("metadataMeta: %s\n", metadataMeta)
	}
	if err := json.Unmarshal(metadataMetaBytes, &metadataMeta); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "error: failed to unmarshal @meta@: %s\n", err)
		os.Exit(1)
	}
	if userFlagDebugMode {
		fmt.Printf("metadataMeta.Version: %s\n", metadataMeta.Version)
	}

	if metadataMeta.Version != version {
		_, _ = fmt.Fprintf(os.Stderr, "error: @meta@ version %d does not match metadata file version %d\n", metadataMeta.Version, version)
		os.Exit(1)
	}

	if userFlagCheckOnly {
		fmt.Printf("CHECK-MODE ENABLED: extract on '%s' stopped before deploying %d packages\n", backupName, len(metadataMap))
		os.Exit(0)
    }

	if userFlagDebugMode {
		fmt.Printf("metadataMap: %s\n", metadataMap)
		fmt.Println("---- STARTING LOOP ----")
	}

	for packageName, packageMetaBytes := range metadataMap {
		if userPackage != "" {
			if userPackage == packageName {
				if userFlagDebugMode {
					fmt.Printf("    found %s package\n",packageName,userPackage)
				}
			} else {
				if userFlagDebugMode {
					fmt.Printf("    skipping %s package (does not match '%s')\n",packageName,userPackage)
				}
				continue
			}
		}

		if userFlagDebugMode {
			fmt.Printf("  packageName: %s\n", packageName)
		}

		if packageName == "@meta@" {
			if userFlagDebugMode {
				fmt.Println("    skipping @meta@ package")
			}
			continue
		}
		if packageName == "@end@" {
			if userFlagDebugMode {
				fmt.Println("    skipping @end@ package")
			}
			continue
		}

		err = func() error {
			var packageMeta struct {
				BackupType string `json:"backupType"`
				State      string `json:"state"`
			}
			if err := json.Unmarshal(packageMetaBytes, &packageMeta); err != nil {
				return fmt.Errorf("    failed to unmarshal metadata: %w", err)
			}
			if userFlagListPackages {
				if packageMeta.State != "" {
					fmt.Printf("    %s (%s)\n", packageName, packageMeta.State)
				} else {
					fmt.Printf("    %s\n", packageName)
				}
				return nil
			}
			if packageMeta.State != "" {
				fmt.Printf("    skipping %q (unsupported state %q)\n", packageName, packageMeta.State)
				return nil
			}
			if packageMeta.BackupType != "KV" && packageMeta.BackupType != "FULL" {
				fmt.Printf("    skipping %q (unsupported backup type %q)\n", packageName, packageMeta.BackupType)
				return nil
			}

			h := sha256.Sum256([]byte(metadataMeta.Salt + packageName))
			packagePath := filepath.Join(userPath, base64.RawURLEncoding.EncodeToString(h[:]))
			if userFlagDebugMode {
				fmt.Printf("    packagePath: %s", packagePath)
			}
			packageFile, err := os.Open(packagePath)
			if userFlagDebugMode {
				fmt.Printf("    packageFile: %s", packageFile)
			}
			if err != nil {
				return fmt.Errorf("    failed to open %q: %w", packagePath, err)
			}
			defer func() {
				_ = packageFile.Close()
			}()

			packageReader := bufio.NewReader(packageFile)
			packageVersion, err := packageReader.ReadByte()
			if err != nil {
				return fmt.Errorf("    failed to read version from %q: %w", packagePath, err)
			}
			if packageVersion != version {
				return fmt.Errorf("    %q version %d does not match metadata file version %d", packagePath, packageVersion, version)
			}

			var type_ byte
			if userFlagDebugMode {
				fmt.Printf("    packageMeta.BackupType = %s", packageMeta.BackupType)
			}
			if packageMeta.BackupType == "KV" {
				type_ = typeKVBackup
			} else {
				type_ = typeFullBackup
			}

			packageBytes, err := decrypt(packageReader, key, getAdditionalData(version, type_, packageName))
			if err != nil {
				return fmt.Errorf("    failed to decrypt %q: %w", packagePath, err)
			}

			var ext string
			if packageMeta.BackupType == "KV" {
				r, err := gzip.NewReader(bytes.NewReader(packageBytes))
				if err != nil {
					return fmt.Errorf("    failed to decompress %q: %w", packagePath, err)
				}
				if packageBytes, err = io.ReadAll(r); err != nil {
					return fmt.Errorf("    failed to decompress %q: %w", packagePath, err)
				}
				ext = ".sqlite"
			} else {
				ext = ".tar"
			}

			outPath := packageName + ext
			if err := os.WriteFile(outPath, packageBytes, 0777); err != nil {
				return fmt.Errorf("    failed to write %q: %w", outPath, err)
			}
			fmt.Printf("    extracting %s\n",outPath)
			return nil
		}()
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "    warning: failed to extract %q: %s\n", packageName, err)
		}
	}
}

func mnemonicToSeed(mnemonic string) ([]byte, error) {
	phrases := strings.Split(mnemonic, " ")

	if len(phrases) != 12 {
		return nil, fmt.Errorf("12 mnemonics needed, yet %d given", len(phrases))
	}

	for _, phrase := range phrases {
		if _, ok := internal.Bip39Words[phrase]; !ok {
			return nil, fmt.Errorf("invalid mnemonic given (case-sensitive): %s", phrase)
		}
	}

	return pbkdf2.Key([]byte(mnemonic), []byte("mnemonic"), 2048, 64, sha512.New), nil
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

func printHelp() {
	execName := filepath.Base(os.Args[0])
	fmt.Printf("usage: %s [PATH] [MNEMONIC] [optional]\n", execName)
	fmt.Println("    PATH      should be a 13-digit folder name (inside .SeedVaultAndroidBackup)")
	fmt.Println("    MNEMONIC  should be a twelve word phrase")
	fmt.Println("")
	fmt.Println("    Optional arguments include:")
	fmt.Println("       --check    confirms that the backup metadata is valid, but does not extract the data")
	fmt.Println("       --list     lists the package names only, but does not extract the data")
	fmt.Println("       --debug    enables excessive amounts of output *INCLUDING SENSITIVE DATA, LIKE KEYS AND PHRASES*")
	fmt.Println("       --package  specifies a Android package name -- all others will be skipped")
	fmt.Println("")
	fmt.Println("    Example usage:")
	fmt.Printf("         %s my_backups/.SeedVaultAndroidBackup/1708344900209 'buzz float culture lake paper season amused rain marine promote coyote mechanic' --list\n",execName)
	fmt.Printf("         %s my_backups/.SeedVaultAndroidBackup/1708344900209 'buzz float culture lake paper season amused rain marine promote coyote mechanic' --check\n",execName)
	fmt.Printf("         %s my_backups/.SeedVaultAndroidBackup/1708344900209 'buzz float culture lake paper season amused rain marine promote coyote mechanic' --package com.android.contacts\n",execName)
	fmt.Println("")
	os.Exit(1)
}
