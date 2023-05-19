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
	"google.golang.org/protobuf/proto"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	typeKVBackup   = 1
	typeFullBackup = 2
)

var debug = os.Getenv("DEBUG") == "1"

func main() {
	if len(os.Args) != 3 {
		_, _ = fmt.Fprintf(os.Stderr, "usage: %s path-to-backup mnemonic\n", filepath.Base(os.Args[0]))
		os.Exit(1)
	}

	backupPath := os.Args[1]
	// err := extractAppBackup(backupPath)
	err := extractFileBackup(backupPath)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "error: %s\n", err)
		os.Exit(1)
	}
}

var folderRegex = regexp.MustCompile("^[a-f0-9]{16}\\.sv$")
var chunkFolderRegex = regexp.MustCompile("^[a-f0-9]{2}$")
var chunkRegex = regexp.MustCompile("^[a-f0-9]{64}$")
var snapshotRegex = regexp.MustCompile("^([0-9]{13})\\.SeedSnap$")

type storedSnapshotT struct {
	time      string
	timestamp uint64
	path      string
}

const TypeChunk byte = 0x0
const TypeSnapshot byte = 0x1

func extractFileBackup(backupPath string) error {
	backupName := filepath.Base(backupPath)

	seed, err := mnemonicToSeed(os.Args[2])
	if err != nil {
		return fmt.Errorf("failed to read seed from mnemonic: %s\n", err)
	}
	if debug {
		fmt.Printf("seed: %s\n", hex.EncodeToString(seed))
	}

	key := hkdfExpand(seed[32:], []byte("stream key"), 32)
	if debug {
		fmt.Printf("key: %s\n", hex.EncodeToString(key))
	}

	if !folderRegex.MatchString(backupName) {
		return fmt.Errorf("unexpected folder name: %s\n", backupName)
	}

	var chunkFolderFiles []fs.DirEntry
	var storedSnapshots []storedSnapshotT

	chunkFolders, _ := os.ReadDir(backupPath)
	for _, chunkFolder := range chunkFolders {
		if chunkFolderRegex.MatchString(chunkFolder.Name()) {
			chunkFolderFiles = append(chunkFolderFiles, chunkFolder)
			if !chunkFolder.IsDir() {
				return fmt.Errorf("unexpected file at chunk folder level: %s/%s\n", backupPath, chunkFolder.Name())
			}
			//chunkFiles, _ := os.ReadDir(backupPath + "/" + chunkFolder.Name())
			//for _, chunkFile := range chunkFiles {
			//	fmt.Println("chunkFile " + chunkFile.Name())
			//}
		} else if snapshotRegex.MatchString(chunkFolder.Name()) {
			if chunkFolder.IsDir() {
				return fmt.Errorf("unexpected folder: %s\n", chunkFolder.Name())
			}
			timestamp, err := strconv.ParseUint(snapshotRegex.FindStringSubmatch(chunkFolder.Name())[1], 10, 64)
			if err != nil {
				return err
			}
			tm := time.Unix(int64(timestamp/1000), 0)

			fmt.Printf("storedSnapshot: %v\n", timestamp)
			fmt.Printf("storedSnapshot: %s - %s\n", tm, backupPath+"/"+chunkFolder.Name())
			storedSnapshots = append(storedSnapshots, storedSnapshotT{
				time:      tm.String(),
				timestamp: timestamp,
				path:      backupPath + "/" + chunkFolder.Name(),
			})

		} else {
			return fmt.Errorf("unexpected file/folder: %s\n", chunkFolder.Name())
		}
	}

	storedSnapshot := storedSnapshots[0]
	metadataPath := storedSnapshot.path

	s, err := os.Stat(metadataPath)
	if errors.Is(err, os.ErrNotExist) {
		_, _ = fmt.Fprintln(os.Stderr, "error: not a backup (missing .SeedSnap)")
	} else if err != nil {
		return fmt.Errorf("failed to stat %q: %s\n", metadataPath, err)
	} else if s.Size() == 0 {
		return fmt.Errorf("empty file %q\n", metadataPath)
	}

	metadataFile, err := os.Open(metadataPath)
	if err != nil {
		return fmt.Errorf("failed to open %q: %s\n", metadataPath, err)
	}
	defer func() {
		_ = metadataFile.Close()
	}()

	metadataReader := bufio.NewReader(metadataFile)
	version, err := metadataReader.ReadByte()
	if err != nil {
		return fmt.Errorf("failed to read version from %q: %s\n", metadataPath, err)
	}
	if version != 1 {
		//return fmt.Errorf("unsupported version %d (only version 1 is supported)\n", version)
	}
	if debug {
		fmt.Printf("version: %d\n", version)
	}

	associatedData := make([]byte, 10)
	associatedData[0] = version
	associatedData[1] = TypeSnapshot
	binary.BigEndian.PutUint64(associatedData[2:], storedSnapshot.timestamp)
	metadataBytes, err := decrypt(metadataReader, key, associatedData)
	if err != nil {
		return fmt.Errorf("failed to decrypt metadata: %s\n", err)
	}

	var metadata internal.BackupSnapshot
	err = proto.Unmarshal(metadataBytes, &metadata)
	if err != nil {
		return err
	}
	if debug {
		fmt.Printf("metadata: %v\n", metadata)
	}

	return nil
}

func extractAppBackup(backupPath string) error {
	metadataPath := filepath.Join(backupPath, ".backup.metadata")
	_, err := os.Stat(metadataPath)
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("not a backup (missing .backup.metadata)")
	} else if err != nil {
		return fmt.Errorf("failed to stat %q: %s\n", metadataPath, err)
	}

	metadataFile, err := os.Open(metadataPath)
	if err != nil {
		return fmt.Errorf("failed to open %q: %s\n", metadataPath, err)
	}
	defer func() {
		_ = metadataFile.Close()
	}()

	metadataReader := bufio.NewReader(metadataFile)
	version, err := metadataReader.ReadByte()
	if err != nil {
		return fmt.Errorf("failed to read version from %q: %s\n", metadataPath, err)
	}
	if version != 1 {
		return fmt.Errorf("unsupported version %d (only version 1 is supported)\n", version)
	}

	if debug {
		fmt.Printf("version: %d\n", version)
	}

	backupName := filepath.Base(backupPath)
	token, err := strconv.ParseUint(backupName, 10, 64)
	if err != nil {
		return fmt.Errorf("failed to parse backup name %q: %s\n", backupName, err)
	}

	if debug {
		fmt.Printf("token: %d\n", token)
	}

	seed, err := mnemonicToSeed(os.Args[2])
	if err != nil {
		return fmt.Errorf("failed to read seed from mnemonic: %s\n", err)
	}
	if debug {
		fmt.Printf("seed: %s\n", hex.EncodeToString(seed))
	}

	key := hkdfExpand(seed[32:], []byte("app data key"), 32)
	if debug {
		fmt.Printf("key: %s\n", hex.EncodeToString(key))
	}

	associatedData := make([]byte, 10)
	associatedData[0] = version
	associatedData[1] = TypeChunk
	binary.BigEndian.PutUint64(associatedData[2:], token)
	metadataBytes, err := decrypt(metadataReader, key, associatedData)
	if err != nil {
		return fmt.Errorf("failed to decrypt metadata: %s\n", err)
	}
	if debug {
		fmt.Printf("metadata: %s\n", string(metadataBytes))
	}

	var metadataMap map[string]json.RawMessage
	if err := json.Unmarshal(metadataBytes, &metadataMap); err != nil {
		return fmt.Errorf("failed to unmarshal metadata: %s\n", err)
	}

	metadataMetaBytes, ok := metadataMap["@meta@"]
	if !ok {
		return fmt.Errorf("missing @meta@ key\n")
	}
	var metadataMeta struct {
		Version byte   `json:"version"`
		Salt    string `json:"salt"`
	}
	if err := json.Unmarshal(metadataMetaBytes, &metadataMeta); err != nil {
		return fmt.Errorf("failed to unmarshal @meta@: %s\n", err)
	}
	if metadataMeta.Version != version {
		return fmt.Errorf("@meta@ version %d does not match metadata file version %d\n", metadataMeta.Version, version)
	}

	for packageName, packageMetaBytes := range metadataMap {
		if packageName == "@meta@" {
			continue
		}
		if packageName == "@end@" {
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
			fmt.Println(outPath)
			return nil
		}()
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "warning: failed to extract %q: %s\n", packageName, err)
		}
	}
	return nil
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
