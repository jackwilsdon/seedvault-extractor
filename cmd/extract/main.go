package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/pbkdf2"
	"io"
	"os"
	"path/filepath"
	"strconv"
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
			if packageMeta.BackupType != "FULL" {
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

			fullAdditionalData := make([]byte, 2+len(packageName))
			fullAdditionalData[0] = version
			fullAdditionalData[1] = 2
			copy(fullAdditionalData[2:], packageName)
			packageBytes, err := decrypt(packageReader, key, fullAdditionalData)
			if err != nil {
				return fmt.Errorf("failed to decrypt %q: %w", packagePath, err)
			}

			tarPath := packageName + ".tar"
			if err := os.WriteFile(tarPath, packageBytes, 0777); err != nil {
				return fmt.Errorf("failed to write %q: %w", tarPath, err)
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

const (
	subKeySizeBytes      byte = 32
	noncePrefixSizeBytes byte = 7
	segmentSizeBytes          = 1 << 20
	tagSizeBytes              = 16
)

func decrypt(r *bufio.Reader, key []byte, associatedData []byte) ([]byte, error) {
	expectedHeaderLength := 1 + subKeySizeBytes + noncePrefixSizeBytes
	if headerLength, err := r.ReadByte(); err != nil {
		return nil, fmt.Errorf("failed to read header length: %w", err)
	} else if headerLength != expectedHeaderLength {
		return nil, fmt.Errorf("malformed header (expected length to be %d bytes, got %d)", expectedHeaderLength, headerLength)
	}

	// Subtracting 1 as we've already read the length.
	header := make([]byte, expectedHeaderLength-1)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, fmt.Errorf("failed to read header: %w", err)
	}

	salt := header[:subKeySizeBytes]
	derivedKey := make([]byte, subKeySizeBytes)
	if _, err := io.ReadFull(hkdf.New(sha256.New, key, salt, associatedData), derivedKey); err != nil {
		return nil, fmt.Errorf("failed to derive key: %w", err)
	}
	aesCipher, err := aes.NewCipher(derivedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}
	aesGCMCipher, err := cipher.NewGCMWithTagSize(aesCipher, tagSizeBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM cipher: %w", err)
	}

	// Add 1 to read an extra byte to detect the last segment.
	segment := make([]byte, segmentSizeBytes+1)
	var fullPlaintext []byte
	var segmentIndex uint32
	noncePrefix := header[subKeySizeBytes:]
	for {
		var end int
		if segmentIndex == 0 {
			// First segment is shorter by the length of the header.
			end, err = io.ReadFull(r, segment[:len(segment)-int(expectedHeaderLength)])
		} else {
			// We read 1 extra byte in the first segment, which offset all
			// subsequent reads by a byte. The last byte of the previous
			// segment is at segment[0], so we read into the slice after this
			// to get the full segment.
			end, err = io.ReadFull(r, segment[1:])
			end += 1
		}

		var lastSegment bool
		if errors.Is(err, io.ErrUnexpectedEOF) {
			// As we always over-read by 1 byte, an unexpected EOF indicates
			// that this is the last segment.
			lastSegment = true
		} else if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, fmt.Errorf("failed to read segment %d: %w", segmentIndex, err)
		} else {
			// This isn't the last segment, meaning we've now read one extra
			// byte that is part of the next segment. Subtract 1 from the
			// number of bytes read to avoid including the extra byte in this
			// segment.
			end -= 1
		}

		// 4 bytes for index, 1 byte for last segment marker.
		nonce := make([]byte, len(noncePrefix)+5)
		copy(nonce, noncePrefix)
		binary.BigEndian.PutUint32(nonce[len(noncePrefix):], segmentIndex)
		if lastSegment {
			nonce[len(noncePrefix)+4] = 1
		}

		plaintext, err := aesGCMCipher.Open(nil, nonce, segment[:end], nil)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt segment %d: %w", segmentIndex, err)
		}
		fullPlaintext = append(fullPlaintext, plaintext...)

		if lastSegment {
			return fullPlaintext, nil
		} else {
			segment[0] = segment[end]
		}

		segmentIndex++
	}
}
