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

	// https://github.com/seedvault-app/seedvault/blob/8bea1be06067eda9c18d984f94f6b1787f2e9614/storage/lib/src/main/java/org/calyxos/backup/storage/plugin/SnapshotRetriever.kt#L29
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

	err = restoreBackupSnapshot(storedSnapshot, metadata)
	if err != nil {
		return err
	}

	return nil
}

type RestorableFile struct {
	mediaFile *internal.BackupMediaFile
	docFile   *internal.BackupDocumentFile
}
type RestorableChunk struct {
	chunkId string
	files   []RestorableFile
}

func restoreBackupSnapshot(storedSnapshot storedSnapshotT, metadata internal.BackupSnapshot) error {
	filesTotal := len(metadata.MediaFiles) + len(metadata.DocumentFiles)
	fmt.Println("filesTotal ", filesTotal)

	totalSize := int64(0)
	for _, file := range metadata.MediaFiles {
		totalSize += file.Size
	}
	for _, file := range metadata.DocumentFiles {
		totalSize += file.Size
	}
	fmt.Println("totalSize ", totalSize)

	zipChunkMap := map[string]*RestorableChunk{}
	chunkMap := map[string]*RestorableChunk{}

	for _, mediaFile := range metadata.MediaFiles {
		fmt.Printf("MF %s/%s %d %s\n", mediaFile.Path, mediaFile.Name, mediaFile.Size, mediaFile.ChunkIds)

		if mediaFile.ZipIndex > 0 {
			if len(mediaFile.ChunkIds) != 1 {
				return fmt.Errorf("more than 1 zip chunk: %s", mediaFile.Name)
			}
			chunkId := mediaFile.ChunkIds[0]
			zipChunk, ok := zipChunkMap[chunkId]
			if !ok {
				zipChunk = &RestorableChunk{chunkId: chunkId}
				zipChunkMap[chunkId] = zipChunk
			}
			zipChunk.files = append(zipChunk.files, RestorableFile{mediaFile: mediaFile})
		} else {
			for _, chunkId := range mediaFile.ChunkIds {
				chunk, ok := chunkMap[chunkId]
				if !ok {
					chunk = &RestorableChunk{chunkId: chunkId}
					chunkMap[chunkId] = chunk
				}
				chunk.files = append(chunk.files, RestorableFile{mediaFile: mediaFile})
			}
		}
	}
	fmt.Printf("%d non zip chunks found\n", len(chunkMap))

	//for _, docFile := range metadata.MediaFiles {
	//	fmt.Printf("DF %s/%s %d %s\n", docFile.Path, docFile.Name, docFile.Size, docFile.ChunkIds)
	//
	//	if docFile.ZipIndex > 0 {
	//		if len(docFile.ChunkIds) != 1 {
	//			return fmt.Errorf("more than 1 zip chunk: %s", docFile.Name)
	//		}
	//		chunkId := docFile.ChunkIds[0]
	//		zipChunk, ok := zipChunkMap[chunkId]
	//		if !ok {
	//			zipChunk = &RestorableChunk{chunkId: chunkId}
	//			zipChunkMap[chunkId] = zipChunk
	//		}
	//		zipChunk.files = append(zipChunk.files, RestorableFile{mediaFile: docFile})
	//	} else {
	//		for _, chunkId := range docFile.ChunkIds {
	//			chunk, ok := chunkMap[chunkId]
	//			if !ok {
	//				chunk = &RestorableChunk{chunkId: chunkId}
	//				chunkMap[chunkId] = chunk
	//			}
	//			chunk.files = append(chunk.files, RestorableFile{mediaFile: docFile})
	//		}
	//	}
	//}
	//fmt.Printf("%d non zip chunks found\n", len(chunkMap))

	fmt.Printf("%d zip chunks found\n", len(zipChunkMap))
	var singleChunks []*RestorableChunk
	var multiChunks []*RestorableChunk
	for _, chunk := range chunkMap {
		//fmt.Printf("%v %d %v\n", x, len(chunk.files), chunk.files)
		if len(chunk.files) == 1 {
			singleChunks = append(singleChunks, chunk)
		} else {
			multiChunks = append(multiChunks, chunk)
		}
	}

	fmt.Printf("Extracting %d zip chunks\n", len(zipChunkMap))
	//for _, zipChunk := range zipChunkMap {
	//
	//	decryptedStream := getAndDecryptChunk(version, storedSnapshot, zipChunk.chunkId)
	//
	//	reader, err := zip.NewReader(decryptedStream, -1)
	//	if err != nil {
	//		return err
	//	}
	//	for _, zipEntry := range reader {
	//		//restoreZipEntry
	//		while (entry != null && entry.name != file.zipIndex.toString()) {
	//			entry = zip.nextEntry
	//		}
	//		check(entry != null) { "zip entry was null for: $file" }
	//		restoreFile(file, observer, "S") { outputStream: OutputStream ->
	//			val bytes = zip.copyTo(outputStream)
	//			zip.closeEntry()
	//			bytes
	//		}
	//		if err != nil {
	//			fmt.Printf("failed to extract small file %s\n", zipEntry)
	//		}
	//	}
	//}

	chunkFolder := filepath.Join(storedSnapshot.path, "..")

	fmt.Printf("Extracting %d single chunks\n", len(singleChunks))
	for _, singleChunk := range singleChunks {
		if len(singleChunk.files) != 1 {
			return fmt.Errorf("unexpected number of files in single chunk: %d", len(singleChunk.files))
		}

		err := restoreSingleChunk(chunkFolder, singleChunk.chunkId, singleChunk.files[0])
		if err != nil {
			return err
		}
	}

	fmt.Printf("Extracting %d multi chunks\n", len(multiChunks))
	//for _, multiChunk := range multiChunks {
	//}

	return nil
}

func restoreSingleChunk(chunkFolder, chunkId string, file RestorableFile) error {
	version := byte(0)

	targetFilePath := ""
	if file.mediaFile != nil {
		targetFilePath = file.mediaFile.Path + "/" + file.mediaFile.Name
	} else {
		targetFilePath = file.docFile.Path + "/" + file.docFile.Name
	}

	if debug {
		fmt.Printf("Decrypting single chunk file %q...\n", targetFilePath)
	}

	chunkFilepath := filepath.Join(chunkFolder, chunkId[:2], chunkId)
	chunkFile, err := os.Open(chunkFilepath)
	if err != nil {
		return fmt.Errorf("failed to open %q: %w", chunkFilepath, err)
	}
	defer func() { _ = chunkFile.Close() }()
	chunkReader := bufio.NewReader(chunkFile)

	chunkEncVersion, err := chunkReader.ReadByte()
	if err != nil {
		return fmt.Errorf("failed to read version from %q: %w", chunkFilepath, err)
	}
	if chunkEncVersion != version {
		return fmt.Errorf("%q chunk encryption version %d does not match expected version %d\n", chunkFilepath, chunkEncVersion, version)
	}

	token, err := hex.DecodeString(chunkId)
	if err != nil {
		return fmt.Errorf("failed to parse chunkId %q: %s\n", chunkId, err)
	}
	if len(token) != 32 {
		return fmt.Errorf("failed to parse token, wrong length %d: %q\n", len(token), token)
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

	streamKey := hkdfExpand(seed[32:], []byte("stream key"), int64(32))
	if debug {
		fmt.Printf("streamKey: %s\n", hex.EncodeToString(streamKey))
	}

	associatedData := make([]byte, 2+32)
	associatedData[0] = version
	associatedData[1] = TypeChunk
	copy(associatedData[2:], token)

	decryptedBytes, err := decrypt(chunkReader, streamKey, associatedData)
	if err != nil {
		return fmt.Errorf("failed to decrypt file chunk: %s\n", err)
	}
	if debug {
		fmt.Printf("decrypted file chunk length: %d\n", len(decryptedBytes))
	}

	outPath := filepath.Join(".", "decrypted", targetFilePath)
	err = os.MkdirAll(filepath.Dir(outPath), 0777)
	if err != nil {
		return err
	}

	err = os.WriteFile(outPath, decryptedBytes, 0777)
	if err != nil {
		return fmt.Errorf("failed to write %q: %w", outPath, err)
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
