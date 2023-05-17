# Seedvault backup extractor
A tool for extracting [Seedvault](https://github.com/seedvault-app/seedvault) backups.

**Note**: this tool only supports v1 backups. Use [tlambertz/seedvault_backup_parser](https://github.com/tlambertz/seedvault_backup_parser) for v0 backups.

## Usage
Download the latest version for your platform from the [releases](https://github.com/jackwilsdon/seedvault-extractor/releases) page and run it:

```Text
$ ./seedvault-extractor path-to-your-backup "your mnemonic here"
```

Note that you need to provide the path to a specific backup, not to the backups directory. For example:

```Text
.SeedVaultAndroidBackup
├╴ 1681333934634
├╴ 1681333947258
└╴ 3e72aa3b9c869632.sv
```

The above backups directory contains two backups, `1681333934634` and `1681333947258`. They can be extracted like so:

```Text
$ ./seedvault-extractor .SeedVaultAndroidBackup/1681333934634 "my mneumonic here"
$ ./seedvault-extractor .SeedVaultAndroidBackup/1681333947258 "my mneumonic here"
```

You can tell if a directory is a backup as it will contain a `.backup.metadata` file.

A `.tar` for each application in the backup will be extracted to the working directory.

## Notes
 * Extracting KV backups is currently unsupported.
 * This tool has only been tested on Linux. Please [let me know](https://github.com/jackwilsdon/seedvault-extractor/issues/new) how it's working for you on other platforms.
 * Additional debug output can be enabled by setting the `DEBUG` environment variable to `1`. Debug output may contain sensitive data!

## Building
You can build the extractor by running `go build ./cmd/extract` (with Go 1.20). This will place a compiled `extract` binary in the working directory.
