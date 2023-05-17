#!/usr/bin/env bash

build() {
	mkdir -p release
	GOOS=$1 GOARCH=$2 go build -trimpath -o release/seedvault-extractor-$1-$2$3 ./cmd/extract
}

build windows amd64 .exe
build linux amd64
build darwin amd64
build darwin arm64
