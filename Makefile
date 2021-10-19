PLUGIN_NAME=vault-plugin-secrets-objectscale
VERSION=$(shell grep PluginVersion version.go | sed -E 's/.*"(.+)"/\1/')

.DEFAULT_GOAL := all

all: fmt build

build: build_linux build_mac build_windows

build_dir:
	mkdir -p bin

build_linux: build_linux_amd64 build_linux_arm

build_linux_amd64: | build_dir
	GOOS=linux GOARCH=amd64 go build -o bin/${PLUGIN_NAME}-linux-amd64-${VERSION} cmd/${PLUGIN_NAME}/main.go

build_linux_arm: | build_dir
	GOOS=linux GOARCH=arm go build -o bin/${PLUGIN_NAME}-linux-arm-${VERSION} cmd/${PLUGIN_NAME}/main.go

build_mac: build_mac_amd64

build_mac_amd64: | build_dir
	GOOS=darwin GOARCH=amd64 go build -o bin/${PLUGIN_NAME}-darwin-amd64-${VERSION} cmd/${PLUGIN_NAME}/main.go

build_windows: build_windows_amd64

build_windows_amd64: | build_dir
	GOOS=windows GOARCH=amd64 go build -o bin/${PLUGIN_NAME}-windows-amd64-${VERSION}.exe cmd/${PLUGIN_NAME}/main.go

source:
	mkdir -p source
	zip -r source/${PLUGIN_NAME}-${VERSION}.zip . -x "bin/*" -x "source/*"
	tar --exclude="bin" --exclude="source" --xform="s,^,${PLUGIN_NAME}-${VERSION}/," -zcvf source/${PLUGIN_NAME}-${VERSION}.tar.gz *

clean:
	rm -f ./bin/${PLUGIN_NAME}*
	rm -f ./source/${PLUGIN_NAME}*

fmt:
	go fmt $$(go list ./...)

.PHONY: clean fmt source build build_dir build_linux build_linux_amd64 build_linux_arm build_mac build_mac_amd64 build_windows build_windows_amd64
