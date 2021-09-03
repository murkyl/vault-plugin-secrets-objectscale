GOARCH = amd64
UNAME = $(shell uname -s)
PLUGIN_NAME = vault-plugin-secrets-objectscale
ACCESS_PATH = onefs

ifndef OS
	ifeq ($(UNAME), Linux)
		OS = linux
	else ifeq ($(UNAME), Darwin)
		OS = darwin
	endif
endif

.DEFAULT_GOAL := all

all: fmt build

build:
	mkdir -p bin
	GOOS=$(OS) GOARCH="$(GOARCH)" go build -o bin/${PLUGIN_NAME} cmd/${PLUGIN_NAME}/main.go

start_dev:
	vault server -dev -dev-root-token-id=root -dev-plugin-dir=./bin

enable:
	vault secrets enable -path=${ACCESS_PATH} ${PLUGIN_NAME}

clean:
	rm -f ./bin/${PLUGIN_NAME}

fmt:
	go fmt $$(go list ./...)

.PHONY: build clean fmt start_dev enable
