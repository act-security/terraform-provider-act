BINARY := terraform-provider-act
VERSION ?= dev
LDFLAGS := -s -w -X main.version=$(VERSION)
DEV_TAGS := -tags actinternal
ACT_INTERNAL_STS ?=
ACT_INTERNAL_API ?=
RC_BASE ?= $(shell jq -r '.["."] // "0.0.0"' .release-please-manifest.json 2>/dev/null || echo 0.0.0)
export RC_BASE
GO_VERSION := $(shell sed -n 's/^go = "\(.*\)"/\1/p' mise.toml)
TERRAFORM_VERSION := $(shell sed -n 's/^terraform = "\(.*\)"/\1/p' mise.toml)
INTERNAL_LDFLAGS := -X github.com/act-security/terraform-provider-act/internal/auth.internalSTSOrigin=$(ACT_INTERNAL_STS) -X github.com/act-security/terraform-provider-act/internal/auth.internalAPIOrigin=$(ACT_INTERNAL_API)
GENERATED := internal/apigen internal/fakeapi/gen
CONTRACT := api/openapi.json
CONTRACT_LOCK := api/openapi.lock
CONTRACT_URL ?=
PROVIDER_ADDRESS ?= registry.terraform.io/act-security/act
TARGET ?= fake
TF ?= terraform
DEV_TFRC := dev/.terraformrc
FAKE_ADDR ?= 127.0.0.1:8787
FAKE_API_ADDR ?= 127.0.0.1:8788
RUN ?= .

GOBIN := $(shell go env GOBIN)
ifeq ($(GOBIN),)
GOBIN := $(shell go env GOPATH)/bin
endif

export CGO_ENABLED := 0
export TF_ACC_PROVIDER_NAMESPACE ?= act-security
export TF_ACC_PROVIDER_HOST ?= registry.terraform.io

.DEFAULT_GOAL := check

.PHONY: check
check: tidy-check fmt-check lint generate-check test sec build docs-check release-check workflow-lint

.PHONY: fmt
fmt:
	golangci-lint fmt

.PHONY: fmt-check
fmt-check:
	@out="$$(golangci-lint fmt --diff)"; \
	if [ -n "$$out" ]; then echo "$$out"; echo "Unformatted files. Run: make fmt"; exit 1; fi

.PHONY: lint
lint:
	golangci-lint run ./...
	golangci-lint run --build-tags actinternal ./...
	golangci-lint run --build-tags e2e ./e2e/...
	@if grep -rn --include='*.go' --exclude-dir=apigen --exclude-dir=gen '//nolint' . ; then \
		echo "//nolint is not allowed: restructure the code instead"; exit 1; fi

.PHONY: test
test:
	CGO_ENABLED=1 go test -race -covermode=atomic -coverprofile=coverage.out ./...
	CGO_ENABLED=1 go test $(DEV_TAGS) -race ./...

.PHONY: sec
sec: gosec vulncheck

.PHONY: gosec
gosec:
	gosec -quiet -severity low -confidence low -exclude-generated ./...

.PHONY: vulncheck
vulncheck:
	govulncheck ./...

.PHONY: tidy
tidy:
	go mod tidy

.PHONY: tidy-check
tidy-check:
	@cp go.mod go.mod.bak && cp go.sum go.sum.bak
	@go mod tidy
	@status=0; \
	if ! diff -q go.mod go.mod.bak >/dev/null || ! diff -q go.sum go.sum.bak >/dev/null; then \
		echo "go.mod or go.sum is not tidy. Run: make tidy"; status=1; \
	fi; \
	mv go.mod.bak go.mod && mv go.sum.bak go.sum; \
	exit $$status

.PHONY: generate
generate:
	oapi-codegen -config internal/apigen/oapi-codegen.yaml $(CONTRACT)
	oapi-codegen -config internal/fakeapi/gen/oapi-codegen.yaml $(CONTRACT)

.PHONY: lock-check
lock-check:
	@want="$$(sed -n 's/^sha256: //p' $(CONTRACT_LOCK))"; \
	got="$$(shasum -a 256 $(CONTRACT) | cut -d' ' -f1)"; \
	if [ "$$want" != "$$got" ]; then echo "$(CONTRACT) does not match $(CONTRACT_LOCK). Run: make contract-sync"; exit 1; fi

.PHONY: generate-check
generate-check: lock-check generate
	@if [ -n "$$(git status --porcelain -- $(GENERATED))" ]; then \
		git --no-pager diff -- $(GENERATED); \
		echo "Generated code is stale. Run: make generate and commit the result"; exit 1; fi

.PHONY: contract-sync
contract-sync:
	@test -n '$(CONTRACT_URL)' || { echo 'Set CONTRACT_URL to the public API origin followed by /v1/openapi.json'; exit 1; }
	curl -fsS --proto =https --max-time 30 $(CONTRACT_URL) | jq --indent 2 . > $(CONTRACT).tmp
	mv $(CONTRACT).tmp $(CONTRACT)
	printf 'version: %s\nsha256: %s\n' "$$(jq -r .info.version $(CONTRACT))" "$$(shasum -a 256 $(CONTRACT) | cut -d' ' -f1)" > $(CONTRACT_LOCK)
	$(MAKE) generate

.PHONY: build
build:
	go build -trimpath -ldflags '$(LDFLAGS)' -o $(BINARY) .

.PHONY: docs
docs:
	tfplugindocs generate --provider-name act

.PHONY: docs-check
docs-check: docs
	tfplugindocs validate --provider-name act
	@if [ -n "$$(git status --porcelain -- docs)" ]; then \
		git --no-pager diff -- docs; \
		echo "docs/ differs from the committed version. Run: make docs and commit it"; exit 1; fi

.PHONY: release-check
release-check:
	goreleaser check
	$(MAKE) rc

.PHONY: rc
rc:
	goreleaser release --snapshot --clean --skip=sign

.PHONY: e2e
e2e: rc
	go test -tags e2e -count=1 -v ./e2e/

.PHONY: e2e-docker
e2e-docker: rc
	docker run --rm -v '$(CURDIR)':/src -w /src -e CGO_ENABLED=0 -e GOFLAGS=-buildvcs=false -e E2E_TERRAFORM_VERSION=$(TERRAFORM_VERSION) golang:$(GO_VERSION) go test -tags e2e -count=1 -v ./e2e/

.PHONY: rc-install
rc-install:
	@test -n '$(RUN)' || { echo 'Set RUN to the id of a CI run that built a release candidate'; exit 1; }
	scripts/rc-install.sh $(RUN)

.PHONY: workflow-lint
workflow-lint:
	actionlint
	zizmor --offline --min-severity medium .github/workflows

.PHONY: install
install:
	go install $(DEV_TAGS) -ldflags '$(INTERNAL_LDFLAGS)' .

.PHONY: fake
fake:
	go run ./internal/fakeapi/cmd/fakeapi -addr $(FAKE_ADDR) -api-addr $(FAKE_API_ADDR) $(if $(SCRIPT),-script $(SCRIPT))

.PHONY: debug
debug:
	TF_LOG=$${TF_LOG:-INFO} go run $(DEV_TAGS) -ldflags '$(INTERNAL_LDFLAGS)' . -debug -address $(PROVIDER_ADDRESS)

dev-%: install
	@printf 'provider_installation {\n  dev_overrides {\n    "registry.terraform.io/act-security/act" = "%s"\n  }\n  direct {}\n}\n' '$(GOBIN)' > $(DEV_TFRC)
	@test -f dev/env/$(TARGET).env || { echo "dev/env/$(TARGET).env is missing"; exit 1; }
	set -a && . ./dev/env/$(TARGET).env && set +a && cd dev/$(TARGET) && TF_CLI_CONFIG_FILE=$(CURDIR)/$(DEV_TFRC) $(TF) $* $(TF_ARGS)

.PHONY: testacc
testacc:
	TF_ACC=1 CGO_ENABLED=1 go test $(DEV_TAGS) -ldflags '$(INTERNAL_LDFLAGS)' -race -count=1 -timeout 120m -v -run '$(RUN)' ./internal/provider/

.PHONY: clean
clean:
	rm -f $(BINARY) coverage.out
	rm -rf dist/

.PHONY: help
help:
	@printf '%s\n' \
	  'check            tidy-check fmt-check lint generate-check test sec build docs-check release-check workflow-lint' \
	  'fmt              format in place (gofumpt and imports through golangci-lint)' \
	  'lint             golangci-lint for the release, actinternal and e2e tag sets; bans //nolint' \
	  'test             unit and fake API tests with -race, release tags then actinternal' \
	  'sec              gosec and govulncheck' \
	  'generate         oapi-codegen client and fake server from api/openapi.json' \
	  'contract-sync    refresh api/openapi.json and its lock from CONTRACT_URL, then generate' \
	  'build            release-identical binary, no actinternal tag' \
	  'docs             regenerate docs/ with tfplugindocs' \
	  'release-check    goreleaser check, then rc' \
	  'rc               release candidate: snapshot zips of 6 platforms in dist/, release guard on each binary' \
	  'e2e              rc, then the end-to-end suite against the zip for this machine (full on Linux, smoke elsewhere)' \
	  'e2e-docker       rc, then the full end-to-end suite in a Linux container (for macOS)' \
	  'rc-install       install the release candidate from CI run RUN into .rc/ for manual testing' \
	  'workflow-lint    actionlint and zizmor over .github/workflows' \
	  'fake             run the fake STS and API on loopback (SCRIPT=file for canned responses)' \
	  'dev-<cmd>        install an actinternal build and run TF <cmd> in dev/TARGET (TARGET=fake|local)' \
	  'debug            run the provider under -debug for a debugger to attach' \
	  'testacc          TF_ACC tests, actinternal build (RUN=regexp)'
