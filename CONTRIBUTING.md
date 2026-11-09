# Contributing

## Setup

```sh
mise trust && mise install
make check
```

`mise.toml` pins every tool and `mise.lock` pins their checksums for Linux, macOS and Windows. CI installs from the same files with `--locked`, so a green `make check` locally means a green CI run. After changing a tool version, run `mise lock --platform linux-x64,linux-arm64,macos-arm64,macos-x64,windows-x64`.

## Inner loop

The default target is an in-repo fake of the Act STS and public API, so no account or network is needed.

```sh
make fake
make dev-plan
make dev-apply TF_ARGS=-auto-approve
```

Run `make fake` in one shell and the `dev-*` targets in another. `make dev-<cmd>` installs a build with the `actinternal` tag and runs `<cmd>` in `dev/$(TARGET)` with `dev_overrides` for the provider. `make debug` starts the provider for a debugger; export the `TF_REATTACH_PROVIDERS` it prints before running `make dev-plan`. `SCRIPT=dev/fake-script.example.json make fake` replays canned responses. Against a non-production Act environment, set `ACT_INTERNAL_STS` and `ACT_INTERNAL_API` to its origins; `install`, `debug` and `testacc` link them into the `actinternal` build, which otherwise accepts only production, plus loopback when `ACT_ALLOW_UNSAFE_ENDPOINT=1`. Release builds accept only production and never read `ACT_ALLOW_UNSAFE_ENDPOINT`.

The `actinternal` tag is set only by `install`, `debug` and `testacc`. Release builds never carry it. GoReleaser runs `scripts/release-guard.sh` on every binary right after building it, before anything is archived, signed or uploaded, and the release fails if a binary carries the tag, was built without `-trimpath` or `CGO_ENABLED=0`, reads `ACT_ALLOW_UNSAFE_ENDPOINT`, or contains any string listed in `RELEASE_GUARD_FORBIDDEN`.

## Where changes go

| Change | Where |
|---|---|
| Public API contract | `CONTRACT_URL=<public API origin>/v1/openapi.json make contract-sync`, which refreshes `api/openapi.json`, its lock and the generated code. Never edit `internal/apigen` or `internal/fakeapi/gen` |
| Authentication | `internal/auth`, with tests for both build tags |
| A new resource or data source | `internal/provider`, its fake behavior in `internal/fakeapi`, its example and doc template (see below), then `make docs` |

## Docs and examples for every resource and data source

Every resource and data source ships with an example, a doc template and the generated doc. `make docs-rule` runs in `make check` and in CI, walks every resource and data source the provider registers, and fails when any of these files is missing or empty, when the generated doc does not show the example, or when a file names something the provider does not register.

| Kind | Files, for a type named `act_<name>` |
|---|---|
| Resource | `examples/resources/act_<name>/resource.tf`, `examples/resources/act_<name>/import.sh`, `templates/resources/<name>.md.tmpl`, `docs/resources/<name>.md` |
| Data source | `examples/data-sources/act_<name>/data-source.tf`, `templates/data-sources/<name>.md.tmpl`, `docs/data-sources/<name>.md` |

Start the template from a copy of `.github/doc-templates/resource.md.tmpl` or `.github/doc-templates/data-source.md.tmpl`. They live outside `templates/` because tfplugindocs renders every file there into `docs/`. Keep the example small enough to paste and valid on Terraform 1.5.7, except a write-only argument, which needs 1.11: then the template also shows the 1.5.7 way. A resource that takes a secret keeps the **Secrets** section and says which arguments are write-only, which Terraform version they need, how to rotate them and what reaches the state file. `docs/` is generated: run `make docs` and commit the result.

## Rules

- No comments in code, YAML, Makefiles or scripts. Put the reasoning in `MarkdownDescription` or the pull request. Build constraints (`//go:build`) and the `# vX.Y.Z` trailer on pinned actions are the only exceptions. `//nolint` is not allowed.
- Pull request titles are conventional commits. Pull requests are squash-merged, and release-please builds versions and the changelog from the titles.
- Never commit a real client secret, token or tenant credential.

## Pull requests from forks

CI does not build or test code from forks. The first job fails on a pull request from a fork and every other job is skipped, so no fork code is checked out or run, even after a maintainer approves the run.

To take a change from a fork, a maintainer reviews the diff, pushes the commits to a branch in this repository and opens a new pull request from that branch. CI runs there, and the original pull request is closed with a link to the new one. The contributor keeps authorship of the commits.

## Release candidates

`make rc` builds the release zips for all six platforms into `dist/` with the release configuration, under a version like `0.1.0-rc.g1a2b3c4`. The end-to-end suite in `e2e/` tests those zips the way a user gets them: Terraform installs the zip from a filesystem mirror under `registry.terraform.io/act-security/act` and talks to the in-repo fake, served over TLS as `auth.act.security` and `api.us1.act.security` with a CA created for the run. The provider reaches the fake through an `HTTPS_PROXY` that refuses every other host, and trusts the CA through `SSL_CERT_FILE`. The binary under test has no test hooks and needs no secrets.

| Command | What it runs |
|---|---|
| `make e2e` | `rc`, then the suite against the zip for this machine. Linux runs everything; macOS and Windows run the install and schema checks, because Go reads `SSL_CERT_FILE` only on Linux. |
| `make e2e-docker` | `rc`, then the full suite in a Linux container, for macOS laptops. |
| `make rc-install RUN=<id>` | downloads the `release-candidate` artifact of CI run `<id>`, checks its checksum and writes `.rc/terraformrc`. Export `TF_CLI_CONFIG_FILE` as printed and pin the printed version. |

CI builds the release candidate on every pull request and runs the full suite on Linux with Terraform 1.5.7 and the pinned Terraform. The release pull request and `main` also run it on macOS and Windows.

## Releases

Maintainers merge the release pull request that release-please opens, then approve the `release` environment. The environment must define the `RELEASE_GUARD_FORBIDDEN` secret (space-separated strings no release binary may contain, such as non-production hostnames; a secret, so the strings never show in the public run logs); the release stops before building if it is empty. The publish job installs only Go and GoReleaser, from `mise.lock`, with a pinned and checksummed mise. It builds, signs and uploads a draft release. The end-to-end suite then runs against those exact signed zips on Linux, macOS and Windows, in jobs that hold no secrets, and only then does the promote job check that the draft holds the tested checksums and publish it.

See also [SECURITY.md](SECURITY.md) and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
