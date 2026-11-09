# Security policy

## Reporting a vulnerability

Report vulnerabilities privately, never in public issues, discussions or pull requests:

- GitHub private vulnerability reporting: https://github.com/act-security/terraform-provider-act/security/advisories/new (preferred)
- Email: security@act.security

Include the provider version, the CLI and its version, a configuration with every secret removed, and the impact you see.

## What to expect

- Acknowledgement within 3 business days.
- Triage within 10 business days.
- Coordinated disclosure: 90 days, or the fixed release if that comes first. We credit reporters unless they ask us not to.

## Supported versions

Before 1.0, only the latest release gets fixes. From 1.0, the latest minor of the current major.

## Scope

In scope: this provider, its release artifacts and its GitHub workflows.

Out of scope: the Act platform itself (report it to security@act.security directly) and the Act onboarding modules (report them in their own repositories).

The `actinternal` build tag adds Act's development hosts to the provider's allow-lists. It is for Act developers only and never ships. A release binary that accepts a development host is a vulnerability.

## Verifying a release

Every release ships a `SHA256SUMS` file signed with the Act provider signing key, and GitHub build provenance for every archive. The public key is [`signing-key.asc`](signing-key.asc) in this repository:

| | |
|---|---|
| Key | RSA 4096, `Act Security Terraform Provider <security@act.security>` |
| Fingerprint | `39FE 9735 C185 B3F4 8FE4  9BEC 13AB 6A41 832F A81D` |

```sh
gpg --import signing-key.asc
gpg --verify terraform-provider-act_<version>_SHA256SUMS.sig terraform-provider-act_<version>_SHA256SUMS
shasum -a 256 --check --ignore-missing terraform-provider-act_<version>_SHA256SUMS
gh attestation verify terraform-provider-act_<version>_<os>_<arch>.zip --repo act-security/terraform-provider-act
```

`terraform init` and `tofu init` run the same signature check automatically when they install from a registry.
