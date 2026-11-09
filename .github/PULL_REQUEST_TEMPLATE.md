## Summary

-

## Why

-

## Testing

- [ ] `make check`
- [ ] `make dev-apply` against the fake when the provider's behavior changed

## Checklist

- [ ] The PR title is a conventional commit; release-please reads the squash title
- [ ] `make docs` and `make generate` output is committed
- [ ] Every new or changed resource and data source has its example, `import.sh` for resources, and a template under `templates/`, so `make docs-rule` passes
- [ ] No comments added to code, YAML or the Makefile
- [ ] No secret or tenant credential in examples or tests
- [ ] `CHANGELOG.md` not edited by hand
