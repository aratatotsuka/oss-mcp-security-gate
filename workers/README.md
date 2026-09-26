# Worker image admission

`workers/static/Dockerfile` is a minimal template for an already-verified, statically linked scanner binary. Build context must contain only the approved binary named `scanner`. Never build it from the hostile target and never let Scan Pipeline run `docker build`.

The Update Pipeline must:

1. Verify the release artifact SHA-256, signature, provenance and advisory status.
2. Extract with traversal, symlink, expanded-size and file-count limits inside quarantine.
3. Verify the extracted binary digest and version in an isolated update worker.
4. Build the image with `FROM scratch`, scan/attest the image, and push it to the internal registry.
5. Record the registry-provided `image@sha256:...` in the approved manifest.
6. Configure the registry so that an existing digest cannot be overwritten.

Cisco MCP Scanner is Python-based and cannot use the scratch template. Its worker requires an internally approved, digest-pinned Python base and a fully hash-locked dependency set generated and verified in the Update Pipeline. No such base is selected in this source distribution; this is `BLOCKED_SECURITY_REQUIREMENT` until the deployment owner approves one.

Scorecard needs a separate image/identity/network policy with GitHub-only egress. It must not share network namespace, token or cache with offline scanners.
