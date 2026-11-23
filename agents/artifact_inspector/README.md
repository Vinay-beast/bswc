# artifact-inspector agent

What ships and what builds it: Dockerfiles, the container image, and CI/CD workflows. It records
facts only; nothing is scored here. Output: `outputs/<app_id>/artifacts/`.

```sh
.venv/bin/python -m agents.artifact_inspector --repo <url> [--image REF | --build-image] [--skip-container] [--run-id ID]
```

## Dockerfiles and compose files → `dockerfile_analysis.json`

For every `Dockerfile`, `Containerfile`, `*.Dockerfile` and `docker-compose*.yml`, it records:
- every build stage with its `FROM` image (with `ARG` defaults substituted) and how it is pinned (digest / tag / latest / variable)
- the `USER` of each stage
- findings: `pipe-to-shell` (`curl|sh`, also across line continuations), `add-from-url`,
  `npm-install-runs-scripts`, `final-stage-runs-as-root`, `base-image-not-digest-pinned`

## Container image → `container.json`, `raw/*-image.*`

1. **Which image**:
   - `--image REF` if given.
   - With `--build-image`: `docker build -t guardian/<app_id>:<short-sha>`.
   - Otherwise the image the project publishes. Image names come from `docker pull/run` lines in
     the README and `image:` keys in compose files. Tags are tried in order: `v<version>`,
     `<version>`, the same without a pre-release suffix, then `latest`. Each candidate is checked
     with `docker manifest inspect` (or the Docker Hub API).
   - Every candidate tried and the reason for the choice are recorded. Juice Shop's
     `20.4.0-SNAPSHOT` has no image, so `bkimminich/juice-shop:v20.4.0` is used and this is said explicitly.
2. **Pull and scan**: with a Docker daemon, `docker pull` → `docker image inspect` (digest, layers,
   platform, user) → `trivy image --image-src docker` and `syft scan docker:<ref>`. Without a
   daemon, Trivy uses `--image-src remote` and Syft scans `registry:<repo>@<digest>`. A failure
   only produces a warning.
3. **Summary**: OS/distro, declared base image and its pinning, layer count, and packages split
   into OS (`deb`/`apk`/`rpm`) and application packages, merged from Syft and Trivy.

## CI/CD → `ci_inventory.json`

- `.github/workflows/*.yml`: triggers, workflow and job `permissions` (missing ones are flagged as
  default token permissions), jobs, `if:` conditions, and every `uses:` reference.
- **Action pinning**: full commit SHA, tag, branch, local or `docker://`. Tag vs branch is resolved
  with `git ls-remote` (`pin_source` says whether it was verified or a heuristic). A `# vX.Y`
  comment after a SHA is kept as `ref_comment`.
- **Publisher**: GitHub-owned (`actions/*`, `github/*`) or third-party.
- **Images** used by job containers, services and `docker://` steps, with their pinning.
- **Patterns** (facts, with the job's `if:`): `pull-request-target-checkout-head`, `pipe-to-shell`,
  `secrets-in-pr-workflow`, `default-token-permissions`.
- **Deduplication**: one entry per `action@ref`, listing every workflow and job that uses it.
- **Other CI systems** (GitLab, Jenkins, Azure Pipelines, CircleCI, ...) are detected and listed but not parsed.
