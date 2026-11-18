# GitHub repository setup

Some repository settings are not stored in git and must be applied once via
the GitHub UI or GitHub CLI. `gh` is not installed in the dev container, so
the commands below are recorded here for the maintainer.

## About panel (description and topics)

```sh
gh repo edit xelira/elira \
  --description "Rust HTTP/1.1, HTTP/2 and HTTP/3 server and reverse proxy with caching, TLS and fast_proxy" \
  --add-topic rust \
  --add-topic http3 \
  --add-topic reverse-proxy \
  --add-topic web-server \
  --add-topic nginx \
  --add-topic quic \
  --add-topic http2 \
  --add-topic tls \
  --add-topic load-balancer
```

Topics to search for: `rust`, `http3`, `reverse-proxy`, `web-server`, `nginx`,
`quic`, `http2`, `tls`, `load-balancer`.

## Releases

`.github/workflows/release.yml` builds four Linux targets and publishes the
archives automatically when a `v*` tag is pushed:

```sh
git tag -a v0.1.0 -m "Elira 0.1.0"
git push origin v0.1.0
```

The workflow uploads `elira-v0.1.0-<target>.tar.gz` plus SHA-256 checksums and
generates release notes from the commit history. `CHANGELOG.md` contains the
human-readable summary for v0.1.0.

## Badges

The English `README.md` already includes CI, release, MSRV and license badges.
They use the workflow files `.github/workflows/ci.yml` and
`.github/workflows/release.yml`.
