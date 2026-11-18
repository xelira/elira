# Deploying Elira

The server reads its configuration from `/etc/elira/elira.toml`; the image and
the systemd unit both start it with `elira run --config /etc/elira/elira.toml`.
The image does not contain that file, so mount or install a real config before
starting.

## Docker

```
docker build -t elira .

docker run --rm --name elira \
  -p 8080:8080 \
  -p 443:443/tcp \
  -p 443:443/udp \
  -v "$PWD/elira.toml:/etc/elira/elira.toml:ro" \
  -v elira-state:/var/lib/elira \
  elira
```

The repository's `elira.toml` listens on `127.0.0.1:8080`. Inside a container
that address is reachable only from the container itself; use
`listen = "0.0.0.0:8080"` when publishing the port.

Certificates named by `[tls]` and `[http3]` must be mounted read-only as well,
for example `-v "$PWD/cert.pem:/etc/elira/cert.pem:ro"`.

The image runs as `elira` (uid/gid 10001). Docker normally permits binding
ports below 1024; if the runtime does not, add `--cap-add=NET_BIND_SERVICE`.
The health check opens a TCP connection to 127.0.0.1 on 8080 or 443. Override
it with `--health-cmd` when the config listens on another port.

## systemd

Install the binary, the config and the unit:

```
sudo groupadd --gid 10001 elira
sudo useradd --uid 10001 --gid elira --home-dir /var/lib/elira \
  --no-create-home --shell /usr/sbin/nologin elira

sudo install -d -o root -g root -m 0755 /etc/elira
sudo install -m 0644 elira.toml /etc/elira/elira.toml
sudo install -d -o elira -g elira -m 0750 /var/lib/elira

sudo install -m 0755 target/release/elira /usr/local/bin/elira
sudo install -m 0644 deploy/elira.service /etc/systemd/system/elira.service

sudo systemctl daemon-reload
sudo systemctl enable --now elira
```

The unit grants only `CAP_NET_BIND_SERVICE`, so ports 80 and 443 work without
running the server as root. `ProtectSystem=strict` makes `/etc` read-only;
`/var/lib/elira` is the only writable path. Keep the config and certificates in
`/etc/elira`.

Reload and logs:

```
sudo systemctl reload elira
journalctl -u elira -f
```

A reload (SIGHUP) replaces routes, upstreams, certificates and the log format
without dropping connections. Changing the listen address or connection limits
needs `systemctl restart elira`.

## npm launcher

`packages/npm` ships only `bin/elira.js`. Without a native binary it prints the
installation options and exits with status 1. The launcher checks, in order:
`ELIRA_BIN`, the optional `@elira/<platform>-<arch>` package, then `elira` in
`PATH`. Platform packages are not published yet, so `ELIRA_BIN` or a release
archive is the usable path today.

## Releases

Pushing a `v*` tag runs `.github/workflows/release.yml`. It builds
`x86_64-unknown-linux-gnu` and `aarch64-unknown-linux-gnu`, strips the binaries,
and attaches `elira-<tag>-<target>.tar.gz` plus a checksum to the GitHub
release.
