# DriftRecon

Differential attack surface monitoring.

Most recon tooling answers "what is exposed right now" and leaves you with a
long list to sift through. DriftRecon answers "what changed since last time":
it stores every scan as a snapshot in a local SQLite database and compares
snapshots instead of dumping fresh output.

It ships as a single static binary with the database embedded. There is no
daemon and nothing else to run.

> **Status:** early development. Discovery, DNS resolution and snapshot
> storage work today. HTTP/TLS fingerprinting, drift detection and risk
> scoring are in progress.

## Intended use

DriftRecon is an attack surface management tool for security teams, auditors
and penetration testers. Run it only against assets you own or are explicitly
authorised to assess. Every target has to be registered with an explicit
authorisation acknowledgement, requests are rate limited, and the tool does
not fuzz paths, guess credentials or exploit anything.

## Build

```sh
go build ./cmd/driftrecon
```

Go 1.26 or newer is required. The build is pure Go, no CGO.

## Quick start

```sh
driftrecon target add acme --root example.com --authorized
driftrecon scan acme
driftrecon assets acme
```

## Scan profiles

| Profile    | What it does                                                    |
|------------|-----------------------------------------------------------------|
| `passive`  | Certificate Transparency only. Nothing is sent to the target.   |
| `standard` | Certificate Transparency plus DNS resolution of what was found. |

## Configuration

Settings are read from `config.yaml` in the DriftRecon directory under the
user configuration directory (`~/.config/driftrecon` on Linux), or from the
file passed with `--config`. Every key is optional.

```yaml
database: /path/to/driftrecon.db
resolvers: [1.1.1.1, 9.9.9.9]
concurrency: 20
rate: 50            # DNS queries per second
timeout: 5s
scan_timeout: 30m
max_hosts: 5000
sources:
  crtsh:
    enabled: true
  certspotter:
    enabled: true
```

A Cert Spotter API token is optional and is read from the
`CERTSPOTTER_TOKEN` environment variable.

## License

MIT
