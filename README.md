# DriftRecon

Differential attack surface monitoring.

Most recon tooling answers "what is exposed right now" and leaves you with a
long list to sift through. DriftRecon answers "what changed since last time":
it stores every scan as a snapshot in a local SQLite database and compares
snapshots instead of dumping fresh output.

It ships as a single static binary with the database embedded. There is no
daemon and nothing else to run.

> **Status:** early development. Discovery, DNS resolution, HTTP and TLS
> probing, structural fingerprints and snapshot storage work today. Drift
> detection and risk scoring are in progress.

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
driftrecon assets acme --kind service
driftrecon show www.example.com
```

`assets` lists the hosts or services of the latest completed scan. `show`
prints everything recorded about one host and the services on it, or about a
single service when given its URL.

## Scan profiles

| Profile    | What it does                                                                  |
|------------|-------------------------------------------------------------------------------|
| `passive`  | Certificate Transparency only. Nothing is sent to the target.                 |
| `standard` | Adds DNS resolution and one look at the front page of every web service found. |

## What a standard scan sends

Every discovered name is resolved. On hosts that resolve, ports 80 and 443
are checked for a web service, and a service that answers is asked for:

- its front page, twice, so that features which change on every request can
  be told apart from the ones worth tracking;
- the pages the front page redirects to on the same service, at most ten;
- its favicon.

Nothing else is requested. A redirect that leads to another host is recorded
and not followed. At most 2 MiB of a response body are read. Requests carry a
User-Agent that names the tool, are limited to two per second per host, and
slow down further when a server answers 429 or 503 with `Retry-After`.

Names that resolve to private, loopback or otherwise non-public addresses are
recorded but never connected to, unless `probe.allow_private` is set. A
public name is free to point at `192.168.1.1`, and that address belongs to
whatever network the scan happens to run in.

## What is recorded

A service is described in layers, each with a fingerprint of its own, so that
a later comparison can say what kind of change happened:

| Layer      | Contents                                                                                   |
|------------|--------------------------------------------------------------------------------------------|
| `dns`      | CNAME chain, name servers, the networks the addresses belong to                            |
| `tls`      | protocol, issuer, public key, names on the certificate, trust problems                     |
| `headers`  | header names in the order and spelling the server sent them, server banner, security policies, cookie names and flags |
| `redirect` | status codes and redirect targets, with identifiers masked                                 |
| `dom`      | the element tree of the page without text or attributes, form signatures                   |

Next to the exact fingerprint of the page structure a 64-bit SimHash is
stored, which places pages with a similar structure close to each other.
Cookie values and form field values are never stored.

A feature that differs between the two requests of one scan is left out of
the fingerprints and listed as volatile instead.

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
probe:
  http_ports: [80]
  https_ports: [443]
  rate: 20          # connections per second, all hosts together
  host_rate: 2      # connections per second to one host
  timeout: 10s
  allow_private: false
```

A source also accepts `url` to point it at a self-hosted mirror instead of
the public endpoint. A Cert Spotter API token is optional and is read from
the `CERTSPOTTER_TOKEN` environment variable.

Up to ten ports can be listed under `probe`. With both lists empty a scan
stops at name resolution. Every scan records which ports it checked, so that
a later comparison does not mistake a newly listed port for new services.

## License

MIT
