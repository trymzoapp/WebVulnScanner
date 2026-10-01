# WebVulnScanner Configuration

## Configuration sources and precedence

Configuration is loaded in this deterministic order, from lowest to highest precedence:

1. `webvulnscanner/config/defaults.yaml`
2. `webvulnscanner/config/scanners.yaml`
3. `webvulnscanner/config/profiles/<selected-profile>.yaml`
4. An optional user configuration file
5. Explicit runtime overrides supplied by the CLI or application

Nested mappings are merged recursively. A higher-precedence scalar replaces the lower
value. Lists, when introduced by later scanner-specific tasks, replace rather than append.
The loader never mutates input mappings.

The selected profile is an explicit profile argument when supplied, otherwise the user
configuration's `profile.name`, otherwise `safe`. A user file cannot rename an explicitly
selected profile.

## Safe default profile

`safe` is the default profile. All profiles, including `standard`, remain
non-destructive. The loader rejects any profile or override that enables:

- destructive behavior;
- authentication or authorization bypass;
- WAF bypass; or
- rate-limit bypass.

Profile resource ceilings cannot exceed the framework's hard safety bounds. Global and
per-scanner concurrency and rate limits must also remain within the selected profile's
limits. These checks apply after all override layers have been merged.

## Core settings

```yaml
timeouts:
  default: 300
  nuclei: 600

concurrency:
  max_scanners: 3
  max_targets: 2

reports:
  json: true
  markdown: true
  html: true

storage:
  root: "./runs"

profile:
  name: "safe"
```

Timeouts are positive seconds. `timeouts.default` is required and scanner-specific
values fall back to it. Unknown scanner names are rejected to catch spelling mistakes.

Storage paths are interpreted by the calling application. Relative paths are therefore
relative to its working directory. Storage containment and atomic scan-directory
creation are implemented by the storage task; configuration loading does not create
directories.

## HTTP collection limits

Passive HTTP collectors share bounded request settings:

```yaml
http:
  user_agent: "WebVulnScanner/0.1 (authorized security assessment)"
  max_redirects: 5
  max_response_bytes: 1048576
```

Scanner-specific timeouts remain in `timeouts`. Redirects are followed manually so each
destination can be scope-validated, response bodies are streamed only up to the
configured cap, and TLS verification remains enabled.

Wayback collection has an independently bounded structured endpoint:

```yaml
wayback:
  endpoint: "https://web.archive.org/cdx/search/cdx"
  max_records: 5000
  page_size: 500
```

The endpoint must use HTTPS. The scanner's generic rate limit controls delay between
pages, and archived URLs are recorded only; they are not requested by the collector.

## Fingerprinting and discovery limits

Nmap is restricted to an explicit TCP port allowlist, conservative timing template, and
per-host deadline:

```yaml
fingerprint:
  ports: [80, 443, 8080, 8443]
  timing_template: 2
  host_timeout_seconds: 120
```

The loader permits at most 64 valid TCP ports and rejects timing templates above `T3`.
Discovery has shared response and recursion bounds:

```yaml
discovery:
  status_codes: [200, 204, 301, 302, 307, 308, 401, 403]
  dirsearch_extensions: [html, php, js, txt]
  max_recursion_depth: 0
```

Safe defaults disable recursion. Recursion depth cannot exceed two, extensions are
strictly alphanumeric, and scanner thread/rate limits remain constrained by the selected
profile. Gobuster and Dirsearch additionally require an explicitly configured wordlist.

## Scanner settings

Tool paths, wordlists, rate limits, and concurrency are externalized:

```yaml
scanners:
  nuclei:
    enabled: true
    executable: "nuclei"
    wordlist: null
    concurrency: 2
    rate_limit_per_second: 5.0
```

`enabled` means the scanner is eligible for later routing; it does not cause blind
execution. Dynamic routing and target scope still decide whether a scanner may run.
Executable names are resolved by the future command/tool-verification layer. Scanner
classes must not embed executable paths, wordlists, timeouts, or concurrency values.

## User override example

The following keeps the safe profile while changing bounded local settings:

```yaml
profile:
  name: "safe"

storage:
  root: "./local-runs"

reports:
  html: false

timeouts:
  headers: 20

scanners:
  nuclei:
    executable: "/opt/security-tools/nuclei"
    rate_limit_per_second: 3.0
```

Sections may be partial in a user file because they merge over packaged defaults.
Unknown root or nested keys, malformed YAML, missing profiles, invalid types, nonpositive
limits, and unsafe values raise a typed configuration error. Secrets do not belong in
YAML configuration; future credentials must use a redacted secret-loading mechanism.

## Profiles

- `safe` uses conservative concurrency and disables directory-discovery tools by default.
- `standard` enables bounded discovery and permits moderately higher resource limits,
  while retaining all non-destructive and no-bypass guarantees.

Choosing a profile never grants permission to assess a target. Operators must still
provide an explicitly authorized scope.
