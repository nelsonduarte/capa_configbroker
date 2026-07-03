# ConfigBroker

A capability-secured configuration and secret resolver that **proves, by
construction, that fetched secrets cannot leak to logs, telemetry or
public output, and that the broker can reach only one allowlisted
upstream host**. Neither guarantee is a policy document or a code-review
sign-off. Both are outputs of a compiler: the [Capa](https://github.com/nelsonduarte)
information-flow analysis rejects any path from a secret value to a
public sink, the Capa capability model gates the network to a single
host, and the capability SBOM Capa emits for this program enumerates
exactly where the one sanctioned disclosure happens and what authority
the program holds.

## The problem

Every service that runs in production has to get secrets from somewhere
(a vault, a config service, a KMS) into a configuration it can use, and
every one of them has the same two risks:

1. **The secret leaks.** A password fetched into memory ends up in a log
   line, a stack trace, a metrics label, a debug print, an APM span, an
   outbound telemetry payload. This is the single most common source of
   credential exposure, and it is almost always accidental: a `println`
   added during debugging, a log formatter that serialises a whole
   struct, an error handler that echoes the request. Secret scanners and
   log redaction catch some of it, after the fact, by pattern-matching.
   None of it is a *proof*.

2. **The broker phones home.** A config resolver that can open arbitrary
   network connections can exfiltrate everything it holds to anywhere.
   "It only talks to our vault" is, in most stacks, a convention, not an
   enforced boundary. A compromised dependency inside the resolver can
   reach a paste site or the cloud metadata endpoint, and nothing in the
   build fails.

ConfigBroker shows a different model. Both properties, "no secret value
reaches a log, the console or a telemetry sink" and "the network is
reachable only at the one allowlisted host", are **compile-time and
capability-time invariants**. If a developer writes the leak, the build
stops. If the resolver reaches for a second host, the capability gate
refuses it before a single packet leaves. The evidence that the shipped
build upholds both is a machine-readable artefact an auditor can
re-verify.

## What ConfigBroker does

It is a realistic config/secret resolver. Given a fetch manifest, a
config template and a local vault, it:

1. **Reads** the fetch manifest (which secrets to fetch, from which
   upstream URLs), the config template (which secret fills which output
   slot) and the local vault fixture, through a **read-only, `data/`-scoped
   filesystem view**.
2. **Fetches** each manifested secret from the upstream over a **`Net`
   capability attenuated to a single allowlisted host**. Every fetch URL
   is checked against that host by the capability gate *before any system
   call*. The fetched values are **`@secret`**.
3. **Resolves** the config: each secret is materialised into exactly the
   output slot the template declared for it, through a **single audited
   `declassify`** with a recorded reason.
4. **Routes outputs** under least privilege, through a write-only,
   `out/`-scoped filesystem view: the **resolved config**
   (`out/resolved.env`, secrets in their authorised slots) and an
   **audit log** (`out/audit.log`, built from public data only, with a
   SHA-256 integrity fingerprint). The audit log **cannot** contain a
   secret value, and the compiler is what guarantees it.

### The data model is the policy

```capa
pub type ResolvedSecret {
    name: String,             // the config slot key - public
    value: @secret String,    // the fetched secret material - never in the clear
    source: String            // "upstream" | "vault-fallback" - public provenance
}
```

The single `@secret` annotation on `value` is the entire confidentiality
policy. From it the compiler propagates a security label through every
derived value and proves it cannot reach a public sink (the audit log,
the console, a telemetry POST, a URL) without crossing the one audited
`declassify` in `resolve.capa`. There is nothing else to trust: no
runtime redaction, no scanner, no reviewer's diligence.

## Why both guarantees are machine-verifiable

### 1. Information-flow control: the leak does not compile

A `@secret` value that reaches a public sink without an audited
`declassify` is a compile-time error. `leaky_configbroker.capa` is the
counter-example that makes this concrete: it deliberately tries to leak
the fetched secret through the four channels a real secret manager must
defend against, and the compiler refuses all four:

```
$ python -m capa --check leaky_configbroker.capa
leaky_configbroker.capa:37:37: error: information-flow: a @secret value reaches
  Fs.write (argument 2), a public sink ...            # secret -> audit log
leaky_configbroker.capa:45:19: error: information-flow: a @secret value reaches
  Stdio.println (argument 1), a public sink ...       # secret -> console
leaky_configbroker.capa:53:56: error: information-flow: a @secret value reaches
  Net.post (argument 2), a public sink ...            # secret -> telemetry POST
leaky_configbroker.capa:62:19: error: information-flow: a @secret value reaches
  Net.get (argument 1), a public sink ...             # secret -> URL query string
leaky_configbroker.capa: 4 errors                     # exit code 1
```

The real resolver (`configbroker.capa`) checks clean. The single
legitimate secret-to-output crossing is the config materialisation, made
explicit at one `declassify` with a reason in `resolve.capa`:

```capa
fun render_slot(slot_key: String, s: ResolvedSecret) -> String
    return declassify(
        "${slot_key}=${s.value}",
        reason: "authorised config materialisation: the fetched secret is
                 written into exactly the output slot the config template
                 declared for it, and nowhere else; this is the sole
                 sanctioned secret-to-output crossing in the broker"
    )
```

### 2. Network attenuation: only the one host is reachable

`main` acquires a `Net` capability and immediately restricts it to a
single host:

```capa
let upstream = net.restrict_to("config.internal.example")
```

Capa's attenuation is monotonic: the restriction can only narrow, and
every `get`/`post` is checked against the allowed-host set *before* any
network syscall. `deny_offhost.capa` demonstrates this at runtime,
offline and deterministically (exit 0):

```
$ python -m capa --run deny_offhost.capa
allowlisted config.internal.example: HTTP GET failed: <urlopen error ...>
attacker exfil host: Net capability does not permit access to host 'attacker.example':
  current restrictions: ['config.internal.example']
public paste service: Net capability does not permit access to host 'paste.example': ...
cloud metadata endpoint: Net capability does not permit access to host '169.254.169.254': ...
```

The allowlisted host passes the gate (the fetch then fails only because
the demo has no live upstream). Every other host, including the cloud
metadata endpoint an attacker would target, is refused at the gate with
no network touched. The SBOM records the restriction, so an auditor sees
the single allowlisted host without running anything:

```
$ python -m capa --manifest configbroker.capa | grep -A3 attenuations
  "attenuations": [ { "method": "restrict_to", "args": [ "\"config.internal.example\"" ] } ]
```

### 3. Capability discipline: the resolver holds nothing else

`main` acquires exactly `Stdio`, `Fs` and `Net`, and never `Env`, `Proc`,
`Db`, `Clock`, `Random` or `Unsafe`. The compiler proves it, the SBOM
records it:

```
$ python -m capa --manifest configbroker.capa | jq '.functions[] |
    select(.source_name=="main") |
    {declared: .declared_capabilities, excluded: .provably_excluded_capabilities}'
{
  "declared": ["Stdio", "Fs", "Net"],
  "excluded": ["Clock", "Db", "Env", "Proc", "Random", "Unsafe"]
}
```

No `Unsafe` means no escape hatch to raw Python / host calls; no `Env`
means the paths and the host are fixed in the source, not taken from the
environment; no `Proc` means it cannot shell out. These are checked
facts, not promises.

### 4. The artefacts: config + audit log + SBOM

`./generate.sh` produces, byte-reproducibly (pinned `SOURCE_DATE_EPOCH`):

| Artefact | Emitted by | What it proves |
| --- | --- | --- |
| `out/resolved.env` | running ConfigBroker | secrets landed only in their authorised slots |
| `out/audit.log` | running ConfigBroker | the audit trail carries public data only, plus a SHA-256 fingerprint |
| `sbom/manifest.json` | `capa --manifest` | 1 declassification site + the capability surface + the `Net` restrict_to host |
| `sbom/sbom.cyclonedx.json` | `capa --cyclonedx` | CycloneDX 1.5 SBOM (Dependency-Track, OSV-Scanner, syft) |
| `sbom/sbom.spdx.json` | `capa --spdx` | SPDX 2.3 companion (OpenChain pipelines) |
| `sbom/provenance.slsa.json` | `capa --provenance` | SLSA build provenance over the source |

One declassification site, not zero (the config materialisation must
cross), not many. The audit log is the program's claim; the SBOM is the
compiler's evidence.

## What runs live vs offline (the honest note)

A live network fetch is not reproducible and may be blocked in CI, so the
test must not depend on a live upstream. ConfigBroker is built so the
**guarantee runs and verifies offline** while the fetch itself is a
reproducible stand-in:

- The **attenuation proof is real and does not need the network.** The
  `Net.restrict_to(host)` gate rejects every non-allowlisted host *before
  any syscall* (see `deny_offhost.capa`, which runs offline, exit 0), and
  the SBOM records the single allowlisted host at compile time.
- The **information-flow proof is entirely compile-time.** It is the
  output of `capa --check`; no network, no execution.
- The **fetch itself falls back to a local vault fixture.** ConfigBroker
  attempts the upstream `Net.get` (exercising the gate); with no live
  upstream, it reads the value from `data/vault.tsv` instead. The
  fetched-vs-fallback provenance is recorded in the audit log
  (`from vault-fallback`). Either way the value is `@secret` and the
  non-leak guarantee holds. In a real deployment the upstream answers and
  `source` reads `upstream`; the fixture is the deterministic offline
  path for the demo and CI.

So: the fetch is **mocked/offline**; the two guarantees the program
exists to make (non-leak of secrets, network attenuation to one host)
are **real and machine-verified** every run.

### A note on servers

An incoming HTTP **server** (a `wasi:http` request handler) is not in the
Capa toolchain today; the network surface is an outgoing client (`Net`).
ConfigBroker is therefore a **resolver / CLI**, not a service. Turning it
into a long-running broker that answers config requests over an incoming
handler is a natural extension the moment Capa grows an incoming-request
surface; the non-leak and attenuation machinery would carry over
unchanged.

## Layout

| Path | Role |
| --- | --- |
| `domain.capa` | the typed data model; the `@secret` annotation that is the policy |
| `parse.capa` | pure parsers for the manifest, template and vault (no capabilities) |
| `fetch.capa` | secret acquisition: `Net` attenuated to one host, offline vault fallback |
| `resolve.capa` | the single audited `declassify` bridge (secret into its authorised slot) |
| `audit.capa` | the audit log built from public data only, with a SHA-256 fingerprint |
| `configbroker.capa` | the orchestrator: read (Fs ro) -> fetch (Net) -> resolve -> write (Fs wo) |
| `leaky_configbroker.capa` | counter-example 1: the four secret leaks the compiler rejects |
| `deny_offhost.capa` | counter-example 2: the network attenuation the gate enforces at runtime |
| `data/manifest.tsv` | which secrets to fetch, from which upstream URLs |
| `data/template.tsv` | which fetched secret fills which output slot |
| `data/vault.tsv` | local vault fixture (fictitious secrets; the offline stand-in) |
| `out/` | sample generated resolved config + audit log |
| `sbom/` | sample generated manifest + SBOMs + provenance |
| `capa_hash` (git dep) | pure, capability-free; fetched + GPG/SLSA-verified by `capa install` into `vendor/` (audit-log fingerprint) |

## Run it

All commands use the local Capa compiler; substitute `python -m capa` for
`capa` if the installed `capa` is not the build you intend.

```sh
# One-time: fetch + verify the git dependency (needs capa >= 1.15.1).
# `capa install` clones capa_hash at its signed tag, verifies the tag's
# GPG signature against the verify_key in capa.toml and its SLSA
# provenance, writes capa.lock, and vendors the source under vendor/.
# Import the publisher key first (see capa_hash's SECURITY.md). capa_hash
# is pure and holds zero capabilities, so this adds a verified supply
# chain without widening the {Stdio, Fs, Net} surface.
capa install

# Type-check + information-flow check (clean: no leaks)
capa --check configbroker.capa

# Run the resolver. Writes out/resolved.env and out/audit.log.
capa --run configbroker.capa

# See the information-flow checker reject the four deliberate secret leaks
capa --check leaky_configbroker.capa     # 4 errors, exit code 1

# Watch the Net attenuation deny every non-allowlisted host (offline, exit 0)
capa --run deny_offhost.capa

# Regenerate the config, audit log and the full SBOM family
./generate.sh
```

### Same source, other backends

ConfigBroker runs unchanged on the Wasm backend, as a Wasm component, and
as a stock WASI Preview 2 component. The resolved config and audit log
are byte-identical between the Python and Wasm backends (the WASI
component differs only in newline style: LF vs the platform newline).

```sh
capa --wasm --run configbroker.capa                        # identical output
capa --wasm --component --run configbroker.capa            # as a Wasm component
capa --wasm --component --wasi --run configbroker.capa     # stock WASI Preview 2
```

The WASI run needs **no `--preopen`**: every filesystem path and the
upstream host are string literals at their `Fs` / `Net` sinks, which the
compiler resolves by constant propagation, so the component's filesystem
authority and its allowed-host ceiling are fixed at compile time rather
than granted by the operator. (In WASI mode the upstream fetch goes over
`wasi:http`; with no live upstream it falls back to the vault exactly as
on the other backends.)

## Dependencies

One dependency, **pure and capability-free**, resolved as a **verified git
dependency** in `capa.toml`:

- `capa_hash` - SHA-256, for the audit-log integrity fingerprint (over
  public audit text; no secret is ever hashed).

It is pinned to a **GPG-signed release tag** with the publisher's
`verify_key`. `capa install` (needs `capa >= 1.15.1`) fetches it at that
tag, verifies the tag's **GPG signature** against `verify_key` and its
**SLSA build provenance** (via `gh attestation verify` against the public
Sigstore log), records the resolved commit SHA in `capa.lock`, and vendors
the source under `vendor/` (git-ignored, not committed). A force-pushed
tag or a substituted commit is rejected before the code is ever compiled.

```toml
[dependencies.capa_hash]
git = "https://github.com/nelsonduarte/capa_hash"
tag = "v0.1.2"
verify_key = "6C1D222D491FB88031E041A536CFB426101AA24B"
```

This is the verifiable supply chain Capa is about, made concrete: the
dependency is **cryptographically verified at install time**, not trusted
by convention, and its pinned, signed provenance is recorded in
`capa.lock`. It holds no authority, so the ConfigBroker capability surface
stays exactly `{Stdio, Fs, Net}` with `Net` attenuated to one host, and
the SBOM proves it does not widen it.

## Licence

MIT. See `LICENSE`. The sample manifest, template and vault are entirely
fictitious; the vault secrets are not real credentials.
