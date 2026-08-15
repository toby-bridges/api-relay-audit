# v2.4.0 DeepSeek Harness Distribution Verification

Verified on 2026-08-16. This record covers distribution integrity and runtime
boundaries. It is not a certification that any relay is safe.

## Immutable Source

| Item | Verified value |
| --- | --- |
| Release tag | `v2.4.0` |
| Release commit | `571b97142c0d22aae305ac2919e45137bc424dcc` |
| Installed package version | `2.4.0` |
| Standalone `audit.py` SHA-256 | `43d237634fabf8618f458668acd70a1d0c15d3595f25e538285e56b057de9e71` |

Both profile lockfiles resolved the GitHub tag to the release commit above.
The installed `audit.py` in each profile was byte-identical to the tag and
published release asset.

## Toolchain

| Tool | Version used |
| --- | --- |
| DeepSeek Harness (`@deepseek-ai/dsh`) | `0.1.0-rc.6` |
| `dsh-cc-tui` | `0.4.1` |
| pnpm | `11.19.0` |
| Node.js | `25.9.0` |
| Python | `3.14.3` |

## Install And Load Checks

The release tag was installed into isolated web and cc-tui profiles:

```bash
DSH_PLUGIN_REF=v2.4.0
npx --yes @deepseek-ai/dsh@0.1.0-rc.6 plugin --profile web add \
  "github:toby-bridges/api-relay-audit#${DSH_PLUGIN_REF}"
npx --yes @deepseek-ai/dsh@0.1.0-rc.6 plugin --profile cc-tui add \
  "github:toby-bridges/api-relay-audit#${DSH_PLUGIN_REF}"
```

Both `--dump-config` results contained the `api-relay-audit` bundle. The web
application reached its loopback HTTP listener, and the cc-tui application
rendered an interactive prompt in a PTY.

The cc-tui profile's `dsh-cc-tui@0.4.1` dependency required explicitly allowing
the `koffi@3.1.5` install script in that profile's pnpm build policy. This is a
cc-tui dependency requirement; the API Relay Audit bundle itself has no build
hook.

## Connectivity And Secret Boundary

A local fake relay accepted both Anthropic-compatible and OpenAI-compatible
requests. For each installed profile, a minimal DSH service harness loaded the
exact installed plugin and invoked its real child `audit.py` process in
`--connectivity` mode. Both protocol probes returned HTTP 200 and each report
recorded `Connectivity Verdict: OK`.

Each invocation resolved the credential once. The child argv contained
`--key-env API_RELAY_AUDIT_KEY`, not the credential value. A unique test-key
sentinel was absent from:

- captured process argv and command results;
- both isolated DSH profile states;
- generated Markdown reports and transparent logs.

The fake relay and generated evidence stayed under isolated temporary paths.
No private relay URL, production credential, or user report was used.

## Evidence Boundary

The profile install, config dump, web boot, and cc-tui boot used the real DSH
applications. The connectivity command was exercised through a minimal DSH
service harness against the exact installed plugin, rather than being entered
manually in either UI. This proves the plugin adapter, subprocess composition,
two protocol paths, and credential boundary; it does not prove every
interactive client rendering path.
