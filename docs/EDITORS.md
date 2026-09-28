# Editor hosts

The OpenTide LSP owns Tide diagnostics. Disable yamlls / Red Hat YAML on `objects/**`.

Languages: `opentide-yaml`, `kql`, `spl` (never `sql`).

Semantic tokens come from the server. TextMate grammars must be **copied from the language-server highlight zip**, never hand-authored.

## Helix

See `editors/helix/languages.toml`.

## Neovim

See `editors/nvim/opentide.lua`.

## Zed

See `editors/zed/opentide.json`.

## VS Code

Lives in **OpenTideHQ/vscode-extension** (other repository). MIT client, EUPL engine notices.

## Structure providers

These replaced whole-buffer stubs. Hosts that advertise the capabilities from
`initialize` get the behavior below (`crates/opentide-lsp/src/server.rs`).

| Method | Behavior |
| --- | --- |
| `textDocument/documentSymbol` | When `name` is set: one symbol, the name string, kind Class (`5`), `detail` = metadata UUID, range = the `name` key. |
| `workspace/symbol` | Matches name, UUID, or schema family (`rule`, `objective`, `threat`). `containerName` is the family. Range is the first occurrence of the name in the open text. |
| `textDocument/documentHighlight` | Every occurrence of the UUID under the cursor in that file. Empty when the cursor is not on a UUID. |
| `textDocument/inlayHint` | Tide YAML only. After each UUID that matches another indexed object, label `{type} {name}` (kind Type, `1`). The document's own `metadata.uuid` is skipped. |
| `textDocument/foldingRange` | One `region` per indent level that has a deeper following line. A fold that would cover the whole buffer is omitted. Blank lines do not start or end a region. |
| `textDocument/selectionRange` | Inner range is the cursor line. Parent is the enclosing less-indented block, through the last deeper line. |
| `textDocument/codeAction` | A `quickfix` only when a diagnostic overlapping the request has a `suggestion`. The edit replaces that diagnostic range with the suggestion string. Title: `Apply suggestion: {suggestion}`. |

Suggestion strings the engines attach:

| Code | Range | Suggestion |
| --- | --- | --- |
| `kql_unknown_operator` | the operator node | closest catalog operator, edit distance ≤ 3 |
| `kql_unknown_function` | the call | closest catalog function, distance 1–2 (no diagnostic when nothing is that close) |
| `kql_unknown_table` | the table token | closest catalog table, distance ≤ 4, and only when the token starts with an ASCII uppercase letter |
| `spl_unknown_command` | the command node | closest catalog command, distance ≤ 3 |
| `invalid_ref` on `detection_model` | the `detection_model` key | UUID of the first indexed objective, when one exists |
| `schema_validation` (string where a list is required) | the field key | `- {text}` |
| `filename_slug` | the `name` key | `{slug}.yaml` |

On Tide keys the range is the key, so applying the edit overwrites the key
text. On query tokens the range is the bad name, so the edit replaces that
name.

`textDocument/diagnostic` is pull diagnostics (`interFileDependencies: true`,
`workspaceDiagnostics: false`). Items use `source: "opentide"` and the engine
code. Severity map: error 1, warning 2, information 3, hint 4.

## Web

`packages/lsp-worker` exposes `highlight()` + `legend()` for Monaco without a full language client.

```ts
import { createOpentideClient } from "@opentide/lsp-client";

const client = createOpentideClient({ transport: "stdio" });
```
