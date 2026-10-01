# Tide objects

OpenTide LSP owns Tide diagnostics. Disable Red Hat YAML / yamlls on `objects/**`.

There is **no YAML formatter**. The LSP does not rename object `name`.

## Types

| schema | refs |
| --- | --- |
| `rule::1.0` | `detection_model` → objective UUID (optional; not schema-required) |
| `objective::1.0` | `objective.threats[]` → threat UUIDs |
| `threat::1.0` | `threat.impact` / `threat.leverage` are non-empty lists. `threat.chaining[].vector` / `relation` are not schema properties in 0.5.0 |

An array field written as one YAML string (`impact: High`) is
`schema_validation`: "{path} must be a YAML list of {name} vocabulary names,
not a single string". The diagnostic's `suggestion` is `- {text}`. A list
shorter than the field's `min_items` is also `schema_validation`. Unknown
names inside the list are `vocab_unknown`.

## Diagnostic codes (CLI-compatible)

Pydantic stays CLI authority. LSP emits the same `{code, field_path, severity}`:

- `schema_validation`
- `vocab_unknown`
- `invalid_uuid`
- `duplicate_id`
- `invalid_ref`
- `chaining_relation_unknown`
- `deprecated_field`
- `filename_slug` — warning. The file stem must equal `slugify(name)` or start with `{slug}-`. `slugify` lowercases ASCII alphanumerics and collapses other characters to a single `-` (`Sentinel KQL Rule` → `sentinel-kql-rule`). Suggestion text is `{slug}.yaml`.
- `missing_author` — warning when `metadata.author` is absent.
- `missing_organisation` — warning when `metadata.organisation` is absent.

Query extras come from the KQL and SPL engines. They fire on raw `.kql` /
`.spl` files and on the same text inside an injected block. Slow-shape
codes (`kql_where_not_first`, `kql_unscoped_search`, `kql_unscoped_union`,
`kql_wildcard_table`, `kql_join_summarize_before_project`, `kql_render_not_valid`,
`spl_wildcard`, `spl_leading_not`, `spl_subsearch_truncation`) are warnings.
Unknown operators, unknown commands, control commands, and parse errors are
errors. Rules: [kql/DESIGN.md](kql/DESIGN.md), [spl/DESIGN.md](spl/DESIGN.md).

- `kql_control_command_unsupported`
- `kql_unknown_operator`
- `kql_unknown_function`
- `kql_unknown_table`
- `kql_render_not_valid`
- `kql_parse_error`
- `kql_where_not_first`
- `kql_unscoped_search`
- `kql_unscoped_union`
- `kql_wildcard_table`
- `kql_join_summarize_before_project`
- `spl_unknown_command`
- `spl_parse_error`
- `spl_wildcard`
- `spl_leading_not`
- `spl_subsearch_truncation`
- `crowdstrike_unsupported` (never faked)
- `defender_output_columns`

## Catalogs

Snapshot from `opentide generate schemas` into `catalogs/tide/`. A workspace file `.opentide/lsp/catalogs/generated/deprecations.json` (same shape as the bundled catalog) adds `deprecated_field` warnings on top of `catalogs/tide/generated/deprecations.json`.

Snippets come from the same templates `opentide generate` writes (`catalogs/tide/templates/`).

## UUID graph

- `textDocument/definition` and `references` on UUIDs
- Completions = names + UUIDs of the target type
- `workspace/symbol` by name / uuid / schema (location range is the name token)
- `duplicate_id` across the workspace
- Inlay hints and the other structure providers: [EDITORS.md](EDITORS.md)
