# KQL inventory for Sentinel and Defender detections

This directory is a **query-language inventory** of Microsoft Kusto Query Language (KQL) as used in:

- Microsoft Sentinel scheduled analytics rules, NRT analytics rules, hunting queries
- Microsoft Defender XDR / Microsoft Defender for Endpoint (MDE) advanced hunting and custom detections

It is **not** a catalog of Azure Data Explorer management (control) commands. Control commands (`.show`, `.create`, `.alter`, `.drop`, `.ingest`, `.set`, …) are listed only as **unsupported** in detections.

## Scope

| In scope | Out of scope |
| --- | --- |
| Tabular query operators (`where`, `join`, `summarize`, …) | SQL |
| Scalar operators (`==`, `has`, `matches regex`, …) | Control / management commands as detections |
| Scalar functions (`ago()`, `parse_json()`, `ipv4_is_private()`, …) | ADX-only cluster administration |
| Aggregation functions used with `summarize` / `make-series` | Full list of every `_CL` partner table in the Sentinel marketplace |
| Scalar types | Python / R plugins as detection logic |
| Syntax: `let`, comments, strings, timespans, pipe pipelines | Visualization-only UX (workbooks charts) except noting `render` |
| Sentinel and Defender **tables used in detections/hunting** | CMPivot / Azure Resource Graph KQL dialects |

## How this inventory maps to repo catalogs

Machine-readable catalogs live under [`/workspace/catalogs/kql/`](../../catalogs/kql/):

| Catalog file | This inventory |
| --- | --- |
| `catalogs/kql/core/operators.toml` | [`operators.md`](operators.md) (tabular) + [`operators-scalar.md`](operators-scalar.md) |
| `catalogs/kql/core/functions.toml` | [`scalar-functions.md`](scalar-functions.md) + [`aggregation-functions.md`](aggregation-functions.md) |
| `catalogs/kql/core/types.toml` | [`types.md`](types.md) |
| `catalogs/kql/sentinel/tables.toml` | [`sentinel-tables.md`](sentinel-tables.md) |
| `catalogs/kql/defender/tables.toml` | [`defender-tables.md`](defender-tables.md) |
| (no catalog) | [`syntax.md`](syntax.md) |
| (gap analysis) | [`coverage-gap.md`](coverage-gap.md) |

The TOML catalogs are a **starter subset**. This inventory is the public Microsoft Learn surface that hunting/detection queries actually use. See [`coverage-gap.md`](coverage-gap.md) for what the catalogs currently miss.

## Detection validity legend

Used throughout this inventory:

| Value | Meaning |
| --- | --- |
| **Yes** | Valid in Sentinel scheduled analytics and Defender custom detections, and in hunting |
| **Restricted** | Valid in scheduled detections with documented caveats (no `search *` / `union *`, length limits, NRT extra rules) |
| **Hunting** | Valid in Logs / advanced hunting; omit from detection rules (visualization, multi-result sets, metadata-only) |
| **NRT-no** | Banned or unsupported in Defender **Continuous (NRT)** custom detections |
| **AM-no** | Not supported in Azure Monitor / Sentinel / Defender (ADX / Fabric only) |
| **No** | Not a detection query construct (control commands, consume-all, etc.) |

## Platform notes (citations)

### Language is KQL, not SQL

Kusto queries are read-only tabular pipelines. Operators are sequenced with `|`. Query statements are `let`, tabular expressions, and (rarely) `set`. Management commands start with `.` and **cannot** be embedded in queries.

- [KQL overview](https://learn.microsoft.com/kusto/query/)
- [Queries](https://learn.microsoft.com/kusto/query/queries)
- [Tabular expression statements](https://learn.microsoft.com/kusto/query/tabular-expression-statements)
- [KQL quick reference](https://learn.microsoft.com/kusto/query/kql-quick-reference)

### Azure Monitor / Sentinel dialect

Sentinel stores data in Log Analytics and uses the Azure Monitor KQL dialect. Differences vs Azure Data Explorer:

- **Not supported:** `alias` / query-parameter statements; `cluster()`, `database()`, `cursor_*()`, `current_principal()`, `extent_id()`, `extent_tags()`; cross-cluster join; Python and `sql_request` plugins.
- **Azure Monitor–only sources:** `workspace()`, `app()`, `resource()`.
- Sentinel scheduled analytics: query length 1–10,000 characters; **must not** contain `search *` or `union *`; ADX `adx()` inside analytics rules is not supported.

Citations:

- [Log queries in Azure Monitor](https://learn.microsoft.com/azure/azure-monitor/logs/log-query-overview)
- [Scheduled analytics rules](https://learn.microsoft.com/azure/sentinel/scheduled-rules-overview)
- [Sentinel service limits](https://learn.microsoft.com/azure/sentinel/sentinel-service-limits)

### Defender XDR / MDE hunting and custom detections

Advanced hunting uses KQL over a specialized schema (`DeviceProcessEvents`, `EmailEvents`, …). Custom detections are hunting queries saved as rules.

**Recommended output columns** for custom detections using Defender data:

1. `Timestamp` or `TimeGenerated`
2. MDE tables: `DeviceId` and `ReportId`
3. Other Defender tables: `Timestamp` and `ReportId` from the same event
4. Impacted-asset identifiers (`DeviceId` / `DeviceName`, mailbox addresses, `AccountObjectId` / `AccountSid` / `AccountUpn`, …)

**Continuous (NRT)** custom detections additionally require: a **single table**, no `join` / `union` / `externaldata`, no comments, and only supported KQL features.

Citations:

- [Advanced hunting query language](https://learn.microsoft.com/defender-xdr/advanced-hunting-query-language)
- [Advanced hunting schema tables](https://learn.microsoft.com/defender-xdr/advanced-hunting-schema-tables)
- [Create custom detection rules](https://learn.microsoft.com/defender-xdr/custom-detection-rules)

### `render` and visualization

`render` is a visualization operator. It is **not** detection logic. The core catalog already marks it `not_valid_in_detections`.

## File index

| File | Contents | Approx. counts |
| --- | --- | --- |
| [operators.md](operators.md) | Tabular operators + evaluate plugins + unsupported control commands | 55 operators + 21 plugins |
| [operators-scalar.md](operators-scalar.md) | Comparison, string, numeric, logical, `between`, IPv4 text match | 50+ operators |
| [scalar-functions.md](scalar-functions.md) | Documented scalar functions (string, datetime, conversion, dynamic, hash, IP, geo, series, …) | 280+ functions |
| [aggregation-functions.md](aggregation-functions.md) | `summarize` / `make-series` aggregations | 45 functions |
| [types.md](types.md) | `bool`, `datetime`, `decimal`, `dynamic`, `guid`, `int`, `long`, `real`, `string`, `timespan` | 10 types |
| [syntax.md](syntax.md) | `let`, comments, strings (`@""`, `` ``` ``), timespans, pipe, `datatable`, `print` | — |
| [sentinel-tables.md](sentinel-tables.md) | Common Sentinel / Log Analytics tables used in detections | 120+ tables |
| [defender-tables.md](defender-tables.md) | Defender XDR schema tables + custom-detection output columns | 60+ tables |
| [coverage-gap.md](coverage-gap.md) | Current TOML catalogs vs this inventory | — |

## Primary Microsoft Learn hubs

- [Kusto Query Language](https://learn.microsoft.com/kusto/query/)
- [Scalar functions](https://learn.microsoft.com/kusto/query/scalar-functions)
- [Aggregation functions](https://learn.microsoft.com/kusto/query/aggregation-functions)
- [String operators](https://learn.microsoft.com/kusto/query/datatypes-string-operators)
- [Numerical operators](https://learn.microsoft.com/kusto/query/numerical-operators)
- [Scalar data types](https://learn.microsoft.com/kusto/query/scalar-data-types/)
- [Sentinel tables and connectors](https://learn.microsoft.com/azure/sentinel/sentinel-tables-connectors-reference)
- [Defender XDR schema tables](https://learn.microsoft.com/defender-xdr/advanced-hunting-schema-tables)
