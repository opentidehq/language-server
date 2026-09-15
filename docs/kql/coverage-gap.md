# Coverage gap: `catalogs/kql` vs this inventory

This file compares the machine-readable catalogs under [`/workspace/catalogs/kql/`](../../catalogs/kql/) with the Microsoft Learn–backed inventory in [`/workspace/docs/kql/`](./).

Catalog files examined:

- [`catalogs/kql/core/operators.toml`](../../catalogs/kql/core/operators.toml) — 16 tabular operators
- [`catalogs/kql/core/functions.toml`](../../catalogs/kql/core/functions.toml) — 8 scalar + 8 aggregate names
- [`catalogs/kql/core/types.toml`](../../catalogs/kql/core/types.toml) — 9 types
- [`catalogs/kql/sentinel/tables.toml`](../../catalogs/kql/sentinel/tables.toml) — 18 tables
- [`catalogs/kql/defender/tables.toml`](../../catalogs/kql/defender/tables.toml) — 20 tables

No catalog exists today for scalar operators, syntax, aggregation-as-its-own-file, evaluate plugins, or control commands.

---

## Inventory vs catalog counts

| Area | Catalog now | Inventory | Gap (approx.) |
| --- | --- | --- | --- |
| Tabular operators (primary names) | 16 | **55** | **39** missing |
| Evaluate plugins | 0 | **21** | 21 |
| Control commands (unsupported list) | 0 | 7 families | not modeled |
| Scalar operators (`has`, `in`, `matches regex`, …) | 0 | **50+** | entire file |
| Scalar functions | 8 | **~280 official + aliases (~325)** | **~270+** |
| Aggregation functions | 8 (mixed into functions.toml) | **45** | **37** |
| Scalar types | 9 | **10** | **`decimal`** |
| Sentinel tables (common first-party) | 18 | **~95** named here / **600+** connector catalog | **77+** common; 500+ `_CL` |
| Defender XDR schema tables | 20 | **~65** | **~45** |

---

## Tabular operators

### Present in `operators.toml`

`where`, `project`, `project-away`, `project-rename`, `extend`, `summarize`, `join`, `union`, `parse`, `lookup`, `take`, `limit`, `sort`, `order`, `distinct`, `render` (marked `not_valid_in_detections`).

### Missing (high priority for hunting/detections)

These appear constantly in Sentinel/Defender rule packs:

| Operator | Why it matters |
| --- | --- |
| `filter` | Documented alias of `where` |
| `project-keep`, `project-reorder` | Column shaping |
| `top` | `top 100 by Timestamp` in every hunting sample |
| `count` (operator) | `T \| count` |
| `mv-expand`, `mv-apply` | JSON/array explosion |
| `parse-where`, `parse-kv` | Unstructured CEF/syslog |
| `search`, `find` | Cross-column/table search (`search *` must be flagged **invalid** in Sentinel analytics) |
| `invoke` | Parser/UDF style |
| `evaluate` + `bag_unpack` | Entra `LocationDetails`, dynamic bags |
| `make-series` | Anomaly/time-series rules |
| `serialize`, `scan` | Sequences (pass-the-hash chains, etc.) |
| `as` | Named subqueries / `union withsource` |
| `datatable`, `print`, `range` | IOC tables / debug |
| `partition` | Per-entity subqueries |
| `externaldata` | Must be marked NRT-banned / often blocked |
| `materialize` (function used like an operator) | Query performance |

### Missing (hunting / specialized)

`sample`, `sample-distinct`, `top-hitters`, `top-nested`, `fork`, `facet`, `consume` (invalid in detections), `getschema`, `reduce`, `make-graph`, `graph-match`, `graph-shortest-paths`, `graph-to-table`, `graph-mark-components`.

### Missing validity flags

Only `render` has `warning = "not_valid_in_detections"`. Catalogs should also encode:

- Sentinel ban: `search *`, `union *`
- Defender NRT ban: `join`, `union`, `externaldata`, comments
- Multi-result: `fork`, `facet`
- AM-no: `cluster()`, Python/`sql_request` plugins
- Control commands: `.show`, `.create`, … as **unsupported**

---

## Scalar operators (no catalog file)

[`operators-scalar.md`](operators-scalar.md) is entirely absent from TOML. Top gaps for a future `operators-scalar.toml`:

**Must-have for detections:** `==`, `!=`, `=~`, `!~`, `has`, `has_cs`, `has_any`, `has_all`, `contains`, `startswith`, `endswith`, `in`, `in~`, `!in`, `!in~`, `matches regex`, `between`, `and`, `or`, `not()`, `<` `>` `<=` `>=`, `+ - * / %`.

**Should-have:** `!has`, `contains_cs`, `hasprefix`, `hassuffix` and `_cs`/`!` variants, IPv4 text operators `has_ipv4*`.

---

## Scalar functions

### Present in `functions.toml`

`ago`, `now`, `tostring`, `toint`, `tolong`, `todatetime`, `strcat`, `strlen`.

### Top gaps (appear in public hunting/detection samples)

| Function | Typical use |
| --- | --- |
| `iff` / `iif`, `case`, `coalesce` | Bucketing / nulls |
| `parse_json` / `todynamic`, `extract`, `extract_json` | Dynamic fields |
| `split`, `substring`, `tolower`, `replace_string`, `replace_regex` | Command-line / URL |
| `base64_decode_tostring` | PowerShell `-enc` |
| `parse_command_line` | MDE argv |
| `parse_url`, `parse_path` | URL/path intel |
| `hash_sha256`, `hash_md5`, `hash_sha1` | Hash computed values |
| `ipv4_is_private`, `ipv4_is_in_range`, `ipv4_is_in_any_range` | RFC1918 / allowlists |
| `bin`, `floor` | Time buckets |
| `ingestion_time` | Custom detection lookback |
| `toscalar`, `materialize` | Lets / watchlist scalars |
| `isempty`, `isnotempty`, `isnull` | Null-safe filters |
| `array_length`, `bag_keys`, `bag_pack` / `pack` | Dynamic |
| `geo_info_from_ip_address` | Geo hunting |
| `column_ifexists` | `bag_unpack` + Sentinel analytics |
| `_GetWatchlist` | Sentinel watchlists (AM-only) |

Hundreds of additional documented functions (geo, series_*, math, conversion aliases `toreal`/`toboolean`) are listed in [`scalar-functions.md`](scalar-functions.md) and missing from the catalog.

---

## Aggregation functions

### Present (as `kind = "aggregate"`)

`count`, `sum`, `avg`, `min`, `max`, `dcount`, `arg_max`, `arg_min`.

### Missing (high priority)

`countif`, `sumif`, `avgif`, `minif`, `maxif`, `dcountif`, `count_distinct`, `make_set`, `make_list`, `make_bag`, `make_set_if`, `make_list_if`, `take_any`, `percentile` / `percentiles`, `stdev`, `variance`, `hll`, `tdigest`.

Defender custom-detection docs **explicitly** use `arg_max` (already cataloged) plus `count()`; `make_set` is named in the advanced-hunting operator table as `makeset`.

---

## Types

Catalog has: `string`, `int`, `long`, `real`, `datetime`, `timespan`, `bool`, `dynamic`, `guid`.

**Missing:** `decimal` (and documented aliases `boolean`, `date`, `double`, `uuid`/`uniqueid`, `time`).

No catalog fields for nullability (`string` is not null) or literal syntax.

---

## Sentinel tables

### Present (18)

`SecurityEvent`, `SecurityAlert`, `SecurityIncident`, `Syslog`, `CommonSecurityLog`, `SigninLogs`, `AuditLogs`, `AzureActivity`, plus MDE/XDR names `Device*`, `EmailEvents`, `IdentityLogonEvents`, `CloudAppEvents`, `AADSignInEventsBeta`.

### Top missing first-party tables used in detections

| Area | Missing tables |
| --- | --- |
| Entra | `AADNonInteractiveUserSignInLogs`, `AADServicePrincipalSignInLogs`, `AADManagedIdentitySignInLogs`, `ADFSSignInLogs`, `AADUserRiskEvents`, `AADRiskyUsers`, `AADServicePrincipalRiskEvents`, `MicrosoftGraphActivityLogs`, `AADProvisioningLogs` |
| Windows / logs | `WindowsEvent`, `Event`, `DnsEvents`, `W3CIISLog` |
| Azure | `AzureDiagnostics`, `AZFWNetworkRule`, `AZFWApplicationRule`, `AZFWIdpsSignature`, `StorageBlobLogs` |
| AWS | `AWSCloudTrail`, `AWSGuardDuty`, `AWSVPCFlow`, `AWSWAF` |
| GCP | `GCPAuditLogs`, `GCPVPCFlow` |
| M365 | `OfficeActivity` (**very high**), `UrlClickEvents`, `EmailAttachmentInfo` |
| TI / UEBA | `ThreatIntelligenceIndicator`, `ThreatIntelIndicators`, `BehaviorAnalytics`, `IdentityInfo`, `Anomalies`, `Watchlist` |
| ASIM | `ASimDnsActivityLogs`, `ASimNetworkSessionLogs`, `ASimAuthenticationEventLogs`, … + `_Im_*` parsers |
| Ops | `Heartbeat`, `LAQueryLogs` |
| Defender extras in Sentinel | `AlertEvidence`, `DeviceNetworkInfo`, `IdentityDirectoryEvents`, `IdentityQueryEvents` |

Partner `_CL` tables (Okta, Proofpoint, SAP, …) are in the [600+ connector list](https://learn.microsoft.com/azure/sentinel/sentinel-tables-connectors-reference) and are **not** in the catalog; inventory intentionally only samples NRT-relevant ones.

---

## Defender tables

### Present (20)

Core MDE (`DeviceEvents`, `DeviceProcessEvents`, `DeviceNetworkEvents`, `DeviceFileEvents`, `DeviceRegistryEvents`, `DeviceLogonEvents`, `DeviceImageLoadEvents`, `DeviceInfo`, `DeviceNetworkInfo`, `DeviceFileCertificateInfo`), alerts (`AlertInfo`, `AlertEvidence`), email (`EmailEvents`, `EmailAttachmentInfo`, `EmailUrlInfo`, `UrlClickEvents`), identity (`IdentityLogonEvents`, `IdentityQueryEvents`, `IdentityDirectoryEvents`), `CloudAppEvents`, `AADSignInEventsBeta`.

### Missing schema tables (Learn catalog)

High-value: `EmailPostDeliveryEvents`, `IdentityInfo`, `AADSpnSignInEventsBeta`, `EntraIdSignInEvents`, `GraphAPIAuditEvents`, `OAuthAppInfo`, `MessageEvents`, TVM family (`DeviceTvmSoftwareVulnerabilities`, `DeviceTvmSoftwareInventory`, …), `ExposureGraphNodes`/`Edges`, `CloudAuditEvents`, `CloudProcessEvents`, `BehaviorInfo`, `CampaignInfo`.

### Missing metadata in the catalog

- Required custom-detection output columns (`Timestamp`/`ReportId`/`DeviceId`)
- NRT eligibility per table
- `TimeGenerated` vs `Timestamp`
- Action-specific columns (`NetworkMessageId` + `RecipientEmailAddress` for email actions)

---

## Syntax (no catalog)

[`syntax.md`](syntax.md) covers `let`, comments, `@""` verbatim strings, timespan suffixes, pipes, `datatable`, `print`. None of this is in TOML today. Highest-impact for a parser/linter catalog:

- `let` + semicolon + no blank lines
- `//` comments banned in Defender NRT
- timespan literals `1d` `5m` `1h`
- verbatim `@'…'` for regex and Windows paths
- control commands starting with `.` as **unsupported**

---

## Recommended catalog backfill order

1. Scalar operators (`has`, `in`, `matches regex`, `between`) + validity.
2. High-frequency functions: `parse_json`, `iff`, `bin`, `extract`, `split`, `ipv4_is_private`, `base64_decode_tostring`, `ingestion_time`, `make_set`, `countif`.
3. Operators: `top`, `mv-expand`, `search` (with `search *` illegal), `evaluate`/`bag_unpack`, `datatable`.
4. Tables: `OfficeActivity`, Entra non-interactive/SP tables, `AWSCloudTrail`, `ThreatIntelligenceIndicator`, Defender `EmailPostDeliveryEvents`.
5. Type `decimal`; mark control commands unsupported.
6. Encode Sentinel/Defender/NRT restriction flags instead of a single `render` warning.

See also [`README.md`](README.md) for how catalogs map to these docs.
