# Coverage gap: inventory vs `catalogs/spl/commands.toml`

Comparison of this docs inventory against the **current** catalog compiled into the engine:

[`catalogs/spl/commands.toml`](../../catalogs/spl/commands.toml)

The catalog is `searchbnf`-informed; OpenTide still owns the grammar. Unknown command tokens become `spl.unknown` / `spl_unknown_command` (`docs/LANGUAGE.md`). Functions not in the catalog simply have no hover / completion / validation.

**Do not treat this file as a mandate to expand the grammar in this change.** It is an inventory of gaps.

## Headline counts

| Surface | In catalog today | Documented in `docs/spl` | Missing from catalog |
| --- | --- | --- | --- |
| Commands (`[[commands]]`) | **17** | **115** unique table names in [commands.md](commands.md) | **98** names (includes aliases / dual rows / adjacent) |
| Eval functions (`kind = "eval"`) | **13** | **107** (93 table rows + 14 trig) | **94** |
| Stats aggregations (`kind = "aggregate"`) | **6** | **35** primary names in [stats-functions.md](stats-functions.md) | **29** primary |
| Search syntax (booleans, macros, comments, subsearches) | not modeled | [search-syntax.md](search-syntax.md) | entire layer |
| CIM / ES fields | not modeled | [common-fields.md](common-fields.md) | entire layer |

Catalog commands (17): `search`, `where`, `eval`, `stats`, `rex`, `table`, `rename`, `fields`, `dedup`, `sort`, `head`, `tail`, `join`, `lookup`, `makemv`, `mvexpand`, `tstats`.

Catalog eval (13): `len`, `lower`, `upper`, `replace`, `strftime`, `strptime`, `if`, `coalesce`, `tonumber`, `tostring`, `md5`, `sha1`, `sha256`.

Catalog aggregates (6): `count`, `sum`, `avg`, `min`, `max`, `dc`.

---

## Top gaps (prioritized for ES / OpenTide detections)

These are the highest-impact misses: they appear constantly in ESCU-style `splunk.query` blocks and will currently tokenize as unknown commands or uncatalogued functions.

### 1. Generating commands beyond `search` / `tstats`

| Missing command | Why it matters |
| --- | --- |
| `inputlookup` | Watchlists, threat intel, baselines as the **first** command |
| `makeresults` | Synthetic rows / test detections |
| `from` | Datamodel / lookup / savedsearch datasets |
| `rest` | Splunk audit detections (`/services/...`) |
| `metadata` | Inventory of hosts/sourcetypes |
| `multisearch` | Parallel streaming legs |
| `datamodel` | Datamodel inspection / search |

`tstats` **is** catalogued, which covers the most common ES generator. Bare `search` is catalogued. Everything else that can legally start a pipeline is a gap.

### 2. Transforming / correlation commands

| Missing command | Why it matters |
| --- | --- |
| `timechart` | Time-binned detections / trending |
| `chart` | Split-by reporting |
| `top` / `rare` | Frequency detections |
| `transaction` | Sessionization (auth bursts, multi-event chains) |
| `eventstats` | Attach population stats then `where` outliers |
| `streamstats` | Sliding-window brute-force / rate |
| `fillnull` | Required before `stats` on sparse CIM fields |
| `bin` / `bucket` | Time/numeric bucketing without `timechart` |
| `xyseries` / `untable` | Table reshape |

### 3. Extraction / filter streaming

| Missing command | Why it matters |
| --- | --- |
| `regex` / `regex field=` | Filter on CommandLine / `_raw` without extracting |
| `spath` | JSON (CloudTrail, kube, o365) |
| `extract` / `kv` | Ad-hoc KV |
| `xmlkv` | XML WinEventLog leftovers |
| `strcat` | Build composite keys |
| `convert` | `ctime`/`mktime` on ES `firstTime`/`lastTime` |
| `outputlookup` | Write baselines |
| `append` / `appendcols` / `appendpipe` | Union-style detections |
| `return` / `format` | Subsearch result shaping |
| `foreach` | Field-wildcard eval |
| `nomv` / `mvcombine` | Mv normalize |
| `rangemap` | Bucket labels |
| `multikv` | Table events |

`rex` is catalogued; `regex` (the **filter** command) is not. That name collision is a parser hazard.

### 4. Eval functions (detection-common, not in catalog)

| Missing | Typical use |
| --- | --- |
| `case` | Multi-way classification |
| `cidrmatch` | RFC1918 / corp ranges in `where` |
| `match` / `like` / `searchmatch` / `in` | Command-line / path matching in `where` |
| `now` / `relative_time` | Age of event, time windows |
| `split` / `mvindex` / `mvcount` / `mvjoin` / `mvfilter` | Parse `process`, hashes, argv |
| `substr` / `trim` | Path / domain slices |
| `isnull` / `isnotnull` / `isnum` / `isstr` / `typeof` | Guard evals |
| `json_extract` / `json_object` | Cloud JSON |
| `round` / `abs` / `ceil` / `floor` / `log` / `pow` / `random` | Numeric / sampling |
| `urldecode` | Encoded URLs / command lines |
| `true` / `false` | Default `case` arm |
| `null` / `coalesce` is present; `null` is not | |

`if` and `coalesce` are catalogued; `case` is the usual next step and is missing.

### 5. Stats aggregations (detection-common, not in catalog)

| Missing | Typical use |
| --- | --- |
| `values` | Collect distinct `src` / `user` onto the notable |
| `list` | Ordered sample of command lines (`stats` only) |
| `earliest` / `latest` | Chronological first/last (≠ `first`/`last`) |
| `first` / `last` | Pipeline-order samples |
| `median` / `perc` / `stdev` / `var` | Outlier thresholds with `eventstats` |
| `mode` / `range` | |
| `estdc` / `exactperc` / `upperperc` | High-cardinality / percentiles |
| `mean` / `stdevp` / `varp` / `sumsq` | |
| `earliest_time` / `latest_time` / `rate` | Counter rates |

ES correlation-search idiom `min(_time) AS firstTime max(_time) AS lastTime` works today because `min`/`max` are catalogued. `values(src) AS src` and `dc(user)` (dc **is** catalogued) are the next most common.

### 6. Syntax the catalog does not describe

The grammar has `bare_search` and pipes; the catalog has no entries for:

- Implied vs authored `search` (policy is documented in [README.md](README.md); catalog `search.docs` currently says “Implicit at the start of a pipeline,” which is the **runtime** fact and must not be implemented as a source rewrite)
- Macros `` `security_content_summariesonly` ``
- Comments ` ```...``` `
- Subsearches `[ ]`
- `IN (...)`
- `TERM()` / `CASE()`
- `AND`/`OR`/`NOT` (and the `search` vs `eval` precedence split)

### 7. Kind mismatches already in the catalog

| Command | Catalog `kind` | Splunk Command types | Notes |
| --- | --- | --- | --- |
| `search` | generating | generating **or** streaming | Correct as primary; later-pipeline `\| search` is streaming |
| `sort` | transforming | **dataset processing** | Catalog follows “reporting-ish”; Splunk does not call `sort` transforming |
| `tail` | streaming | **dataset processing** | Needs the full set |
| `join` | dataset | centralized streaming **or** dataset | Reasonable |
| `dedup` | streaming | streaming, or dataset if `sortby`/`keepevents` | OK for default |
| `table` | transforming | transforming | OK |
| `lookup` | streaming | streaming, or orchestrating if `local=true` | OK for default |

Several catalog rows lack `citation` (`table`, `rename`, `fields`, `dedup`, `sort`, `head`, `tail`, `join`, `lookup`, `makemv`, `mvexpand`, `tstats`, and all `[[functions]]`). Inventory URLs are in [commands.md](commands.md) / [eval-functions.md](eval-functions.md) / [stats-functions.md](stats-functions.md).

---

## Commands in the catalog (covered)

These 17 are the only command names the engine currently treats as first-class:

`search` `tstats` `eval` `where` `stats` `rex` `table` `rename` `fields` `dedup` `sort` `head` `tail` `join` `lookup` `makemv` `mvexpand`

Everything in [commands.md](commands.md) not in that list is a gap. Highest-frequency remaining names, as a punch list:

```
inputlookup makeresults from rest metadata
timechart chart top rare transaction eventstats streamstats
fillnull bin bucket regex spath extract kv xmlkv
strcat convert outputlookup append appendcols return
foreach nomv mvcombine rangemap multikv untable
localop require
```

## Eval functions in the catalog (covered)

`if` `coalesce` `len` `lower` `upper` `replace` `strftime` `strptime` `tonumber` `tostring` `md5` `sha1` `sha256`

Punch list of remaining detection-common evals:

```
case cidrmatch match like searchmatch in true false
now relative_time split mvindex mvcount mvjoin mvfilter
substr trim isnull isnotnull isnum isstr typeof
json_extract json_object round abs ceil floor log pow random
urldecode null
```

## Aggregates in the catalog (covered)

`count` `sum` `avg` `min` `max` `dc`

Punch list:

```
values list earliest latest first last
median perc stdev var mode range
estdc exactperc upperperc
```

---

## Suggested catalog expansion order (docs only; not done here)

1. **Commands:** `regex`, `fillnull`, `spath`, `timechart`, `eventstats`, `streamstats`, `inputlookup`, `bin`, `append`, `outputlookup`, `where` already present — then `transaction`, `top`, `makeresults`, `from`, `convert`, `foreach`.
2. **Eval:** `case`, `match`, `cidrmatch`, `now`, `split`, `mvindex`, `isnull`, `json_extract`, `true`.
3. **Stats:** `values`, `earliest`, `latest`, `list`, `perc`, `stdev`.
4. Fill missing `citation` keys on existing rows using Search Reference `latest` URLs.
5. Do **not** add an implicit `| search` rewrite when expanding `search`; keep authored tokenization.

---

## Out of catalog on purpose (for now)

Still documented in the inventory so implementers can recognize them:

- Orchestrating: `noop`, `redistribute`, `localop` (low frequency in detections)
- Anomaly/ML: `kmeans`, `predict`, `anomalydetection`
- Destructive / side-effect: `delete`, `collect`, `script`, `sendemail`
- App commands: `dbxquery`, ESCU custom commands
- Full trig / bitwise eval sets (needed for completeness, not for v1 completion)

Those are **inventory-complete** and **catalog-deferred**.
