//! I/O-free EQL engine for Elastic Security `eql` rules: parse, the checks
//! Elasticsearch's EQL builder makes after the grammar, the function
//! catalog, highlighting, hover, completion, and signature help.
//!
//! Builder checks follow `x-pack/plugin/eql/.../parser/LogicalPlanBuilder.java`
//! and `AbstractBuilder.java`: `maxspan` units, `runs`, sequence and sample
//! sizes, missing events, pipes, and Endgame syntax Elasticsearch rejects.

use opentide_core::{
    ByteSpan, CompletionItem, Diagnostic, LanguageId, ParameterInformation, Position, Range,
    SignatureHelp, SignatureInformation, codes, span_to_range,
};
use opentide_highlight::{HighlightSpec, HighlightToken, tokens_from_spans};
use opentide_syntax::{first_error, node_span, parse as ts_parse};
use serde::Deserialize;
use std::sync::OnceLock;
use tree_sitter::Node;

const FUNCTIONS_TOML: &str = include_str!("../../../catalogs/eql/functions.toml");
const PIPES_TOML: &str = include_str!("../../../catalogs/eql/pipes.toml");

const SYNTAX_DOCS: &str = "https://www.elastic.co/docs/reference/query-languages/eql/eql-syntax";

/// Units `LogicalPlanBuilder.visitSequenceParams` accepts.
const MAXSPAN_UNITS: &[(&str, u64)] = &[
    ("ms", 1),
    ("s", 1_000),
    ("m", 60_000),
    ("h", 3_600_000),
    ("d", 86_400_000),
];

const MAX_RUNS: u64 = 100;
/// A sequence expands to at most this many queries after `runs`.
const MAX_SEQUENCE_QUERIES: u64 = 256;
const KEYWORD_WORDS: &[&str] = &[
    "and", "any", "by", "false", "in", "join", "like", "maxspan", "not", "null", "of", "or",
    "regex", "sample", "sequence", "true", "until", "where", "with",
];
const MAX_SAMPLE_QUERIES: usize = 5;

#[derive(Debug, Deserialize)]
struct FunctionsFile {
    functions: Vec<FunctionRow>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FunctionRow {
    pub name: String,
    pub signature: String,
    #[serde(default)]
    pub docs: String,
    #[serde(default)]
    pub returns: Vec<String>,
    #[serde(default)]
    pub case_insensitive: bool,
    /// Argument counts the function registry accepts; `max_args` absent is unbounded.
    #[serde(default)]
    pub min_args: usize,
    #[serde(default)]
    pub max_args: Option<usize>,
    #[serde(default)]
    pub citation: Option<String>,
    #[serde(default)]
    pub parameters: Vec<ParamRow>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ParamRow {
    pub name: String,
    #[serde(default)]
    pub docs: String,
    #[serde(default)]
    pub types: Vec<String>,
    #[serde(default)]
    pub required: bool,
}

#[derive(Debug, Deserialize)]
struct PipesFile {
    pipes: Vec<PipeRow>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PipeRow {
    pub name: String,
    pub signature: String,
    #[serde(default)]
    pub docs: String,
    #[serde(default)]
    pub citation: Option<String>,
}

#[derive(Debug)]
pub struct Catalog {
    pub functions: Vec<FunctionRow>,
    pub pipes: Vec<PipeRow>,
}

impl Catalog {
    pub fn cached() -> &'static Catalog {
        static CATALOG: OnceLock<Catalog> = OnceLock::new();
        CATALOG.get_or_init(|| {
            let functions: FunctionsFile = toml::from_str(FUNCTIONS_TOML).expect("eql functions");
            let pipes: PipesFile = toml::from_str(PIPES_TOML).expect("eql pipes");
            Catalog {
                functions: functions.functions,
                pipes: pipes.pipes,
            }
        })
    }

    /// The registry resolves function names case-insensitively: Elastic's own
    /// rules write `cidrmatch`. Matching *behaviour* is case-sensitive unless
    /// the call uses `~`.
    pub fn function(&self, name: &str) -> Option<&FunctionRow> {
        self.functions
            .iter()
            .find(|f| f.name.eq_ignore_ascii_case(name))
    }

    pub fn pipe(&self, name: &str) -> Option<&PipeRow> {
        self.pipes.iter().find(|p| p.name == name)
    }
}

/// Keywords and operators with a syntax-reference anchor, for hover.
const KEYWORDS: &[(&str, &str, &str)] = &[
    (
        "sequence",
        "Matches an ordered series of events.",
        "eql-sequences",
    ),
    (
        "sample",
        "Matches events that share join keys, in any order.",
        "eql-samples",
    ),
    (
        "by",
        "Join keys: events must share these field values.",
        "eql-by-keyword",
    ),
    (
        "maxspan",
        "Time span a sequence must fit in. Units: `ms`, `s`, `m`, `h`, `d`.",
        "eql-with-maxspan-keywords",
    ),
    (
        "until",
        "Expiration event: a sequence that has not completed when it matches is discarded.",
        "eql-until-keyword",
    ),
    (
        "runs",
        "Repeat the preceding sequence query `runs` times (1 to 100).",
        "eql-with-runs-statement",
    ),
    (
        "any",
        "Matches events of any category.",
        "eql-syntax-match-any-event-category",
    ),
    ("where", "Event condition.", "eql-basic-syntax"),
    (
        ":",
        "Case-insensitive equality with `*` and `?` wildcards. Same as `like~`.",
        "eql-syntax-comparison-operators",
    ),
    (
        "like",
        "Case-sensitive wildcard match.",
        "eql-syntax-pattern-comparison-keywords",
    ),
    (
        "like~",
        "Case-insensitive wildcard match.",
        "eql-syntax-pattern-comparison-keywords",
    ),
    (
        "regex",
        "Case-sensitive regular expression match.",
        "eql-syntax-pattern-comparison-keywords",
    ),
    (
        "regex~",
        "Case-insensitive regular expression match.",
        "eql-syntax-pattern-comparison-keywords",
    ),
    (
        "in",
        "Case-sensitive membership in a list.",
        "eql-syntax-lookup-operators",
    ),
    (
        "in~",
        "Case-insensitive membership in a list.",
        "eql-syntax-lookup-operators",
    ),
    (
        "![",
        "Missing event: the sequence matches only when no such event occurs. Needs `maxspan`.",
        "eql-missing-events",
    ),
    (
        "?",
        "Optional field: a missing field reads as `null` instead of failing the query.",
        "eql-syntax-optional-fields",
    ),
];

pub struct AnalyzeResult {
    pub diagnostics: Vec<Diagnostic>,
    pub tokens: Vec<HighlightToken>,
}

pub fn analyze(source: &str) -> AnalyzeResult {
    let spec = HighlightSpec::load().expect("highlight spec");
    let catalog = Catalog::cached();
    let Some(tree) = ts_parse(LanguageId::Eql, source) else {
        return AnalyzeResult {
            diagnostics: vec![Diagnostic::error(
                codes::EQL_PARSE_ERROR,
                "failed to initialize the EQL parser",
                Range::point(0, 0),
            )],
            tokens: Vec::new(),
        };
    };
    let root = tree.root_node();
    let mut out = Vec::new();
    if let Some(err) = first_error(root) {
        out.push(Diagnostic::error(
            codes::EQL_PARSE_ERROR,
            parse_error_message(err, source),
            range(source, node_span(err)),
        ));
    }
    walk(root, &mut |node| {
        check_node(node, source, catalog, &mut out)
    });
    check_pipes(root, source, catalog, &mut out);
    let tokens = highlight(&spec, source);
    AnalyzeResult {
        diagnostics: out,
        tokens,
    }
}

fn parse_error_message(err: Node, source: &str) -> String {
    if err.is_missing() {
        return format!("EQL syntax error: missing `{}`", err.kind());
    }
    let snippet = text(err, source).trim();
    if snippet.starts_with('=') && !snippet.starts_with("==") {
        return "EQL syntax error: use `==` for equality; `=` is not a comparison".into();
    }
    match snippet.split_whitespace().next() {
        Some(first) => {
            let lower = first.to_ascii_lowercase();
            if KEYWORD_WORDS.contains(&lower.as_str()) && first != lower {
                format!("EQL syntax error near `{first}`: keywords are lower case (`{lower}`)")
            } else {
                format!("EQL syntax error near `{first}`")
            }
        }
        None => "EQL syntax error".into(),
    }
}

fn check_node(node: Node, source: &str, catalog: &Catalog, out: &mut Vec<Diagnostic>) {
    // Keyword tokens share their kind with the node (`sequence`, `join`).
    if !node.is_named() {
        return;
    }
    match node.kind() {
        "string" => check_string(node, source, out),
        "index" => out.push(Diagnostic::error(
            codes::EQL_UNSUPPORTED,
            "array indexes are not supported in Elasticsearch EQL",
            range(source, node_span(node)),
        )),
        "field" => check_field_case(node, source, out),
        "event_category" => check_category_case(node, source, out),
        "comparison" => check_literal_wildcard(node, source, out),
        "predicate_expression" => check_literal_wildcard(node, source, out),
        "function_call" => check_function(node, source, catalog, out),
        "sequence" => check_sequence(node, source, out),
        "sample" => check_sample(node, source, out),
        "join" => out.push(unsupported(
            node,
            source,
            "Elasticsearch EQL does not support `join`; use `sequence` or `sample`",
            keyword_span(node),
        )),
        "relationship" => {
            let relation = node
                .child_by_field_name("relation")
                .map(|n| text(n, source))
                .unwrap_or("of");
            out.push(unsupported(
                node,
                source,
                &format!("Elasticsearch EQL does not support the lineage keyword `{relation} of`"),
                node_span(node),
            ));
        }
        "subquery" => {
            let missing = node
                .child_by_field_name("open")
                .is_some_and(|o| o.kind() == "missing_event_open");
            let in_sequence = node
                .parent()
                .and_then(|p| p.parent())
                .is_some_and(|g| g.kind() == "sequence");
            if missing && !in_sequence {
                out.push(Diagnostic::error(
                    codes::EQL_PARSE_ERROR,
                    "missing events (`![ ... ]`) are supported only in sequences",
                    range(source, node_span(node)),
                ));
            }
        }
        _ => {}
    }
}

fn check_string(node: Node, source: &str, out: &mut Vec<Diagnostic>) {
    let t = text(node, source);
    let message = if t.starts_with('\'') {
        Some("use double quotes [\"] for string literals, not single quotes [']")
    } else if t.starts_with('?') {
        Some(
            "`?\"` and `?'` are not raw strings in Elasticsearch EQL; use triple double quotes [\"\"\"]",
        )
    } else {
        None
    };
    if let Some(message) = message {
        out.push(unsupported(node, source, message, node_span(node)));
        return;
    }
    if t.starts_with("\"\"\"") {
        return;
    }
    // `"…"` accepts only these escapes; anything else fails the lexer.
    let bytes = t.as_bytes();
    let mut i = 1;
    while i + 1 < bytes.len() {
        if bytes[i] != b'\\' {
            i += 1;
            continue;
        }
        let next = bytes[i + 1];
        let bad = match next {
            b'b' | b't' | b'n' | b'f' | b'r' | b'"' | b'\'' | b'\\' => false,
            b'u' => {
                let rest = &t[i + 2..];
                let digits = rest
                    .strip_prefix('{')
                    .and_then(|r| r.split_once('}'))
                    .map(|(h, _)| h);
                !digits.is_some_and(|h| {
                    (2..=8).contains(&h.len()) && h.chars().all(|c| c.is_ascii_hexdigit())
                })
            }
            _ => true,
        };
        if bad {
            let at = node.start_byte() + i;
            out.push(Diagnostic::error(
                codes::EQL_PARSE_ERROR,
                format!(
                    "invalid escape `\\{}`: EQL strings accept \\b \\t \\n \\f \\r \\\" \\' \\\\ and \\u{{2-8 hex}}; use `\\\\` or a triple-quoted string",
                    next as char
                ),
                range(source, ByteSpan::new(at, at + 2)),
            ));
            return;
        }
        i += 2;
    }
}

/// `x == TRUE` reads a field named `TRUE`: keywords are lower case.
fn check_field_case(node: Node, source: &str, out: &mut Vec<Diagnostic>) {
    let t = text(node, source).trim_start_matches('?').trim();
    let lower = t.to_ascii_lowercase();
    if KEYWORD_WORDS.contains(&lower.as_str()) && t != lower {
        out.push(
            Diagnostic::warning(
                codes::EQL_CASE_SENSITIVE,
                format!("EQL keywords are lower case: `{t}` here is a field name, not `{lower}`"),
                range(source, node_span(node)),
            )
            .with_suggestion(lower),
        );
    }
}

/// Categories compare case-sensitively with `event.category`, which ECS
/// keeps lower case: `PROCESS where` matches nothing.
fn check_category_case(node: Node, source: &str, out: &mut Vec<Diagnostic>) {
    let t = text(node, source).trim_matches('"');
    if t.chars().any(|c| c.is_ascii_uppercase()) {
        out.push(
            Diagnostic::warning(
                codes::EQL_CASE_SENSITIVE,
                format!(
                    "event category `{t}` is compared case-sensitively; ECS categories are lower case"
                ),
                range(source, node_span(node)),
            )
            .with_suggestion(t.to_ascii_lowercase()),
        );
    }
}

/// `==`, `!=`, `in`, and `in~` do not expand wildcards, so `"*.exe"` is
/// matched literally. A `*` next to a backslash (`\\*\\ADMIN$`) is left alone.
fn check_literal_wildcard(node: Node, source: &str, out: &mut Vec<Diagnostic>) {
    let operator = node
        .child_by_field_name("operator")
        .map(|o| text(o, source))
        .unwrap_or("");
    if !matches!(operator, "==" | "!=" | "in" | "in~") {
        return;
    }
    let mut cursor = node.walk();
    let candidates: Vec<Node> = if node.kind() == "comparison" {
        node.child_by_field_name("right").into_iter().collect()
    } else {
        node.children_by_field_name("values", &mut cursor).collect()
    };
    for value in candidates {
        if value.kind() != "string" {
            continue;
        }
        let t = text(value, source);
        let bytes = t.as_bytes();
        let wild = bytes.iter().enumerate().any(|(i, b)| {
            *b == b'*'
                && bytes.get(i.wrapping_sub(1)) != Some(&b'\\')
                && bytes.get(i + 1) != Some(&b'\\')
        });
        if wild {
            let suggestion = if operator.starts_with("in") {
                ":"
            } else {
                "like"
            };
            out.push(
                Diagnostic::warning(
                    codes::EQL_LITERAL_WILDCARD,
                    format!(
                        "`{operator}` matches `*` literally; use `{suggestion}` for a wildcard"
                    ),
                    range(source, node_span(value)),
                )
                .with_suggestion(suggestion),
            );
            return;
        }
    }
}

fn check_function(node: Node, source: &str, catalog: &Catalog, out: &mut Vec<Diagnostic>) {
    let Some(name_node) = node.child_by_field_name("name") else {
        return;
    };
    let raw = text(name_node, source);
    let (name, insensitive) = match raw.strip_suffix('~') {
        Some(base) => (base, true),
        None => (raw, false),
    };
    let span = node_span(name_node);
    match catalog.function(name) {
        Some(row) if insensitive && !row.case_insensitive => out.push(Diagnostic::error(
            codes::EQL_UNKNOWN_FUNCTION,
            format!("function `{name}` has no case-insensitive `{name}~` form"),
            range(source, span),
        )),
        Some(row) => {
            let mut c = node.walk();
            // The field spans the comma list, so count named nodes only.
            let args = node
                .children_by_field_name("arguments", &mut c)
                .filter(|n| n.is_named())
                .count();
            let too_many = row.max_args.is_some_and(|m| args > m);
            if args < row.min_args || too_many {
                let expected = match row.max_args {
                    Some(m) if m == row.min_args => format!("{m}"),
                    Some(m) => format!("{} to {m}", row.min_args),
                    None => format!("at least {}", row.min_args),
                };
                out.push(Diagnostic::error(
                    codes::EQL_FUNCTION_ARITY,
                    format!("`{}` takes {expected} arguments, found {args}", row.name),
                    range(source, node_span(node)),
                ));
            }
        }
        None => {
            let mut d = Diagnostic::error(
                codes::EQL_UNKNOWN_FUNCTION,
                format!("unknown EQL function `{name}`"),
                range(source, span),
            );
            if let Some(s) = catalog
                .functions
                .iter()
                .map(|f| (f.name.as_str(), edit_distance(&f.name, name)))
                .filter(|(_, d)| *d <= 2)
                .min_by_key(|(_, d)| *d)
                .map(|(n, _)| n)
            {
                if s != name {
                    d = d.with_suggestion(s);
                }
            }
            out.push(d);
        }
    }
}

fn check_sequence(node: Node, source: &str, out: &mut Vec<Diagnostic>) {
    let mut cursor = node.walk();
    let children: Vec<Node> = node.children(&mut cursor).collect();
    // `sequence with maxspan=... by k` is rejected: `by` must come first.
    let params_pos = children.iter().position(|c| c.kind() == "sequence_params");
    let by_pos = children.iter().position(|c| {
        c.kind() == "join_keys" && node.child_by_field_name("by").map(|b| b.id()) == Some(c.id())
    });
    if let (Some(p), Some(b)) = (params_pos, by_pos) {
        if p < b {
            out.push(Diagnostic::error(
                codes::EQL_PARSE_ERROR,
                "specify sequence `by` before `with maxspan`, not after",
                range(source, node_span(children[b])),
            ));
        }
    }
    let maxspan = params_pos.and_then(|p| children[p].child_by_field_name("maxspan"));
    if let Some(unit) = maxspan {
        check_maxspan(unit, source, out);
    }
    let mut queries = 0u64;
    let mut missing = 0usize;
    let mut cursor = node.walk();
    for term in node.children_by_field_name("term", &mut cursor) {
        let is_missing = term
            .named_child(0)
            .and_then(|s| s.child_by_field_name("open"))
            .is_some_and(|o| o.kind() == "missing_event_open");
        if is_missing {
            missing += 1;
        }
        queries += check_runs(term, source, out);
    }
    if queries < 2 {
        out.push(Diagnostic::error(
            codes::EQL_PARSE_ERROR,
            format!("a sequence requires a minimum of 2 queries, found [{queries}]"),
            range(source, keyword_span(node)),
        ));
    }
    if queries > MAX_SEQUENCE_QUERIES {
        out.push(Diagnostic::error(
            codes::EQL_PARSE_ERROR,
            format!(
                "a sequence cannot contain more than {MAX_SEQUENCE_QUERIES} queries after `runs`, found [{queries}]"
            ),
            range(source, keyword_span(node)),
        ));
    }
    check_key_counts(node, source, out);
    if missing > 0 && maxspan.is_none() {
        out.push(Diagnostic::error(
            codes::EQL_PARSE_ERROR,
            "`maxspan` is required for sequences with missing events",
            range(source, keyword_span(node)),
        ));
    }
    if missing > 0 && missing as u64 >= queries {
        out.push(Diagnostic::error(
            codes::EQL_PARSE_ERROR,
            "a sequence requires at least one positive event query",
            range(source, keyword_span(node)),
        ));
    }
}

/// Number of queries a term contributes (`with runs=n` repeats it).
fn check_runs(term: Node, source: &str, out: &mut Vec<Diagnostic>) -> u64 {
    let Some(option) = term.child_by_field_name("term_option").or_else(|| {
        let mut c = term.walk();
        term.named_children(&mut c)
            .find(|n| n.kind() == "term_option")
    }) else {
        return 1;
    };
    let key = option
        .child_by_field_name("key")
        .map(|k| text(k, source))
        .unwrap_or("");
    if key != "runs" {
        out.push(Diagnostic::error(
            codes::EQL_PARSE_ERROR,
            format!("unrecognized option [{key}], expecting [runs]"),
            range(source, node_span(option)),
        ));
        return 1;
    }
    let value = option
        .child_by_field_name("value")
        .map(|v| text(v, source))
        .unwrap_or("");
    match value.parse::<u64>() {
        Ok(n) if (1..=MAX_RUNS).contains(&n) => n,
        Ok(n) if n > MAX_RUNS => {
            out.push(Diagnostic::error(
                codes::EQL_PARSE_ERROR,
                format!("a query cannot be repeated more than {MAX_RUNS} times; found [{n}]"),
                range(source, node_span(option)),
            ));
            1
        }
        _ => {
            out.push(Diagnostic::error(
                codes::EQL_PARSE_ERROR,
                format!("a positive integer `runs` value is required; found [{value}]"),
                range(source, node_span(option)),
            ));
            1
        }
    }
}

fn check_maxspan(unit: Node, source: &str, out: &mut Vec<Diagnostic>) {
    let value = unit
        .child_by_field_name("value")
        .map(|v| text(v, source))
        .unwrap_or("");
    let suffix = unit.child_by_field_name("unit").map(|u| text(u, source));
    let span = node_span(unit);
    match value.parse::<u64>() {
        Ok(0) => out.push(Diagnostic::error(
            codes::EQL_MAXSPAN_UNIT,
            "a positive `maxspan` value is required; found [0]",
            range(source, span),
        )),
        Ok(_) => {}
        Err(_) => out.push(Diagnostic::error(
            codes::EQL_MAXSPAN_UNIT,
            format!("decimal time interval [{value}] is not supported; use a positive integer"),
            range(source, span),
        )),
    }
    match suffix {
        None => out.push(
            Diagnostic::error(
                codes::EQL_MAXSPAN_UNIT,
                format!("no time unit in `maxspan={value}`; use one of ms, s, m, h, d"),
                range(source, span),
            )
            .with_suggestion(format!("{value}s")),
        ),
        Some(u) if !MAXSPAN_UNITS.iter().any(|(name, _)| *name == u) => {
            out.push(Diagnostic::error(
                codes::EQL_MAXSPAN_UNIT,
                format!("unrecognized time unit [{u}] in `maxspan`; use one of ms, s, m, h, d"),
                range(source, span),
            ))
        }
        Some(_) => {}
    }
}

fn check_sample(node: Node, source: &str, out: &mut Vec<Diagnostic>) {
    let mut cursor = node.walk();
    let terms: Vec<Node> = node.children_by_field_name("term", &mut cursor).collect();
    if terms.len() < 2 {
        out.push(Diagnostic::error(
            codes::EQL_PARSE_ERROR,
            format!(
                "a sample requires a minimum of 2 queries, found [{}]",
                terms.len()
            ),
            range(source, keyword_span(node)),
        ));
    }
    if terms.len() > MAX_SAMPLE_QUERIES {
        out.push(Diagnostic::error(
            codes::EQL_PARSE_ERROR,
            format!(
                "a sample cannot contain more than {MAX_SAMPLE_QUERIES} queries, found [{}]",
                terms.len()
            ),
            range(source, node_span(terms[MAX_SAMPLE_QUERIES])),
        ));
    }
    check_key_counts(node, source, out);
    let shared_keys = node.child_by_field_name("by").is_some();
    if !shared_keys && terms.iter().any(|t| t.child_by_field_name("by").is_none()) {
        out.push(Diagnostic::error(
            codes::EQL_PARSE_ERROR,
            "a sample must have at least one join key, found none",
            range(source, keyword_span(node)),
        ));
    }
}

/// Every term of a sequence or sample (and `until`) names the same number
/// of join keys.
fn check_key_counts(node: Node, source: &str, out: &mut Vec<Diagnostic>) {
    let mut terms = Vec::new();
    let mut cursor = node.walk();
    terms.extend(node.children_by_field_name("term", &mut cursor));
    if let Some(until) = node.child_by_field_name("until") {
        terms.push(until);
    }
    let mut expected: Option<usize> = None;
    for term in terms {
        let keys = term
            .child_by_field_name("by")
            .map_or(0, |b| b.named_child_count());
        match expected {
            None => expected = Some(keys),
            Some(e) if e != keys => {
                let at = term.child_by_field_name("by").unwrap_or(term);
                out.push(Diagnostic::error(
                    codes::EQL_PARSE_ERROR,
                    format!("inconsistent number of join keys specified; expected [{e}] but found [{keys}]"),
                    range(source, node_span(at)),
                ));
                return;
            }
            _ => {}
        }
    }
}

fn check_pipes(root: Node, source: &str, catalog: &Catalog, out: &mut Vec<Diagnostic>) {
    let is_sample = root
        .child_by_field_name("query")
        .is_some_and(|q| q.kind() == "sample");
    let mut cursor = root.walk();
    for pipe in root.children_by_field_name("pipe", &mut cursor) {
        let Some(name_node) = pipe.child_by_field_name("name") else {
            continue;
        };
        let name = text(name_node, source);
        if is_sample {
            out.push(Diagnostic::error(
                codes::EQL_UNSUPPORTED,
                "samples do not support pipes",
                range(source, node_span(pipe)),
            ));
            continue;
        }
        if catalog.pipe(name).is_none() {
            let endgame = matches!(
                name,
                "count" | "filter" | "sort" | "unique" | "unique_count"
            );
            let message = if endgame {
                format!(
                    "Elasticsearch EQL does not support the `{name}` pipe; only `head` and `tail`"
                )
            } else {
                format!("unrecognized pipe [{name}]; Elasticsearch EQL supports `head` and `tail`")
            };
            out.push(unsupported(pipe, source, &message, node_span(name_node)));
            continue;
        }
        let mut c = pipe.walk();
        let args: Vec<Node> = pipe
            .children_by_field_name("arguments", &mut c)
            .filter(|n| n.is_named())
            .collect();
        let positive_int = args.len() == 1
            && args[0].kind() == "number"
            && text(args[0], source).parse::<u32>().is_ok();
        if !positive_int {
            out.push(Diagnostic::error(
                codes::EQL_PARSE_ERROR,
                format!("pipe [{name}] expects exactly one positive integer argument"),
                range(source, node_span(pipe)),
            ));
        }
    }
}

fn unsupported(_node: Node, source: &str, message: &str, span: ByteSpan) -> Diagnostic {
    Diagnostic::error(codes::EQL_UNSUPPORTED, message, range(source, span))
}

fn keyword_span(node: Node) -> ByteSpan {
    let first = node.child(0).unwrap_or(node);
    node_span(first)
}

fn walk<'t>(node: Node<'t>, f: &mut impl FnMut(Node<'t>)) {
    f(node);
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk(child, f);
    }
}

fn range(source: &str, span: ByteSpan) -> Range {
    span_to_range(source, span)
}

fn text<'a>(node: Node, source: &'a str) -> &'a str {
    source.get(node.start_byte()..node.end_byte()).unwrap_or("")
}

fn edit_distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.iter().enumerate() {
        let mut cur = vec![i + 1];
        for (j, cb) in b.iter().enumerate() {
            let cost = usize::from(!ca.eq_ignore_ascii_case(cb));
            cur.push((prev[j] + cost).min(prev[j + 1] + 1).min(cur[j] + 1));
        }
        prev = cur;
    }
    prev[b.len()]
}

fn highlight(spec: &HighlightSpec, source: &str) -> Vec<HighlightToken> {
    let Ok(mut spans) = opentide_syntax::query_captures(
        LanguageId::Eql,
        source,
        opentide_highlight::EQL_HIGHLIGHTS_SCM,
    ) else {
        return Vec::new();
    };
    let catalog = Catalog::cached();
    for (span, capture) in spans.iter_mut() {
        if capture == "function" {
            let name = source.get(span.start..span.end).unwrap_or("");
            if catalog.function(name.trim_end_matches('~')).is_some() {
                *capture = "function.builtin".into();
            }
        }
    }
    let refs: Vec<(ByteSpan, &str)> = spans.iter().map(|(s, c)| (*s, c.as_str())).collect();
    tokens_from_spans(spec, source, &refs).unwrap_or_default()
}

/// Each `with maxspan=` in the query: its span and length in milliseconds.
/// Tide compares these with the rule's `scheduling` ([elastic-1.0] Advisories).
pub fn sequence_maxspans(source: &str) -> Vec<(ByteSpan, u64)> {
    let Some(tree) = ts_parse(LanguageId::Eql, source) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    walk(tree.root_node(), &mut |node| {
        if node.kind() != "time_unit" {
            return;
        }
        let value = node
            .child_by_field_name("value")
            .and_then(|v| text(v, source).parse::<u64>().ok());
        let unit = node.child_by_field_name("unit").map(|u| text(u, source));
        let factor =
            unit.and_then(|u| MAXSPAN_UNITS.iter().find(|(n, _)| *n == u).map(|(_, f)| *f));
        if let (Some(v), Some(f)) = (value, factor) {
            out.push((node_span(node), v.saturating_mul(f)));
        }
    });
    out
}

// ---- Hover ----------------------------------------------------------------

pub fn hover(source: &str, position: Position) -> Option<String> {
    let offset = position_to_offset(source, position);
    let tree = ts_parse(LanguageId::Eql, source)?;
    let node = tree.root_node().descendant_for_byte_range(offset, offset)?;
    let catalog = Catalog::cached();
    let parent = node.parent();
    if parent.is_some_and(|p| p.kind() == "function_call") {
        let name = text(node, source).trim_end_matches('~');
        if let Some(row) = catalog.function(name) {
            return Some(function_hover(row));
        }
    }
    if parent.is_some_and(|p| p.kind() == "pipe") {
        if let Some(row) = catalog.pipe(text(node, source)) {
            let mut md = format!(
                "**{}** (pipe)\n\n```eql\n{}\n```\n\n{}",
                row.name, row.signature, row.docs
            );
            if let Some(c) = &row.citation {
                md.push_str(&format!("\n\n[Elastic docs]({c})"));
            }
            return Some(md);
        }
    }
    let word = match node.kind() {
        "missing_event_open" => "![",
        "optional_marker" => "?",
        _ => text(node, source),
    };
    KEYWORDS
        .iter()
        .find(|(k, _, _)| *k == word)
        .map(|(k, doc, anchor)| {
            format!("**`{k}`**\n\n{doc}\n\n[Elastic docs]({SYNTAX_DOCS}#{anchor})")
        })
}

fn function_hover(row: &FunctionRow) -> String {
    let mut md = format!(
        "**{}** (function)\n\n```eql\n{}\n```",
        row.name, row.signature
    );
    if !row.docs.is_empty() {
        md.push_str(&format!("\n\n{}", row.docs));
    }
    if !row.parameters.is_empty() {
        md.push_str("\n\n**Parameters**\n");
        for p in &row.parameters {
            let optional = if p.required { "" } else { " (optional)" };
            md.push_str(&format!(
                "\n- `{}`{optional} _{}_ — {}",
                p.name,
                p.types.join(" | "),
                p.docs
            ));
        }
    }
    if !row.returns.is_empty() {
        md.push_str(&format!("\n\n**Returns** _{}_", row.returns.join(" | ")));
    }
    if row.case_insensitive {
        md.push_str(&format!("\n\nCase-insensitive form: `{}~(...)`.", row.name));
    }
    if let Some(c) = &row.citation {
        md.push_str(&format!("\n\n[Elastic docs]({c})"));
    }
    md
}

// ---- Completion -----------------------------------------------------------

/// ECS `event.category` values, the usual EQL event categories.
const EVENT_CATEGORIES: &[&str] = &[
    "any",
    "api",
    "authentication",
    "configuration",
    "database",
    "driver",
    "email",
    "file",
    "host",
    "iam",
    "intrusion_detection",
    "library",
    "malware",
    "network",
    "package",
    "process",
    "registry",
    "session",
    "threat",
    "vulnerability",
    "web",
];

pub fn completions(source: &str, offset: usize) -> Vec<CompletionItem> {
    let catalog = Catalog::cached();
    let before = &source[..offset.min(source.len())];
    let trimmed = before.trim_end();
    if trimmed.is_empty() {
        let mut items: Vec<CompletionItem> = ["sequence", "sample"]
            .iter()
            .map(|k| CompletionItem::new(*k, "keyword"))
            .collect();
        items.extend(
            EVENT_CATEGORIES
                .iter()
                .map(|c| CompletionItem::new(*c, "type")),
        );
        return items;
    }
    if trimmed.ends_with('|') {
        return catalog
            .pipes
            .iter()
            .map(|p| {
                CompletionItem::new(p.name.clone(), "command")
                    .with_detail(p.signature.clone())
                    .with_docs(p.docs.clone())
            })
            .collect();
    }
    if trimmed.ends_with('[') {
        return EVENT_CATEGORIES
            .iter()
            .map(|c| CompletionItem::new(*c, "type"))
            .collect();
    }
    if trimmed.ends_with("maxspan=") {
        return MAXSPAN_UNITS
            .iter()
            .map(|(u, _)| CompletionItem::new(format!("1{u}"), "enum"))
            .collect();
    }
    let mut items: Vec<CompletionItem> = catalog
        .functions
        .iter()
        .map(|f| {
            CompletionItem::new(f.name.clone(), "function")
                .with_detail(f.signature.clone())
                .with_docs(function_hover(f))
        })
        .collect();
    for kw in [
        "and", "or", "not", "in", "in~", "like", "like~", "regex", "regex~", "where", "by", "with",
        "until",
    ] {
        items.push(CompletionItem::new(kw, "keyword"));
    }
    items.extend(
        fields_in(source)
            .into_iter()
            .map(|f| CompletionItem::new(f, "property")),
    );
    items
}

fn fields_in(source: &str) -> Vec<String> {
    let Some(tree) = ts_parse(LanguageId::Eql, source) else {
        return Vec::new();
    };
    let mut names = std::collections::BTreeSet::new();
    walk(tree.root_node(), &mut |node| {
        if node.kind() == "field" && !node.has_error() {
            names.insert(text(node, source).trim_start_matches('?').to_string());
        }
    });
    names.into_iter().collect()
}

// ---- Signature help -------------------------------------------------------

pub fn signature_help(source: &str, offset: usize) -> Option<SignatureHelp> {
    let before = &source[..offset.min(source.len())];
    let (name, active) = innermost_call(before)?;
    let row = Catalog::cached().function(name.trim_end_matches('~'))?;
    let parameters: Vec<ParameterInformation> = row
        .parameters
        .iter()
        .map(|p| ParameterInformation {
            label: format!("<{}>", p.name),
            documentation: Some(format!("_{}_", p.types.join(" | "))),
        })
        .collect();
    let active = active.min(parameters.len().saturating_sub(1) as u32);
    Some(SignatureHelp {
        signatures: vec![SignatureInformation {
            label: row.signature.clone(),
            documentation: Some(row.docs.clone()),
            parameters,
        }],
        active_signature: 0,
        active_parameter: active,
    })
}

fn innermost_call(before: &str) -> Option<(String, u32)> {
    let bytes = before.as_bytes();
    let mut stack: Vec<(usize, u32)> = Vec::new();
    let mut in_string = false;
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if in_string {
            if b == b'\\' {
                i += 1;
            } else if b == b'"' {
                in_string = false;
            }
        } else {
            match b {
                b'"' => in_string = true,
                b'(' => stack.push((i, 0)),
                b')' => {
                    stack.pop();
                }
                b',' => {
                    if let Some(top) = stack.last_mut() {
                        top.1 += 1;
                    }
                }
                _ => {}
            }
        }
        i += 1;
    }
    let (open, commas) = *stack.last()?;
    let name_start = before[..open]
        .rfind(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '~'))
        .map(|i| i + 1)
        .unwrap_or(0);
    let name = before[name_start..open].to_string();
    (!name.is_empty()).then_some((name, commas))
}

fn position_to_offset(source: &str, position: Position) -> usize {
    let mut line = 0u32;
    let mut col = 0u32;
    for (idx, ch) in source.char_indices() {
        if line == position.line && col >= position.character {
            return idx;
        }
        if ch == '\n' {
            line += 1;
            col = 0;
        } else {
            col += ch.len_utf16() as u32;
        }
    }
    source.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn codes_of(src: &str) -> Vec<String> {
        analyze(src)
            .diagnostics
            .into_iter()
            .map(|d| d.code)
            .collect()
    }

    #[test]
    fn detection_rule_is_clean() {
        let src = "sequence by host.id with maxspan=1m\n  [process where event.type == \"start\" and process.name : \"cmd.exe\"]\n  [network where startsWith~(process.name, \"cmd\")]";
        let r = analyze(src);
        assert!(r.diagnostics.is_empty(), "{:?}", r.diagnostics);
        assert!(r.tokens.iter().any(|t| t.capture == "function.builtin"));
    }

    #[test]
    fn maxspan_units_follow_the_builder() {
        let c = codes_of("sequence with maxspan=5w [process where true] [file where true]");
        assert!(c.contains(&codes::EQL_MAXSPAN_UNIT.to_string()), "{c:?}");
        let c = codes_of("sequence with maxspan=5 [process where true] [file where true]");
        assert!(c.contains(&codes::EQL_MAXSPAN_UNIT.to_string()), "{c:?}");
        assert!(
            codes_of("sequence with maxspan=500ms [process where true] [file where true]")
                .is_empty()
        );
    }

    #[test]
    fn maxspans_are_in_milliseconds() {
        let spans = sequence_maxspans("sequence with maxspan=500ms [a where true] [b where true]");
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].1, 500);
        let spans = sequence_maxspans("sequence with maxspan=2h [a where true] [b where true]");
        assert_eq!(spans[0].1, 7_200_000);
    }

    #[test]
    fn endgame_syntax_is_unsupported() {
        for src in [
            "process where process.name == 'cmd.exe'",
            "process where descendant of [process where true]",
            "process where true | unique process.name",
            "join [process where true] [file where true]",
        ] {
            assert!(
                codes_of(src).contains(&codes::EQL_UNSUPPORTED.to_string()),
                "{src}"
            );
        }
    }

    #[test]
    fn functions_resolve_case_insensitively_and_tilde_is_checked() {
        assert!(
            codes_of("process where startsWth(process.name, \"a\")")
                .contains(&codes::EQL_UNKNOWN_FUNCTION.to_string())
        );
        assert!(
            codes_of("process where startswith(process.name, \"a\")").is_empty(),
            "the registry ignores case"
        );
        assert!(
            codes_of("process where add~(1, 2) == 3")
                .contains(&codes::EQL_UNKNOWN_FUNCTION.to_string())
        );
        assert!(codes_of("process where endsWith~(process.name, \".EXE\")").is_empty());
    }

    #[test]
    fn sequence_shape_checks() {
        assert!(
            codes_of("sequence [process where true]").contains(&codes::EQL_PARSE_ERROR.to_string())
        );
        assert!(
            codes_of("sequence [process where true] ![file where true]")
                .contains(&codes::EQL_PARSE_ERROR.to_string())
        );
        assert!(codes_of("sequence [process where true] with runs=2").is_empty());
        assert!(
            codes_of("sequence [process where true] with runs=101 [file where true]")
                .contains(&codes::EQL_PARSE_ERROR.to_string())
        );
        assert!(codes_of("process where true | head 5").is_empty());
        assert!(
            codes_of("process where true | head").contains(&codes::EQL_PARSE_ERROR.to_string())
        );
    }

    #[test]
    fn elasticsearch_builder_and_lexer_rules() {
        assert!(
            codes_of("process where cidrmatch(source.ip, \"10.0.0.0/8\")").is_empty(),
            "names resolve case-insensitively"
        );
        assert!(
            codes_of("process where length(a, b) > 1")
                .contains(&codes::EQL_FUNCTION_ARITY.to_string())
        );
        assert!(
            codes_of("process where between(a, \"x\") == \"\"")
                .contains(&codes::EQL_FUNCTION_ARITY.to_string())
        );
        assert!(
            codes_of("process where file.path == \"C:\\Windows\"")
                .contains(&codes::EQL_PARSE_ERROR.to_string())
        );
        assert!(codes_of("process where file.path == \"C:\\\\Windows\"").is_empty());
        assert!(codes_of("process where file.path == \"\"\"C:\\Windows\"\"\"").is_empty());
        assert!(
            codes_of("process where process.args[0] == \"x\"")
                .contains(&codes::EQL_UNSUPPORTED.to_string())
        );
        assert!(codes_of("PROCESS where true").contains(&codes::EQL_CASE_SENSITIVE.to_string()));
        assert!(
            codes_of("process where x == TRUE").contains(&codes::EQL_CASE_SENSITIVE.to_string())
        );
        assert!(
            codes_of("process where process.name == \"*.exe\"")
                .contains(&codes::EQL_LITERAL_WILDCARD.to_string())
        );
        assert!(
            codes_of("process where process.name in (\"a\", \"*.exe\")")
                .contains(&codes::EQL_LITERAL_WILDCARD.to_string())
        );
        assert!(codes_of("process where process.name : \"*.exe\"").is_empty());
        assert!(codes_of("process where file.path == \"\\\\*\\\\ADMIN$\"").is_empty());
        assert!(
            codes_of("sequence by a [x where true] by b [y where true]")
                .contains(&codes::EQL_PARSE_ERROR.to_string())
        );
        assert!(
            codes_of("sequence [x where true] by a [y where true]")
                .contains(&codes::EQL_PARSE_ERROR.to_string())
        );
        assert!(codes_of("process where like == 1").contains(&codes::EQL_PARSE_ERROR.to_string()));
    }

    #[test]
    fn keywords_are_case_sensitive() {
        assert!(
            codes_of("SEQUENCE [process where true] [file where true]")
                .contains(&codes::EQL_PARSE_ERROR.to_string())
        );
    }

    #[test]
    fn hover_and_signature_help() {
        let src = "process where startsWith~(process.name, \"a\")";
        let h = hover(src, Position::new(0, 16)).expect("hover");
        assert!(h.contains("startsWith") && h.contains("elastic.co"), "{h}");
        let partial = "process where between(file.path, \"a\", ";
        let help = signature_help(partial, partial.len()).expect("signature");
        assert_eq!(help.active_parameter, 2);
        let h = hover(
            "sequence [a where true] [b where true]",
            Position::new(0, 2),
        )
        .expect("keyword");
        assert!(h.contains("sequence"));
    }

    #[test]
    fn completion_contexts() {
        assert!(completions("", 0).iter().any(|i| i.label == "sequence"));
        assert!(
            completions("process where true | ", 21)
                .iter()
                .any(|i| i.label == "head")
        );
        let src = "process where ";
        assert!(
            completions(src, src.len())
                .iter()
                .any(|i| i.label == "stringContains")
        );
    }
}
