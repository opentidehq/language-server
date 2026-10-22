//! `configurations.elastic`: which query language each field holds, and the
//! advisories that compare a query with the block's schedule.
//!
//! [elastic-1.0](https://github.com/opentidehq/specifications/blob/main/specs/platforms/elastic-1.0.md):
//! the language comes from the block, not the platform. `type: esql` is ES|QL,
//! `type: eql` is EQL, `machine_learning` has no query, and the other types
//! take `language` (`kuery` when omitted, or `lucene`). The indicator query
//! `threat.query` takes `threat.language` the same way.

use crate::{InjectedQuery, remap_span};
use opentide_core::{ByteSpan, Diagnostic, LanguageId, codes, span_to_range};

/// Query language of `configurations.elastic.query`, or of `threat.query`
/// when `rule_type` is `threat_match` and `language` is `threat.language`.
pub fn elastic_query_language(
    rule_type: Option<&str>,
    language: Option<&str>,
) -> Option<LanguageId> {
    match rule_type? {
        "esql" => Some(LanguageId::Esql),
        "eql" => Some(LanguageId::Eql),
        "query" | "threshold" | "new_terms" | "threat_match" => match language {
            None | Some("kuery") => Some(LanguageId::Kuery),
            Some("lucene") => Some(LanguageId::Lucene),
            Some(_) => None,
        },
        _ => None,
    }
}

/// One YAML line that holds a mapping key, with its full key path.
struct KeyLine {
    line: usize,
    path: Vec<String>,
    value: String,
}

/// Key paths for every mapping key outside block-scalar bodies. `- key:` list
/// items nest under their parent key with an `[]` segment.
fn key_lines(lines: &[&str]) -> Vec<KeyLine> {
    let mut out = Vec::new();
    let mut stack: Vec<(usize, String)> = Vec::new();
    let mut block_indent: Option<usize> = None;
    for (i, raw) in lines.iter().enumerate() {
        let line = raw.trim_end_matches(['\n', '\r']);
        let trimmed = line.trim_start();
        let indent = line.len() - trimmed.len();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some(b) = block_indent {
            if indent > b {
                continue;
            }
            block_indent = None;
        }
        let (key_indent, content, list_item) = match trimmed.strip_prefix("- ") {
            Some(rest) => (indent + 2, rest.trim_start(), true),
            None => (indent, trimmed, false),
        };
        while stack.last().is_some_and(|(ind, _)| *ind >= key_indent) {
            stack.pop();
        }
        if list_item {
            // The list item itself sits under the nearest parent key.
            while stack.last().is_some_and(|(ind, _)| *ind >= indent) {
                stack.pop();
            }
            stack.push((indent, "[]".into()));
        }
        let Some((key, value)) = split_key(content) else {
            continue;
        };
        let mut path: Vec<String> = stack.iter().map(|(_, k)| k.clone()).collect();
        path.push(key.to_string());
        let value = value.trim().to_string();
        if value.starts_with('|') || value.starts_with('>') {
            block_indent = Some(key_indent);
        }
        out.push(KeyLine {
            line: i,
            path,
            value,
        });
        stack.push((key_indent, key.to_string()));
    }
    out
}

fn split_key(content: &str) -> Option<(&str, &str)> {
    let colon = content.find(':')?;
    let key = content[..colon].trim();
    let rest = &content[colon + 1..];
    if key.is_empty()
        || key.contains(' ')
        || !(rest.is_empty() || rest.starts_with(' ') || rest.starts_with('\t'))
    {
        return None;
    }
    Some((key.trim_matches(['"', '\'']), rest))
}

fn scalar(value: &str) -> Option<String> {
    let v = value.split(" #").next().unwrap_or(value).trim();
    let v = v.trim_matches(['"', '\'']);
    (!v.is_empty()).then(|| v.to_string())
}

fn path_is(path: &[String], expected: &[&str]) -> bool {
    path.len() == expected.len() && path.iter().zip(expected).all(|(a, b)| a == b)
}

/// Injected `query` and `threat.query` of a `configurations.elastic` block.
pub(crate) fn elastic_injections(source: &str) -> Vec<InjectedQuery> {
    let lines: Vec<&str> = source.split_inclusive('\n').collect();
    let keys = key_lines(&lines);
    let value_at = |path: &[&str]| {
        keys.iter()
            .find(|k| path_is(&k.path, path))
            .and_then(|k| scalar(&k.value))
    };
    let rule_type = value_at(&["configurations", "elastic", "type"]);
    let language = value_at(&["configurations", "elastic", "language"]);
    let threat_language = value_at(&["configurations", "elastic", "threat", "language"]);
    let mut line_starts = Vec::with_capacity(lines.len());
    let mut byte = 0usize;
    for l in &lines {
        line_starts.push(byte);
        byte += l.len();
    }
    let mut out = Vec::new();
    for key in &keys {
        let (language, field_path) = if path_is(&key.path, &["configurations", "elastic", "query"])
        {
            (
                elastic_query_language(rule_type.as_deref(), language.as_deref()),
                vec!["configurations", "elastic", "query"],
            )
        } else if path_is(&key.path, &["configurations", "elastic", "threat", "query"])
            && rule_type.as_deref() == Some("threat_match")
        {
            (
                elastic_query_language(Some("threat_match"), threat_language.as_deref()),
                vec!["configurations", "elastic", "threat", "query"],
            )
        } else {
            continue;
        };
        let Some(language) = language else {
            continue;
        };
        let field_path = field_path.into_iter().map(String::from).collect();
        if let Some(inj) = scalar_injection(
            source,
            &lines,
            key.line,
            line_starts[key.line],
            language,
            field_path,
        ) {
            out.push(inj);
        }
    }
    out
}

/// The value of the `key: value` on `lines[i]`: a block scalar (`|`, `>`), or a
/// plain, single-quoted, or double-quoted flow scalar.
fn scalar_injection(
    source: &str,
    lines: &[&str],
    i: usize,
    line_start: usize,
    language: LanguageId,
    field_path: Vec<String>,
) -> Option<InjectedQuery> {
    let line = lines[i];
    let colon = line.find(':')?;
    let after = &line[colon + 1..];
    let value = after.trim();
    if value.starts_with('|') || value.starts_with('>') {
        let indent = line.len() - line.trim_start().len();
        let key_indent = if line.trim_start().starts_with("- ") {
            indent + 2
        } else {
            indent
        };
        return block_injection(lines, i, line_start, key_indent, language, field_path);
    }
    let lead = after.len() - after.trim_start().len();
    let start = line_start + colon + 1 + lead;
    let raw_end = line_start + line.trim_end_matches(['\n', '\r']).len();
    let raw = source.get(start..raw_end)?;
    let (inner, host_map) = match raw.chars().next()? {
        '\'' => unquote(raw, start, '\''),
        '"' => unquote(raw, start, '"'),
        _ => {
            let body = raw.split(" #").next().unwrap_or(raw).trim_end();
            (body.to_string(), (start..start + body.len()).collect())
        }
    };
    if inner.trim().is_empty() {
        return None;
    }
    let host_span = ByteSpan::new(
        host_map.first().copied().unwrap_or(start),
        host_map.last().map(|b| b + 1).unwrap_or(raw_end),
    );
    Some(InjectedQuery {
        language,
        field_path,
        inner,
        host_map,
        host_span,
    })
}

/// Strip YAML quotes. Single quotes escape `'` as `''`; double quotes use `\`.
fn unquote(raw: &str, start: usize, quote: char) -> (String, Vec<usize>) {
    let mut inner = String::new();
    let mut map = Vec::new();
    let mut chars = raw.char_indices().skip(1).peekable();
    while let Some((i, c)) = chars.next() {
        if c == quote {
            if quote == '\'' && chars.peek().map(|(_, n)| *n) == Some('\'') {
                chars.next();
                push_char(&mut inner, &mut map, '\'', start + i);
                continue;
            }
            break;
        }
        if quote == '"' && c == '\\' {
            if let Some((j, e)) = chars.next() {
                let decoded = match e {
                    'n' => '\n',
                    't' => '\t',
                    other => other,
                };
                push_char(&mut inner, &mut map, decoded, start + j);
            }
            continue;
        }
        push_char(&mut inner, &mut map, c, start + i);
    }
    (inner, map)
}

fn push_char(inner: &mut String, map: &mut Vec<usize>, c: char, host: usize) {
    inner.push(c);
    for k in 0..c.len_utf8() {
        map.push(host + k);
    }
}

fn block_injection(
    lines: &[&str],
    i: usize,
    line_start: usize,
    key_indent: usize,
    language: LanguageId,
    field_path: Vec<String>,
) -> Option<InjectedQuery> {
    let mut inner = String::new();
    let mut host_map = Vec::new();
    let mut b = line_start + lines[i].len();
    let mut host_start = b;
    let mut host_end = b;
    let mut content_indent: Option<usize> = None;
    let mut pending_blank = 0usize;
    for l in &lines[i + 1..] {
        let body_line = l.trim_end_matches(['\n', '\r']);
        if body_line.trim().is_empty() {
            if content_indent.is_some() {
                pending_blank += 1;
            }
            b += l.len();
            continue;
        }
        let ind = body_line.len() - body_line.trim_start().len();
        if ind <= key_indent {
            break;
        }
        let strip = *content_indent.get_or_insert(ind);
        if inner.is_empty() {
            host_start = b;
        }
        if !inner.is_empty() {
            for _ in 0..=pending_blank {
                inner.push('\n');
                host_map.push(host_end.saturating_sub(1).max(host_start));
            }
        }
        pending_blank = 0;
        let cut = strip.min(ind);
        let body = &body_line[cut..];
        for k in 0..body.len() {
            host_map.push(b + cut + k);
        }
        inner.push_str(body);
        host_end = b + body_line.len() + 1;
        b += l.len();
    }
    if inner.is_empty() {
        return None;
    }
    Some(InjectedQuery {
        language,
        field_path,
        inner,
        host_map,
        host_span: ByteSpan::new(host_start, host_end.min(b)),
    })
}

/// A duration in the [elastic-1.0] Durations grammar, in milliseconds:
/// shorthand `[n d][n h][n m][n s]` (lower case, in that order) or ISO 8601
/// `P[nD][T[nH][nM][nS]]`. Zero is returned as `Some(0)`; the caller decides.
pub fn duration_millis(text: &str) -> Option<u64> {
    let text = text.trim();
    if let Some(rest) = text.strip_prefix('P') {
        let (days, time) = match rest.split_once('T') {
            Some((d, t)) => {
                if t.is_empty() {
                    return None;
                }
                (d, Some(t))
            }
            None => (rest, None),
        };
        let mut total = parts(days, &[('D', 86_400_000)])?;
        if let Some(t) = time {
            total += parts(t, &[('H', 3_600_000), ('M', 60_000), ('S', 1_000)])?;
        }
        return (!rest.is_empty()).then_some(total);
    }
    if text.is_empty() {
        return None;
    }
    parts(
        text,
        &[
            ('d', 86_400_000),
            ('h', 3_600_000),
            ('m', 60_000),
            ('s', 1_000),
        ],
    )
}

/// `1h10m`-style parts in the given unit order, each unit at most once.
fn parts(text: &str, units: &[(char, u64)]) -> Option<u64> {
    let mut total = 0u64;
    let mut next_unit = 0usize;
    let mut digits = String::new();
    for c in text.chars() {
        if c.is_ascii_digit() {
            digits.push(c);
            continue;
        }
        let pos = units[next_unit..].iter().position(|(u, _)| *u == c)? + next_unit;
        if digits.is_empty() {
            return None;
        }
        total = total.checked_add(digits.parse::<u64>().ok()?.checked_mul(units[pos].1)?)?;
        digits.clear();
        next_unit = pos + 1;
    }
    digits.is_empty().then_some(total)
}

/// `eql_maxspan_window`: an EQL `sequence ... with maxspan=` longer than the
/// rule's window (interval + lookback) cannot match; longer than `lookback`
/// alone, a sequence that straddles two runs is missed ([elastic-1.0]
/// Advisories). Defaults are `interval: 5m`, `lookback: 1m`.
pub(crate) fn maxspan_advisories(
    source: &str,
    configurations: Option<&serde_yaml::Value>,
    injection: &InjectedQuery,
) -> Vec<Diagnostic> {
    let scheduling = configurations
        .and_then(|c| c.get("elastic"))
        .and_then(|e| e.get("scheduling"));
    let read = |key: &str, default: &str| {
        scheduling
            .and_then(|s| s.get(key))
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .unwrap_or_else(|| default.to_string())
    };
    let interval_text = read("interval", "5m");
    let lookback_text = read("lookback", "1m");
    let (Some(interval), Some(lookback)) = (
        duration_millis(&interval_text),
        duration_millis(&lookback_text),
    ) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (span, maxspan) in opentide_eql::sequence_maxspans(&injection.inner) {
        let message = if maxspan > interval + lookback {
            format!(
                "EQL maxspan exceeds the rule window, interval + lookback ({interval_text} + {lookback_text}); the sequence cannot fit one run"
            )
        } else if maxspan > lookback {
            format!(
                "EQL maxspan exceeds scheduling.lookback ({lookback_text}); a sequence that straddles two runs is missed"
            )
        } else {
            continue;
        };
        let host = remap_span(injection, span);
        out.push(
            Diagnostic::warning(
                codes::EQL_MAXSPAN_WINDOW,
                message,
                span_to_range(source, host),
            )
            .with_field_path(injection.field_path.clone()),
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn language_follows_type_and_language() {
        assert_eq!(
            elastic_query_language(Some("esql"), None),
            Some(LanguageId::Esql)
        );
        assert_eq!(
            elastic_query_language(Some("eql"), None),
            Some(LanguageId::Eql)
        );
        assert_eq!(
            elastic_query_language(Some("query"), None),
            Some(LanguageId::Kuery)
        );
        assert_eq!(
            elastic_query_language(Some("new_terms"), Some("lucene")),
            Some(LanguageId::Lucene)
        );
        assert_eq!(elastic_query_language(Some("machine_learning"), None), None);
        assert_eq!(elastic_query_language(None, None), None);
    }

    #[test]
    fn durations_follow_the_spec() {
        assert_eq!(duration_millis("5m"), Some(300_000));
        assert_eq!(duration_millis("1h10m"), Some(4_200_000));
        assert_eq!(duration_millis("PT1H"), Some(3_600_000));
        assert_eq!(duration_millis("P1DT2H"), Some(93_600_000));
        assert_eq!(duration_millis("0m"), Some(0));
        assert_eq!(duration_millis("10m1h"), None, "units in d, h, m, s order");
        assert_eq!(duration_millis("1w"), None);
        assert_eq!(duration_millis("PT"), None);
        assert_eq!(duration_millis("1.5h"), None);
    }

    #[test]
    fn query_language_comes_from_siblings_in_any_order() {
        let src = "configurations:\n  elastic:\n    query: |\n      FROM logs-* METADATA _id\n      | LIMIT 1\n    type: esql\n";
        let inj = elastic_injections(src);
        assert_eq!(inj.len(), 1);
        assert_eq!(inj[0].language, LanguageId::Esql);
        assert_eq!(inj[0].inner, "FROM logs-* METADATA _id\n| LIMIT 1");
    }

    #[test]
    fn single_quoted_kuery_is_unquoted() {
        let src = "configurations:\n  elastic:\n    type: query\n    query: 'event.category : \"process\" and x:''y'''\n";
        let inj = elastic_injections(src);
        assert_eq!(inj.len(), 1);
        assert_eq!(inj[0].language, LanguageId::Kuery);
        assert_eq!(inj[0].inner, "event.category : \"process\" and x:'y'");
        let at = inj[0].host_map[0];
        assert_eq!(&src[at..at + 5], "event");
    }

    #[test]
    fn threat_query_takes_threat_language_and_osquery_is_skipped() {
        let src = "\
configurations:
  elastic:
    type: threat_match
    language: lucene
    query: 'event.category:file'
    threat:
      index: [logs-ti_*]
      language: kuery
      query: '@timestamp >= \"now-30d/d\"'
    actions:
      respond:
        - osquery:
            query: SELECT * FROM processes
";
        let inj = elastic_injections(src);
        let langs: Vec<_> = inj
            .iter()
            .map(|i| (i.field_path.join("."), i.language))
            .collect();
        assert_eq!(
            langs,
            vec![
                ("configurations.elastic.query".into(), LanguageId::Lucene),
                (
                    "configurations.elastic.threat.query".into(),
                    LanguageId::Kuery
                ),
            ]
        );
    }

    #[test]
    fn no_type_means_no_injection() {
        let src = "configurations:\n  elastic:\n    query: x\n";
        assert!(elastic_injections(src).is_empty());
    }
}
