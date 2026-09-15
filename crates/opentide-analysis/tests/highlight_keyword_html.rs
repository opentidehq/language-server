//! Regression: keyword tokens must exist and survive HTML rendering as class=keyword.
use opentide_analysis::highlight;
use opentide_core::LanguageId;
use opentide_highlight::HighlightToken;

fn to_html(source: &str, tokens: &[HighlightToken]) -> String {
    let mut html = String::new();
    let mut last = 0usize;
    let mut ordered = tokens.to_vec();
    ordered.sort_by_key(|t| t.span.start);
    for t in &ordered {
        if t.span.start < last {
            continue;
        }
        html.push_str(&source[last..t.span.start]);
        html.push_str(&format!("<span class=\"{}\">", t.capture.replace('.', "-")));
        html.push_str(&source[t.span.start..t.span.end]);
        html.push_str("</span>");
        last = t.span.end;
    }
    html.push_str(&source[last..]);
    html
}

#[test]
fn kql_keyword_tokens_and_html_spans() {
    let src = "SecurityEvent | where EventID == 1 | take 1";
    let r = highlight(LanguageId::Kql, src);
    assert!(
        r.tokens
            .iter()
            .any(|t| t.capture == "keyword" && &src[t.span.start..t.span.end] == "where"),
        "{:?}",
        r.tokens
    );
    assert!(
        r.tokens
            .iter()
            .any(|t| t.capture == "keyword" && &src[t.span.start..t.span.end] == "take"),
        "{:?}",
        r.tokens
    );
    let html = to_html(src, &r.tokens);
    assert!(
        html.contains("<span class=\"keyword\">where</span>"),
        "{html}"
    );
    assert!(
        html.contains("<span class=\"keyword\">take</span>"),
        "{html}"
    );
}

#[test]
fn spl_keyword_tokens_and_html_spans() {
    let src = "index=main | stats count by host | head 1";
    let r = highlight(LanguageId::Spl, src);
    assert!(
        r.tokens
            .iter()
            .any(|t| t.capture == "keyword" && &src[t.span.start..t.span.end] == "stats"),
        "{:?}",
        r.tokens
    );
    assert!(
        r.tokens
            .iter()
            .any(|t| t.capture == "keyword" && &src[t.span.start..t.span.end] == "head"),
        "{:?}",
        r.tokens
    );
    let html = to_html(src, &r.tokens);
    assert!(
        html.contains("<span class=\"keyword\">stats</span>"),
        "{html}"
    );
    assert!(
        html.contains("<span class=\"keyword\">head</span>"),
        "{html}"
    );
}
