use opentide_analysis::highlight;
use opentide_core::LanguageId;
use opentide_highlight::tokens_to_html;

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
    let html = tokens_to_html(src, &r.tokens);
    assert!(
        html.contains("<span class=\"keyword\">where</span>"),
        "{html}"
    );
    assert!(
        html.contains("<span class=\"keyword\">take</span>"),
        "{html}"
    );
    assert!(html.contains("#c586c0"), "{html}");
    assert!(html.contains("#ff79c6"), "{html}");
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
    let html = tokens_to_html(src, &r.tokens);
    assert!(
        html.contains("<span class=\"keyword\">stats</span>"),
        "{html}"
    );
    assert!(
        html.contains("<span class=\"keyword\">head</span>"),
        "{html}"
    );
}
