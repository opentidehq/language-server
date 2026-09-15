//! Tree-sitter language bindings. Parser C is vendored; do not hand-edit `parser.c`.

use opentide_core::LanguageId;
use tree_sitter::{Language, Parser, Tree};

unsafe extern "C" {
    fn tree_sitter_opentide_kql() -> *const ();
    fn tree_sitter_opentide_spl() -> *const ();
}

fn from_raw(ptr: *const ()) -> Language {
    // tree-sitter 0.25: Language::new(LanguageFn)
    unsafe { Language::from_raw(ptr as usize as *const tree_sitter::ffi::TSLanguage) }
}

pub fn language(id: LanguageId) -> Option<Language> {
    match id {
        LanguageId::Kql => Some(kql_language()),
        LanguageId::Spl => Some(spl_language()),
        LanguageId::TideYaml => None,
    }
}

pub fn kql_language() -> Language {
    unsafe { from_raw(tree_sitter_opentide_kql()) }
}

pub fn spl_language() -> Language {
    unsafe { from_raw(tree_sitter_opentide_spl()) }
}

pub fn parse(id: LanguageId, source: &str) -> Option<Tree> {
    let language = language(id)?;
    let mut parser = Parser::new();
    parser.set_language(&language).ok()?;
    parser.parse(source, None)
}

pub fn has_error(tree: &Tree) -> bool {
    tree.root_node().has_error()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_kql_pipeline() {
        let tree = parse(
            LanguageId::Kql,
            "SecurityEvent | where EventID == 4688 | take 1",
        )
        .expect("parse");
        assert!(!has_error(&tree), "{}", tree.root_node().to_sexp());
    }

    #[test]
    fn parses_kql_let() {
        let tree = parse(LanguageId::Kql, "let x = 1; DeviceProcessEvents | take 1").unwrap();
        assert!(!has_error(&tree));
        let sexp = tree.root_node().to_sexp();
        assert!(sexp.contains("let_statement"));
    }

    #[test]
    fn parses_kql_control_command() {
        let tree = parse(LanguageId::Kql, ".show tables").unwrap();
        assert!(tree.root_node().to_sexp().contains("control_command"));
    }

    #[test]
    fn parses_spl_bare_search() {
        let tree = parse(LanguageId::Spl, "index=main | head 1").unwrap();
        assert!(!has_error(&tree), "{}", tree.root_node().to_sexp());
        assert!(tree.root_node().to_sexp().contains("bare_search"));
    }

    #[test]
    fn parses_spl_unknown_command() {
        let tree = parse(LanguageId::Spl, "index=main | bogus foo=bar | head 1").unwrap();
        assert!(!has_error(&tree), "{}", tree.root_node().to_sexp());
        assert!(tree.root_node().to_sexp().contains("unknown_command"));
    }

    #[test]
    fn parses_spl_stats() {
        let tree = parse(LanguageId::Spl, "search index=main | stats count by host").unwrap();
        assert!(!has_error(&tree), "{}", tree.root_node().to_sexp());
    }
}
