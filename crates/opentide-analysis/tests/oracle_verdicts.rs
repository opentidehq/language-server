//! Engine verdicts for the Elastic CI oracles (`scripts/ci-oracle-elastic.sh`).
//!
//! Opt-in: with `OPENTIDE_VERDICTS_IN` set to a directory written by
//! `scripts/oracles/elastic/collect.py`, writes `<lang>.tsv` files to
//! `OPENTIDE_VERDICTS_OUT`, one line per query: `file`, `OK` or `ERR`, and the
//! codes of the Error diagnostics.

use opentide_core::{LanguageId, Severity};
use std::fs;
use std::path::PathBuf;

#[test]
fn engine_verdicts_for_the_oracles() {
    let (Some(input), Some(output)) = (
        std::env::var_os("OPENTIDE_VERDICTS_IN"),
        std::env::var_os("OPENTIDE_VERDICTS_OUT"),
    ) else {
        eprintln!("OPENTIDE_VERDICTS_IN / OPENTIDE_VERDICTS_OUT not set; skipping");
        return;
    };
    let (input, output) = (PathBuf::from(input), PathBuf::from(output));
    fs::create_dir_all(&output).unwrap();
    for (id, language) in [
        ("esql", LanguageId::Esql),
        ("eql", LanguageId::Eql),
        ("kuery", LanguageId::Kuery),
        ("lucene", LanguageId::Lucene),
    ] {
        let Ok(entries) = fs::read_dir(input.join(id)) else {
            continue;
        };
        let mut names: Vec<String> = entries
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        let mut lines = String::new();
        for name in names {
            let text = fs::read_to_string(input.join(id).join(&name)).unwrap();
            let diagnostics = match language {
                LanguageId::Esql => opentide_esql::analyze(&text).diagnostics,
                LanguageId::Eql => opentide_eql::analyze(&text).diagnostics,
                LanguageId::Kuery => opentide_kuery::analyze(&text).diagnostics,
                _ => opentide_lucene::analyze(&text).diagnostics,
            };
            let mut errors: Vec<String> = diagnostics
                .into_iter()
                .filter(|d| d.severity == Severity::Error)
                .map(|d| d.code)
                .collect();
            errors.dedup();
            let verdict = if errors.is_empty() { "OK" } else { "ERR" };
            lines.push_str(&format!("{name}\t{verdict}\t{}\n", errors.join(",")));
        }
        fs::write(output.join(format!("{id}.tsv")), lines).unwrap();
    }
}
