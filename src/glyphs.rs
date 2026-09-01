//! Mesure de la largeur réelle des glyphes de l'interface.
//!
//! kdt calcule ses largeurs de colonnes et ses remplissages avec `unicode-width`, comme ratatui.
//! Si le terminal, lui, facture un nombre de cellules différent pour un glyphe (glyphe couleur pris
//! dans une police emoji, largeur ambiguë traitée comme large…), tout ce qui suit sur la ligne se
//! décale et la bordure droite des panneaux part en escalier.
//!
//! Plutôt que de supposer, on demande au terminal : on écrit le glyphe en début de ligne, puis on
//! lui demande où se trouve le curseur (CPR, `ESC[6n`). L'écart entre la mesure et `unicode-width`
//! est exactement la correction à appliquer aux calculs de largeur.

use std::io::Write;

use crossterm::{cursor, terminal, ExecutableCommand};
use unicode_width::UnicodeWidthChar;

/// Les glyphes non-ASCII employés par l'interface.
pub const UI_GLYPHS: &str = "²·»×–—•…←↑→↓↡↻⇅≥⊞⊟⊡─│└═█▏░■▲▸►▼▾◂○●◐◑◒◓◔✓✗";

/// Ce que le terminal facture pour un glyphe, face à ce que kdt suppose.
#[derive(Debug, Clone, Copy)]
pub struct Measure {
    pub ch: char,
    /// Cellules réellement consommées, mesurées par CPR.
    pub measured: u16,
    /// Cellules supposées par `unicode-width` (donc par ratatui et par kdt).
    pub assumed: u16,
}

impl Measure {
    pub fn agrees(&self) -> bool {
        self.measured == self.assumed
    }
}

/// Mesure chaque glyphe en le faisant écrire par le terminal puis en relisant la position du
/// curseur. Nécessite un vrai terminal ; la ligne de test est effacée derrière soi.
pub fn measure(glyphs: &str) -> std::io::Result<Vec<Measure>> {
    let mut out = std::io::stdout();
    terminal::enable_raw_mode()?;
    let result = (|| -> std::io::Result<Vec<Measure>> {
        let mut measures = Vec::new();
        for ch in glyphs.chars() {
            write!(out, "\r{ch}")?;
            out.flush()?;
            // Le curseur part de la colonne 0 : sa nouvelle colonne est la largeur consommée.
            let measured = cursor::position()?.0;
            write!(out, "\r")?;
            out.execute(terminal::Clear(terminal::ClearType::CurrentLine))?;
            measures.push(Measure {
                ch,
                measured,
                assumed: ch.width().unwrap_or(0) as u16,
            });
        }
        Ok(measures)
    })();
    terminal::disable_raw_mode()?;
    result
}

/// Readable report: `kdt --probe-glyphs`, to be run in the terminal one wants to characterise.
pub fn print_report() -> std::io::Result<()> {
    let st = crate::lang::active();
    let measures = measure(UI_GLYPHS)?;
    println!("{}\n", st.glyph_report_title);
    // The header and the "off" flag are padded to the same width in both languages: this report is
    // a hand-aligned ASCII table, and a shorter word would shear the columns.
    println!("{}", st.glyph_header);
    for m in &measures {
        let flag = if m.agrees() { "" } else { st.glyph_off_flag };
        println!(
            "    {}     U+{:04X}     {}         {}{}",
            m.ch, m.ch as u32, m.measured, m.assumed, flag
        );
    }
    let off: Vec<&Measure> = measures.iter().filter(|m| !m.agrees()).collect();
    println!();
    if off.is_empty() {
        println!("{}", st.glyph_all_agree);
    } else {
        let list = off
            .iter()
            .map(|m| {
                crate::lang::fill(
                    st.glyph_off_detail,
                    &[
                        ("ch", &m.ch.to_string()),
                        ("measured", &m.measured.to_string()),
                        ("assumed", &m.assumed.to_string()),
                    ],
                )
            })
            .collect::<Vec<_>>()
            .join(", ");
        println!(
            "{}",
            crate::lang::fill(
                &st.plural(off.len(), st.glyph_off_one, st.glyph_off_many),
                &[("list", &list)],
            )
        );
    }
    Ok(())
}
