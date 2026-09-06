//! La langue d'une requête.
//!
//! Dans le TUI, la langue est un réglage du processus : `lang::set_active` la pose et les tâches de
//! fond la relisent. Un serveur n'a pas ce luxe — il répond à plusieurs personnes à la fois, dont
//! rien ne dit qu'elles lisent la même — donc la langue voyage dans la requête, et la table de
//! chaînes est passée à `kdt` au lieu d'être lue dans un global.
//!
//! Ce qui n'est pas demandé reste en français : c'est la langue par défaut de kdt.

use kdt::ai::AiLanguage;
use kdt::lang::Strings;

/// La table de chaînes de kdt pour cette langue. Tout ce qui n'est pas `en` est du français.
pub fn lang_of(lang: &str) -> &'static Strings {
    kdt::lang::t(if lang.eq_ignore_ascii_case("en") {
        AiLanguage::En
    } else {
        AiLanguage::Fr
    })
}
