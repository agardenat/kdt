//! Clipboard copy via the OSC 52 terminal escape sequence, which works over SSH and
//! through multiplexers when the terminal emulator supports it (no system clipboard daemon).

use std::io::{self, Write};

use base64::{engine::general_purpose::STANDARD, Engine};

// Emit `ESC ] 52 ; c ; <base64> ESC \` so the terminal stores `text` in its clipboard.
pub fn copy_to_clipboard(text: &str) -> Result<(), String> {
    let encoded = STANDARD.encode(text.as_bytes());
    let mut payload = Vec::with_capacity(encoded.len() + 16);
    payload.extend_from_slice(b"\x1b]52;c;");
    payload.extend_from_slice(encoded.as_bytes());
    payload.extend_from_slice(b"\x1b\\");
    let mut out = io::stdout().lock();
    out.write_all(&payload).map_err(|e| format!("stdout: {}", e))?;
    out.flush().map_err(|e| format!("flush: {}", e))?;
    Ok(())
}
