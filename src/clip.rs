use std::io::{self, Write};

use base64::{engine::general_purpose::STANDARD, Engine};

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
