//! Startup screen: held on the terminal while kdt checks it can actually reach the cluster.
//!
//! Building the kube client touches no network — it only reads the kubeconfig. So an unreachable
//! API server used to open a perfectly normal, perfectly empty UI: no events, no cluster banner,
//! no error, nothing moving. This screen takes those first seconds, asks the API server for its
//! version, and says plainly what it found. It is also the only place where the user learns *which*
//! server kdt is talking to, which is what makes a wrong context obvious.

use std::time::{Duration, Instant};

use anyhow::Result;
use crossterm::event::{Event, EventStream, KeyCode, KeyEventKind, KeyModifiers};
use futures::StreamExt;
use kube::Client;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};
use ratatui::DefaultTerminal;

use crate::jump::{JumpConfig, JumpEvent};
use crate::lang;

// Long enough for a VPN handshake or a cold API server, short enough that a black hole is called
// out while the user is still watching. A refused connection answers well before this.
const PROBE_TIMEOUT: Duration = Duration::from_secs(15);
// The same four frames the AI panel spins, at the same 100ms: one idiom for "kdt is waiting".
const SPINNER: [char; 4] = ['◐', '◓', '◑', '◒'];

/// What the user decided (or what the probe decided for them).
pub enum Outcome {
    /// Carry on into the UI — either the cluster answered, or the user chose to go in anyway.
    Ready,
    /// Give up before the UI ever opens.
    Aborted,
}

enum Probe {
    Running(Instant),
    Failed(String),
}

/// Identity of the cluster being contacted, as shown on the screen.
pub struct Target<'a> {
    pub context: &'a str,
    pub cluster: &'a str,
    pub namespace: &'a str,
    pub server: &'a str,
    /// The context kdt is already on, when this screen checks a `:ctx` switch rather than a start:
    /// `q` then means staying there, not leaving kdt.
    pub stay: Option<&'a str>,
}

// A reachability check, not a capability check: `/version` needs no RBAC, so a failure here is a
// network/TLS/auth problem and never "this token cannot list events".
async fn probe(client: Client) -> Result<(), String> {
    match tokio::time::timeout(PROBE_TIMEOUT, client.apiserver_version()).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(e)) => Err(error_chain(&e)),
        Err(_) => Err(lang::fill(
            lang::active().splash_timeout,
            &[("n", &PROBE_TIMEOUT.as_secs().to_string())],
        )),
    }
}

// The whole point of this screen is naming the failure, and `kube::Error`'s own Display does not:
// a refused connection prints "ServiceError: client error (Connect)" and keeps "Connection refused"
// in its source chain. Walk the chain, skipping links that only repeat what is already there.
fn error_chain(e: &dyn std::error::Error) -> String {
    let mut out = e.to_string();
    let mut src = e.source();
    while let Some(s) = src {
        let text = s.to_string();
        if !out.contains(&text) {
            out.push_str(": ");
            out.push_str(&text);
        }
        src = s.source();
    }
    out
}

pub async fn run(terminal: &mut DefaultTerminal, client: Client, target: Target<'_>) -> Result<Outcome> {
    let mut events = EventStream::new();
    let mut ticker = tokio::time::interval(Duration::from_millis(100));
    let mut state = Probe::Running(Instant::now());
    let mut task = tokio::spawn(probe(client.clone()));

    loop {
        terminal.draw(|f| draw(f, &state, &target))?;

        tokio::select! {
            // Only polled while a probe is in flight: an aborted/finished JoinHandle polled again
            // panics, and once we hold the error there is nothing left to await.
            res = &mut task, if matches!(state, Probe::Running(_)) => {
                match res {
                    Ok(Ok(())) => return Ok(Outcome::Ready),
                    Ok(Err(e)) => state = Probe::Failed(e),
                    Err(e) => state = Probe::Failed(e.to_string()),
                }
            }
            _ = ticker.tick() => {}
            Some(Ok(ev)) = events.next() => {
                let Event::Key(k) = ev else { continue };
                if k.kind != KeyEventKind::Press { continue }
                match (k.code, k.modifiers) {
                    (KeyCode::Char('c'), KeyModifiers::CONTROL) => return Ok(Outcome::Aborted),
                    (KeyCode::Char('q'), _) | (KeyCode::Esc, _) => return Ok(Outcome::Aborted),
                    // Both only make sense once the attempt has come back: while it is running,
                    // Enter would skip a probe that is about to answer on its own.
                    (KeyCode::Enter, _) if matches!(state, Probe::Failed(_)) => {
                        return Ok(Outcome::Ready)
                    }
                    (KeyCode::Char('r'), _) if matches!(state, Probe::Failed(_)) => {
                        task = tokio::spawn(probe(client.clone()));
                        state = Probe::Running(Instant::now());
                    }
                    _ => {}
                }
            }
        }
    }
}

fn draw(f: &mut ratatui::Frame, state: &Probe, target: &Target<'_>) {
    let st = lang::active();
    let area = f.area();

    // Width first, so the prose below can be wrapped by hand to the exact inner width: ratatui's
    // own wrapping restarts continuation rows at column 0, which would throw the two-space indent
    // away and glue a wrapped error against the border.
    let width = 76.min(area.width.saturating_sub(4)).max(24);
    let text_width = width.saturating_sub(4) as usize;

    let (headline, color) = match state {
        Probe::Running(since) => {
            let spinner = SPINNER[(since.elapsed().as_millis() / 100) as usize % SPINNER.len()];
            (
                format!("{}  {}  {}s", spinner, st.splash_connecting, since.elapsed().as_secs()),
                Color::Yellow,
            )
        }
        Probe::Failed(_) => (format!("✗  {}", st.splash_unreachable), Color::Red),
    };

    // Field labels stay in English on both sides: they name kubeconfig entries, and a user reading
    // `cluster`/`context`/`server` here is reading the same words their kubeconfig uses.
    let mut lines = vec![
        Line::from(""),
        Line::from(vec![
            Span::raw("  "),
            Span::styled(headline, Style::default().fg(color).add_modifier(Modifier::BOLD)),
        ]),
        Line::from(""),
        field("cluster", target.cluster),
        field("context", target.context),
        field("namespace", target.namespace),
        field("server", target.server),
    ];

    if let Probe::Failed(err) = state {
        lines.push(Line::from(""));
        for l in wrap(err, text_width) {
            lines.push(Line::from(vec![
                Span::raw("  "),
                Span::styled(l, Style::default().fg(Color::Red)),
            ]));
        }
        lines.push(Line::from(""));
        for l in wrap(st.splash_hint, text_width) {
            lines.push(Line::from(vec![
                Span::raw("  "),
                Span::styled(l, Style::default().fg(Color::DarkGray)),
            ]));
        }
    }

    let leave = match target.stay {
        Some(ctx) => lang::fill(st.splash_stay, &[("ctx", ctx)]),
        None => match state {
            Probe::Running(_) => st.splash_abort.to_string(),
            Probe::Failed(_) => st.k_quit.to_string(),
        },
    };
    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::raw("  "),
        Span::styled(
            match state {
                Probe::Running(_) => format!("q  {}", leave),
                Probe::Failed(_) => format!(
                    "r  {}    Enter  {}    q  {}",
                    st.splash_retry, st.splash_continue, leave
                ),
            },
            Style::default().fg(Color::DarkGray),
        ),
    ]));

    // Sized from the content, so the failed screen grows to hold the error instead of clipping it.
    // One spare row absorbs a field value (a long server URL) that ratatui still has to wrap.
    let height = (lines.len() as u16 + 3).min(area.height);
    let popup = centered(width, height, area);

    f.render_widget(Clear, popup);
    let title = format!(" kdt v{} ", env!("CARGO_PKG_VERSION"));
    let p = Paragraph::new(lines)
        // `trim: false` keeps the two-space indent of every line: with `trim: true` a wrapped error
        // would come back flush against the border.
        .wrap(Wrap { trim: false })
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(title)
                .border_style(Style::default().fg(match state {
                    Probe::Running(_) => Color::Cyan,
                    Probe::Failed(_) => Color::Red,
                })),
        );
    f.render_widget(p, popup);
}

enum Opening {
    Running(Instant),
    Failed(String),
}

struct Question {
    prompt: String,
    hidden: bool,
    input: String,
    reply: tokio::sync::oneshot::Sender<Option<String>>,
}

/// The window that opens a jump host before the cluster is probed: the hop being reached, and the
/// questions of the hops (account, password) asked in place. What the sessions print stays behind
/// it — a bastion's banners are not the user's business unless a hop fails, and then the error
/// carries the end of it.
pub async fn jump(terminal: &mut DefaultTerminal, cfg: &JumpConfig, context: &str, stay: Option<&str>) -> Result<Outcome> {
    let mut events = EventStream::new();
    let mut ticker = tokio::time::interval(Duration::from_millis(100));
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    // Polled in place rather than spawned: dropping it on `Esc` is what closes the sessions.
    let mut task = Box::pin(crate::jump::prepare(cfg, tx.clone()));
    let mut state = Opening::Running(Instant::now());
    let mut hop: Option<(usize, usize, String)> = None;
    let mut question: Option<Question> = None;

    loop {
        terminal.draw(|f| draw_jump(f, cfg, context, stay, &state, hop.as_ref(), question.as_ref()))?;

        tokio::select! {
            res = &mut task, if matches!(state, Opening::Running(_)) => match res {
                Ok(()) => return Ok(Outcome::Ready),
                Err(e) => {
                    let err = format!("{e:#}");
                    tracing::warn!(jump = %cfg.name, error = %err, "jump not opened");
                    state = Opening::Failed(err);
                    question = None;
                }
            },
            Some(ev) = rx.recv() => match ev {
                JumpEvent::Hop { n, total, what } => hop = Some((n, total, what)),
                JumpEvent::Ask { prompt, hidden, reply } => {
                    question = Some(Question { prompt, hidden, input: String::new(), reply });
                }
            },
            _ = ticker.tick() => {}
            Some(Ok(ev)) = events.next() => {
                let Event::Key(k) = ev else { continue };
                if k.kind != KeyEventKind::Press { continue }
                if k.code == KeyCode::Esc || (k.code == KeyCode::Char('c') && k.modifiers.contains(KeyModifiers::CONTROL)) {
                    return Ok(Outcome::Aborted);
                }
                // While a question is up, every printable key belongs to the answer, `q` included.
                if question.is_some() {
                    match k.code {
                        KeyCode::Enter => {
                            if let Some(q) = question.take() {
                                let _ = q.reply.send(Some(q.input));
                            }
                        }
                        KeyCode::Backspace => {
                            if let Some(q) = question.as_mut() {
                                q.input.pop();
                            }
                        }
                        KeyCode::Char(c) => {
                            if let Some(q) = question.as_mut() {
                                q.input.push(c);
                            }
                        }
                        _ => {}
                    }
                    continue;
                }
                match k.code {
                    KeyCode::Char('q') => return Ok(Outcome::Aborted),
                    KeyCode::Char('r') if matches!(state, Opening::Failed(_)) => {
                        task = Box::pin(crate::jump::prepare(cfg, tx.clone()));
                        state = Opening::Running(Instant::now());
                        hop = None;
                    }
                    _ => {}
                }
            }
        }
    }
}

fn draw_jump(
    f: &mut ratatui::Frame,
    cfg: &JumpConfig,
    context: &str,
    stay: Option<&str>,
    state: &Opening,
    hop: Option<&(usize, usize, String)>,
    question: Option<&Question>,
) {
    let st = lang::active();
    let area = f.area();
    let width = 76.min(area.width.saturating_sub(4)).max(24);
    let text_width = width.saturating_sub(4) as usize;
    let indented = |text: &str, style: Style| -> Vec<Line<'static>> {
        wrap(text, text_width)
            .into_iter()
            .map(|l| Line::from(vec![Span::raw("  "), Span::styled(l, style)]))
            .collect()
    };

    let title = lang::fill(st.jump_opening_title, &[("name", &cfg.name)]);
    let (headline, color) = match state {
        // Nothing is being waited for while the question is up: no spinner, no clock.
        Opening::Running(_) if question.is_some() => (format!("▸  {}", title), Color::Yellow),
        Opening::Running(since) => {
            let spinner = SPINNER[(since.elapsed().as_millis() / 100) as usize % SPINNER.len()];
            (format!("{}  {}  {}s", spinner, title, since.elapsed().as_secs()), Color::Yellow)
        }
        Opening::Failed(_) => (format!("✗  {}", title), Color::Red),
    };
    let mut lines = vec![
        Line::from(""),
        Line::from(vec![
            Span::raw("  "),
            Span::styled(headline, Style::default().fg(color).add_modifier(Modifier::BOLD)),
        ]),
        Line::from(""),
        field("context", context),
    ];
    if let Some((n, total, what)) = hop {
        let label = lang::fill(st.jump_hop, &[("n", &n.to_string()), ("total", &total.to_string())]);
        lines.push(field("jump", &label));
        lines.extend(indented(what, Style::default().fg(Color::DarkGray)));
    }

    if let Some(q) = question {
        lines.push(Line::from(""));
        lines.extend(indented(&q.prompt, Style::default().fg(Color::White).add_modifier(Modifier::BOLD)));
        let shown = if q.hidden { "•".repeat(q.input.chars().count()) } else { q.input.clone() };
        lines.push(Line::from(vec![
            Span::raw("  "),
            Span::styled("▸ ", Style::default().fg(Color::Cyan)),
            Span::styled(shown, Style::default().fg(Color::White)),
            Span::styled("▏", Style::default().fg(Color::Cyan)),
        ]));
    }
    if let Opening::Failed(err) = state {
        lines.push(Line::from(""));
        lines.extend(indented(err, Style::default().fg(Color::Red)));
    }

    let leave = match stay {
        Some(ctx) => lang::fill(st.splash_stay, &[("ctx", ctx)]),
        None => match state {
            Opening::Running(_) => st.splash_abort.to_string(),
            Opening::Failed(_) => st.k_quit.to_string(),
        },
    };
    let keys = match (state, question) {
        (Opening::Running(_), Some(_)) => format!("Enter  {}    Esc  {}", st.jump_validate, leave),
        (Opening::Running(_), None) => format!("Esc  {}", leave),
        (Opening::Failed(_), _) => format!("r  {}    q  {}", st.splash_retry, leave),
    };
    lines.push(Line::from(""));
    lines.push(Line::from(vec![Span::raw("  "), Span::styled(keys, Style::default().fg(Color::DarkGray))]));

    let height = (lines.len() as u16 + 3).min(area.height);
    let popup = centered(width, height, area);
    f.render_widget(Clear, popup);
    let p = Paragraph::new(lines).wrap(Wrap { trim: false }).block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!(" kdt v{} ", env!("CARGO_PKG_VERSION")))
            .border_style(Style::default().fg(match state {
                Opening::Running(_) => Color::Cyan,
                Opening::Failed(_) => Color::Red,
            })),
    );
    f.render_widget(p, popup);
}

fn field(label: &str, value: &str) -> Line<'static> {
    Line::from(vec![
        Span::raw("  "),
        Span::styled(format!("{:<11}", label), Style::default().fg(Color::DarkGray)),
        Span::styled(value.to_string(), Style::default().fg(Color::White)),
    ])
}

// Word wrap, breaking inside a word only when the word alone cannot fit — an error chain is one
// long sentence, and a URL in the middle of it must not push the box open.
fn wrap(text: &str, width: usize) -> Vec<String> {
    if width == 0 { return vec![text.to_string()]; }
    let mut out: Vec<String> = Vec::new();
    let mut line = String::new();
    for word in text.split_whitespace() {
        let mut word = word;
        while word.chars().count() > width {
            if !line.is_empty() {
                out.push(std::mem::take(&mut line));
            }
            let cut = word.char_indices().nth(width).map(|(i, _)| i).unwrap_or(word.len());
            out.push(word[..cut].to_string());
            word = &word[cut..];
        }
        let extra = if line.is_empty() { 0 } else { 1 };
        if line.chars().count() + extra + word.chars().count() > width {
            out.push(std::mem::take(&mut line));
        }
        if !line.is_empty() { line.push(' '); }
        line.push_str(word);
    }
    if !line.is_empty() { out.push(line); }
    if out.is_empty() { out.push(String::new()); }
    out
}

fn centered(width: u16, height: u16, area: Rect) -> Rect {
    let x = area.x + area.width.saturating_sub(width) / 2;
    let y = area.y + area.height.saturating_sub(height) / 2;
    Rect::new(x, y, width.min(area.width), height.min(area.height))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrapping_never_exceeds_the_box() {
        // Overflowing by one column is what pushes the box border out of alignment.
        let err = "ServiceError: client error (Connect): tcp connect error: Connection refused (os error 111)";
        for width in [24usize, 40, 72] {
            for line in wrap(err, width) {
                assert!(line.chars().count() <= width, "width {width}: {line:?}");
            }
        }
    }

    #[test]
    fn a_word_longer_than_the_line_is_the_only_thing_broken_mid_word() {
        assert_eq!(wrap("un deux trois", 9), vec!["un deux", "trois"]);
        assert_eq!(wrap("https://very-long-host:6443", 10), vec!["https://ve", "ry-long-ho", "st:6443"]);
        assert_eq!(wrap("", 10), vec![""]);
    }
}
