//! Rebonds : joindre un apiserver que seul un hôte de rebond voit, sans toucher au kubeconfig.
//!
//! Le cas visé est celui d'un bastion qui n'ouvre qu'un shell : une CLI d'accès lance un `ssh`
//! vers une passerelle, la passerelle ouvre une session sur l'hôte de rebond, et de là on peut
//! encore sauter en `ssh` vers un second hôte. Aucun port-forward, aucun `ProxyJump` — juste un
//! terminal. kdt le pilote comme le ferait une personne : il lance `command` dans un
//! pseudo-terminal, attend l'invite du shell, tape chaque ligne de `then` (les sauts suivants),
//! puis, au bout de la chaîne, passe le terminal en mode brut et y lance `nc` vers l'apiserver.
//! Ce terminal devient alors un tuyau d'octets, que le client kube emprunte pour son TLS.
//!
//! # Comment le client kube s'y branche
//!
//! Par un proxy SOCKS5 local, ouvert par kdt sur `127.0.0.1` et protégé par un jeton : le nom de
//! l'apiserver part tel quel dans la requête SOCKS, le certificat est vérifié contre lui, et le
//! kubeconfig reste celui de tous les jours. `kubectl exec` (`E`) passe par le même proxy, via
//! `HTTPS_PROXY`. Sans jeton, n'importe quel processus local pourrait emprunter le rebond sous
//! l'identité de la personne.
//!
//! # Une session par connexion
//!
//! Un terminal ne transporte qu'un flux : chaque connexion TCP du client consomme une session
//! entière. Le pool de connexions de hyper les garde ouvertes, et des sessions de réserve
//! (`spare`), ouvertes d'avance jusqu'à l'invite finale, rendent une nouvelle connexion
//! immédiate.
//!
//! # Les invites
//!
//! Une question qui correspond à `prompt` (mot de passe d'un saut) n'est posée qu'une fois, dans
//! la fenêtre qui ouvre le contexte ([`prepare`], que l'écran de démarrage pilote par
//! [`JumpEvent`]) ; la réponse reste en mémoire et répond aux mêmes questions des sessions
//! suivantes, ouvertes en tâche de fond. Une question nouvelle à ce moment-là fait échouer la
//! session plutôt que de bloquer l'interface. Le déroulé des sessions n'est jamais montré : seul
//! le saut en cours l'est, et la fin de la sortie quand une session échoue.
//!
//! # L'invite du shell
//!
//! `ready` reconnaît les invites ordinaires (`$`, `#` en fin de ligne). Une invite décorée, sur deux
//! lignes, n'y ressemble pas : quand le terminal se tait sans poser de question, kdt tape une sonde
//! (`printf` d'un marqueur), et le marqueur revenu dit que le shell est là, quelle que soit la
//! forme de son invite.
//!
//! # Le caractère d'échappement de ssh
//!
//! Le `ssh` qu'une CLI de bastion lance avec un terminal a son échappement `~` actif, et la CLI ne
//! laisse pas toujours le couper (`-F /dev/null`). Dans un flux TLS, `\n~.` finit par arriver —
//! statistiquement dès le mégaoctet — et coupe la session. kdt double donc chaque `~` qui suit
//! une fin de ligne, la séquence que ssh documente pour transmettre un `~` seul. Les sauts tapés
//! dans `then` doivent, eux, couper l'échappement (`ssh -e none`) : un seul niveau se compense.
//!
//! # Un premier saut qui ne relaie pas tous les octets
//!
//! Une CLI qui pilote son `ssh` par pexpect relaie le terminal avec `interact()`, qui s'arrête au
//! premier `0x1d` (Ctrl-]) reçu — un octet qu'un flux TLS envoie dès sa poignée de main. Avec
//! `encode`, kdt n'envoie plus le flux montant brut : les octets de contrôle, `~` et `!` y sont
//! échappés (`!` puis l'octet décalé de 0x40), et un relais `python3` les décode sur le dernier saut,
//! à la place de `connect`. Le flux descendant reste brut : rien ne l'interprète en chemin.

use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::process::Stdio;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context as _, Result};
use regex::Regex;
use serde::Deserialize;
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot, OwnedSemaphorePermit, Semaphore};

use crate::lang;

/// The SOCKS user name: fixed, the token is what is checked.
pub const USER: &str = "kdt";

// How long a quiet terminal has to stay quiet before its last line is read as an invite: a banner
// printed in several writes would otherwise be taken for a prompt at its first `$`.
const SETTLE: Duration = Duration::from_millis(200);
// From the stream command to the marker it prints: one round trip and a `command -v`.
const STREAM_TIMEOUT: Duration = Duration::from_secs(30);
// What a session keeps of its own output, for the error message when it fails.
const SCREEN_MAX: usize = 64 * 1024;
// A terminal quiet this long, with no question on it, is asked whether a shell is listening.
const PROBE_AFTER: Duration = Duration::from_secs(2);

/// What the window opening a jump is told, and asked.
pub enum JumpEvent {
    /// Hop `n` of `total` is being reached, through `what` (the command, or the line typed).
    Hop { n: usize, total: usize, what: String },
    /// A question for the person; `None` sent back abandons.
    Ask { prompt: String, hidden: bool, reply: oneshot::Sender<Option<String>> },
}

/// Where [`prepare`] sends its [`JumpEvent`]s.
pub type Asker = mpsc::UnboundedSender<JumpEvent>;

/// One jump, as written in the `jumps` list of the config file.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct JumpConfig {
    pub name: String,
    /// The kubeconfig contexts reached through this jump.
    #[serde(default)]
    pub contexts: Vec<String>,
    /// The first hop: a program and its arguments, run in a pseudo-terminal.
    pub command: Vec<String>,
    /// The next hops: lines typed at each shell prompt, in order; `%u` is the account.
    #[serde(default)]
    pub then: Vec<String>,
    /// The account `%u` stands for; asked once on the terminal when absent.
    #[serde(default)]
    pub user: Option<String>,
    /// Escape the upstream bytes and decode them with `python3` on the last hop, for a first hop that
    /// does not relay every byte (pexpect's `interact()`); `connect` is then not used.
    #[serde(default)]
    pub encode: bool,
    /// What opens the byte stream on the last hop; `%h` and `%p` are the apiserver host and port.
    #[serde(default = "default_connect")]
    pub connect: String,
    #[serde(default = "default_ready")]
    pub ready: String,
    #[serde(default = "default_prompt")]
    pub prompt: String,
    /// The escape character of the first hop's ssh, `none` when it has none.
    #[serde(default = "default_escape")]
    pub escape: String,
    #[serde(default = "default_open_timeout")]
    pub open_timeout: u64,
    #[serde(default = "default_spare")]
    pub spare: usize,
    #[serde(default = "default_max_sessions")]
    pub max_sessions: usize,
}

fn default_connect() -> String {
    "nc %h %p".to_string()
}
fn default_ready() -> String {
    r"[$#] ?$".to_string()
}
fn default_prompt() -> String {
    r"(?i)(password|passphrase|mot de passe|verification code)[^\n]*: ?$".to_string()
}
fn default_escape() -> String {
    "~".to_string()
}
fn default_open_timeout() -> u64 {
    120
}
fn default_spare() -> usize {
    2
}
fn default_max_sessions() -> usize {
    12
}

/// The jump a context goes through, if any.
pub fn for_context<'a>(jumps: &'a [JumpConfig], context: &str) -> Option<&'a JumpConfig> {
    jumps.iter().find(|j| j.contexts.iter().any(|c| c == context))
}

/// Where the client finds the jump: the local SOCKS5 listener and its token.
pub struct Proxy {
    pub addr: SocketAddr,
    pub token: String,
}

impl Proxy {
    /// The listener alone, for a connector that is handed the credentials separately.
    pub fn uri(&self) -> String {
        format!("socks5://{}", self.addr)
    }

    /// The listener with its credentials, the form `HTTPS_PROXY` takes.
    pub fn url(&self) -> String {
        format!("socks5://{USER}:{}@{}", self.token, self.addr)
    }
}

/// Start the jump's listener if it is not running yet. Touches no network: sessions are opened by
/// the first connection, or by [`prepare`].
pub async fn proxy(cfg: &JumpConfig) -> Result<Proxy> {
    let jump = started(cfg).await?;
    Ok(Proxy { addr: jump.addr, token: jump.token.clone() })
}

/// The `HTTPS_PROXY` value for a context whose jump is running — what a shelled-out `kubectl`
/// needs to reach the same cluster.
pub fn proxy_url_for(context: &str) -> Option<String> {
    let map = registry().lock().ok()?;
    map.values()
        .find(|(j, _)| j.cfg.contexts.iter().any(|c| c == context))
        .map(|(j, _)| Proxy { addr: j.addr, token: j.token.clone() }.url())
}

/// Whether a session is already waiting at the last prompt, so that [`prepare`] would have nothing
/// to ask.
pub fn is_warm(cfg: &JumpConfig) -> bool {
    let Ok(map) = registry().lock() else { return false };
    match map.get(&cfg.name) {
        Some((j, _)) if j.cfg == *cfg => j.has_live_spare(),
        _ => false,
    }
}

/// Open a first session, the only moment a question can be answered: the hops and the questions
/// go to `asker`, whose window answers them. Dropping the future abandons, sessions included.
pub async fn prepare(cfg: &JumpConfig, asker: Asker) -> Result<()> {
    let jump = started(cfg).await?;
    if jump.has_live_spare() {
        return Ok(());
    }
    // Failed or abandoned half-way, a typed account is asked again next time rather than kept.
    let mut forget = ForgetAccount(Some(&jump.user));
    let session = jump.open(Some(&asker)).await?;
    forget.0 = None;
    jump.spares.lock().unwrap_or_else(|e| e.into_inner()).push(session);
    jump.prepared.send_replace(true);
    jump.refill();
    Ok(())
}

struct ForgetAccount<'a>(Option<&'a Mutex<Option<String>>>);

impl Drop for ForgetAccount<'_> {
    fn drop(&mut self) {
        if let Some(user) = self.0 {
            *user.lock().unwrap_or_else(|e| e.into_inner()) = None;
        }
    }
}

type Registry = Mutex<HashMap<String, (Arc<Jump>, tokio::task::AbortHandle)>>;

fn registry() -> &'static Registry {
    static JUMPS: OnceLock<Registry> = OnceLock::new();
    JUMPS.get_or_init(|| Mutex::new(HashMap::new()))
}

// A jump edited in the config file between two `:ctx` gets a fresh listener; an unchanged one is
// reused with its spares and the answers already given.
async fn started(cfg: &JumpConfig) -> Result<Arc<Jump>> {
    if let Some((j, _)) = registry().lock().unwrap_or_else(|e| e.into_inner()).get(&cfg.name) {
        if j.cfg == *cfg {
            return Ok(j.clone());
        }
    }
    let jump = Arc::new(Jump::new(cfg.clone()).await?);
    let listener = jump.listener.lock().unwrap_or_else(|e| e.into_inner()).take();
    let accept = tokio::spawn(accept_loop(jump.clone(), listener.expect("fresh listener")));
    let previous = registry()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(cfg.name.clone(), (jump.clone(), accept.abort_handle()));
    if let Some((_, handle)) = previous {
        handle.abort();
    }
    Ok(jump)
}

struct Jump {
    cfg: JumpConfig,
    ready: Regex,
    prompt: Regex,
    escape: Option<u8>,
    addr: SocketAddr,
    token: String,
    listener: Mutex<Option<TcpListener>>,
    answers: Mutex<HashMap<String, String>>,
    user: Mutex<Option<String>>,
    spares: Mutex<Vec<Session>>,
    opening: AtomicUsize,
    slots: Arc<Semaphore>,
    // Set once `prepare` has opened a session. The client's first connections arrive while the
    // window is still asking: they wait for its answers instead of opening sessions of their own,
    // which could only fail on the same questions.
    prepared: tokio::sync::watch::Sender<bool>,
    // The first hop is started one at a time: a bastion CLI keeps caches and agents of its own, and
    // several of them starting at once corrupt each other's files.
    first_hop: tokio::sync::Mutex<()>,
}

impl Jump {
    async fn new(cfg: JumpConfig) -> Result<Self> {
        let bad = |err: String| anyhow!(lang::fill(lang::active().jump_bad_config, &[("name", &cfg.name), ("err", &err)]));
        if cfg.command.is_empty() {
            return Err(bad("command: []".to_string()));
        }
        let ready = Regex::new(&cfg.ready).map_err(|e| bad(format!("ready: {e}")))?;
        let prompt = Regex::new(&cfg.prompt).map_err(|e| bad(format!("prompt: {e}")))?;
        let escape = match cfg.escape.as_str() {
            "" | "none" => None,
            s if s.len() == 1 && s.is_ascii() => Some(s.as_bytes()[0]),
            s => return Err(bad(format!("escape: {s}"))),
        };
        if !cfg.encode && (!cfg.connect.contains("%h") || !cfg.connect.contains("%p")) {
            return Err(bad(format!("connect: {}", cfg.connect)));
        }
        if let Some(u) = cfg.user.as_deref().filter(|u| !is_account(u)) {
            return Err(bad(format!("user: {u}")));
        }
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let addr = listener.local_addr()?;
        Ok(Self {
            slots: Arc::new(Semaphore::new(cfg.max_sessions.max(1))),
            cfg,
            ready,
            prompt,
            escape,
            addr,
            token: random_hex(16)?,
            listener: Mutex::new(Some(listener)),
            answers: Mutex::new(HashMap::new()),
            user: Mutex::new(None),
            spares: Mutex::new(Vec::new()),
            opening: AtomicUsize::new(0),
            prepared: tokio::sync::watch::Sender::new(false),
            first_hop: tokio::sync::Mutex::new(()),
        })
    }

    fn has_live_spare(&self) -> bool {
        let mut spares = self.spares.lock().unwrap_or_else(|e| e.into_inner());
        spares.retain_mut(Session::alive);
        !spares.is_empty()
    }

    fn take_spare(&self) -> Option<Session> {
        let mut spares = self.spares.lock().unwrap_or_else(|e| e.into_inner());
        while let Some(mut s) = spares.pop() {
            if s.alive() {
                return Some(s);
            }
        }
        None
    }

    // Top the reserve back up, in the background, with the answers already given.
    fn refill(self: &Arc<Self>) {
        let have = self.spares.lock().unwrap_or_else(|e| e.into_inner()).len() + self.opening.load(Ordering::SeqCst);
        for _ in have..self.cfg.spare {
            self.opening.fetch_add(1, Ordering::SeqCst);
            let jump = self.clone();
            tokio::spawn(async move {
                let opened = jump.open(None).await;
                jump.opening.fetch_sub(1, Ordering::SeqCst);
                match opened {
                    Ok(s) => jump.spares.lock().unwrap_or_else(|e| e.into_inner()).push(s),
                    Err(e) => tracing::warn!(jump = %jump.cfg.name, error = %format!("{e:#}"), "spare session not opened"),
                }
            });
        }
    }

    // A session at the last prompt, turned into a stream to `host:port`. A spare that went stale
    // while waiting (idle timeout of a hop) is given one fresh replacement.
    async fn stream(self: &Arc<Self>, host: &str, port: u16) -> Result<(Session, Vec<u8>)> {
        let _ = self.prepared.subscribe().wait_for(|done| *done).await;
        if let Some(spare) = self.take_spare() {
            self.refill();
            match self.open_stream(spare, host, port).await {
                Ok(s) => return Ok(s),
                Err(e) => tracing::info!(jump = %self.cfg.name, error = %format!("{e:#}"), "spare session unusable, opening another"),
            }
        }
        let session = self.open(None).await?;
        self.refill();
        self.open_stream(session, host, port).await
    }

    async fn open(&self, asker: Option<&Asker>) -> Result<Session> {
        // Asked before anything starts: the hops' own timeouts do not run while a person types.
        let user = match self.cfg.then.iter().any(|l| l.contains("%u")) {
            true => Some(self.account(asker).await?),
            false => None,
        };
        let hops: Vec<String> = self
            .cfg
            .then
            .iter()
            .filter(|l| !l.trim().is_empty())
            .map(|l| match &user {
                Some(u) => l.replace("%u", u),
                None => l.clone(),
            })
            .collect();
        let total = hops.len() + 1;
        let hop = |n: usize, what: &str| {
            if let Some(a) = asker {
                let _ = a.send(JumpEvent::Hop { n, total, what: what.to_string() });
            }
        };
        hop(1, &self.cfg.command.join(" "));
        let slot = self.slots.clone().acquire_owned().await?;
        let first_hop = self.first_hop.lock().await;
        let (pty, slave) = Pty::open()?;
        let mut cmd = tokio::process::Command::new(&self.cfg.command[0]);
        cmd.args(&self.cfg.command[1..])
            .env("TERM", "dumb")
            .stdin(Stdio::from(slave.try_clone()?))
            .stdout(Stdio::from(slave.try_clone()?))
            .stderr(Stdio::from(slave))
            .kill_on_drop(true);
        // A session of its own, with the pseudo-terminal as its controlling terminal: what `ssh` and
        // a password prompt look for before they agree to talk.
        unsafe {
            cmd.pre_exec(|| {
                if libc::setsid() < 0 || libc::ioctl(0, libc::TIOCSCTTY as _, 0) < 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = cmd.spawn().with_context(|| self.cfg.command[0].clone())?;
        drop(cmd);
        let mut session = Session { child, pty, _slot: slot };
        let mut screen = Screen::new();
        self.wait_ready(&mut session, &mut screen, asker).await?;
        drop(first_hop);
        for (i, line) in hops.iter().enumerate() {
            hop(i + 2, line);
            session.pty.write_all(format!("{line}\r").as_bytes()).await?;
            screen.clear();
            self.wait_ready(&mut session, &mut screen, asker).await?;
        }
        Ok(session)
    }

    // The account of the next hops: from the config, else the one typed earlier, else asked now.
    async fn account(&self, asker: Option<&Asker>) -> Result<String> {
        let st = lang::active();
        let name = self.cfg.name.as_str();
        if let Some(u) = &self.cfg.user {
            return Ok(u.clone());
        }
        if let Some(u) = self.user.lock().unwrap_or_else(|e| e.into_inner()).clone() {
            return Ok(u);
        }
        let Some(asker) = asker else {
            bail!(lang::fill(st.jump_needs_user, &[("name", name)]));
        };
        let cancelled = || anyhow!(lang::fill(st.jump_cancelled, &[("name", name)]));
        // It is typed into a remote shell: anything beyond an account name is refused.
        let mut prompt = st.jump_ask_user.to_string();
        let user = loop {
            let typed = ask(asker, &prompt, false).await.ok_or_else(cancelled)?;
            let typed = typed.trim().to_string();
            if is_account(&typed) {
                break typed;
            }
            prompt = lang::fill(st.jump_bad_user, &[("user", &typed)]);
        };
        *self.user.lock().unwrap_or_else(|e| e.into_inner()) = Some(user.clone());
        Ok(user)
    }

    // Read until a shell listens, answering the questions on the way: its prompt recognised by
    // `ready`, or the marker of a probe typed into a terminal gone quiet.
    async fn wait_ready(&self, s: &mut Session, screen: &mut Screen, asker: Option<&Asker>) -> Result<()> {
        let st = lang::active();
        let name = self.cfg.name.as_str();
        let mut deadline = Instant::now() + Duration::from_secs(self.cfg.open_timeout);
        let nonce = random_hex(6)?;
        // Assembled by printf, so the echo of the typed probe never contains it.
        let marker = format!("kdt-ready-{nonce}");
        let probe = format!("printf 'kdt-ready-%s\\n' {nonce}\r");
        // The questions answered from memory during this step: asked again, the answer was wrong.
        let mut answered: Vec<String> = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                let secs = self.cfg.open_timeout.to_string();
                bail!(lang::fill(st.jump_timeout, &[("name", name), ("secs", &secs), ("tail", &screen.tail())]));
            }
            let n = match tokio::time::timeout(left.min(PROBE_AFTER), s.pty.read(&mut buf)).await {
                Err(_) => {
                    // A question left on screen is not a silence: typing there would answer it.
                    if !self.prompt.is_match(&screen.last_line()) {
                        s.pty.write_all(probe.as_bytes()).await?;
                    }
                    continue;
                }
                Ok(r) => r?,
            };
            if n == 0 {
                bail!(lang::fill(st.jump_exited, &[("name", name), ("tail", &screen.tail())]));
            }
            screen.push(&buf[..n]);
            loop {
                match tokio::time::timeout(SETTLE, s.pty.read(&mut buf)).await {
                    Err(_) => break,
                    Ok(Ok(0)) => bail!(lang::fill(st.jump_exited, &[("name", name), ("tail", &screen.tail())])),
                    Ok(Ok(n)) => screen.push(&buf[..n]),
                    Ok(Err(e)) => return Err(e.into()),
                }
            }
            if screen.contains(&marker) {
                screen.clear();
                return Ok(());
            }
            let last = screen.last_line();
            if self.prompt.is_match(&last) {
                let key = last.trim().to_string();
                let remembered = self.answers.lock().unwrap_or_else(|e| e.into_inner()).get(&key).cloned();
                let answer = match remembered {
                    Some(a) if !answered.contains(&key) => a,
                    _ => {
                        self.answers.lock().unwrap_or_else(|e| e.into_inner()).remove(&key);
                        let Some(asker) = asker else {
                            bail!(lang::fill(st.jump_needs_input, &[("name", name), ("prompt", &key)]));
                        };
                        let asked = Instant::now();
                        let a = ask(asker, &key, true)
                            .await
                            .ok_or_else(|| anyhow!(lang::fill(st.jump_cancelled, &[("name", name)])))?;
                        deadline += asked.elapsed();
                        self.answers.lock().unwrap_or_else(|e| e.into_inner()).insert(key.clone(), a.clone());
                        a
                    }
                };
                answered.push(key);
                s.pty.write_all(format!("{answer}\r").as_bytes()).await?;
                screen.clear();
                continue;
            }
            if self.ready.is_match(&last) {
                screen.clear();
                return Ok(());
            }
        }
    }

    // Raw mode at both ends, then the stream command. The marker printed just before it says where
    // the shell's chatter stops and the apiserver's bytes begin.
    async fn open_stream(&self, s: Session, host: &str, port: u16) -> Result<(Session, Vec<u8>)> {
        let st = lang::active();
        let name = self.cfg.name.as_str();
        let target = format!("{host}:{port}");
        let connect = if self.cfg.encode {
            relay_command(host, port)
        } else {
            self.cfg.connect.replace("%h", host).replace("%p", &port.to_string())
        };
        let tool = connect.split_whitespace().find(|w| *w != "exec").unwrap_or("nc").to_string();
        let nonce = random_hex(8)?;
        // The marker is assembled by printf, so the echo of the typed line never contains it.
        let line = format!(
            "stty raw -echo -iexten cs8 -parenb; if command -v {tool} >/dev/null 2>&1; then printf 'kdt-jump-%s\\n' {nonce}; exec {connect}; else printf 'kdt-jump-%s-absent\\n' {nonce}; fi\r"
        );
        s.pty.set_raw();
        s.pty.write_all(line.as_bytes()).await?;
        let ok = format!("kdt-jump-{nonce}\n");
        let crlf = format!("kdt-jump-{nonce}\r\n");
        let absent = format!("kdt-jump-{nonce}-absent");
        let mut seen: Vec<u8> = Vec::new();
        let mut buf = [0u8; 4096];
        let deadline = Instant::now() + STREAM_TIMEOUT;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            let n = match tokio::time::timeout(left, s.pty.read(&mut buf)).await {
                Err(_) => 0,
                Ok(r) => r?,
            };
            if n == 0 {
                let tail = Screen::tail_of(&seen);
                bail!(lang::fill(st.jump_no_stream, &[("name", name), ("target", &target), ("tail", &tail)]));
            }
            seen.extend_from_slice(&buf[..n]);
            if find(&seen, absent.as_bytes()).is_some() {
                bail!(lang::fill(st.jump_missing_tool, &[("name", name), ("tool", &tool)]));
            }
            if find(&seen, crlf.as_bytes()).is_some() {
                bail!(lang::fill(st.jump_line_endings, &[("name", name)]));
            }
            if let Some(at) = find(&seen, ok.as_bytes()) {
                let rest = seen.split_off(at + ok.len());
                return Ok((s, rest));
            }
        }
    }
}

async fn accept_loop(jump: Arc<Jump>, listener: TcpListener) {
    loop {
        let Ok((tcp, _)) = listener.accept().await else { continue };
        let jump = jump.clone();
        tokio::spawn(async move {
            if let Err(e) = serve(jump.clone(), tcp).await {
                tracing::warn!(jump = %jump.cfg.name, error = %format!("{e:#}"), "jump connection");
            }
        });
    }
}

// SOCKS5 (RFC 1928) with username/password (RFC 1929), CONNECT only: what kube and kubectl send.
async fn serve(jump: Arc<Jump>, mut tcp: TcpStream) -> Result<()> {
    let mut head = [0u8; 2];
    tcp.read_exact(&mut head).await?;
    if head[0] != 5 {
        bail!("not a SOCKS5 client");
    }
    let mut methods = vec![0u8; head[1] as usize];
    tcp.read_exact(&mut methods).await?;
    if !methods.contains(&2) {
        tcp.write_all(&[5, 0xff]).await?;
        bail!("SOCKS client without credentials");
    }
    tcp.write_all(&[5, 2]).await?;
    let version = tcp.read_u8().await?;
    let user = read_field(&mut tcp).await?;
    let pass = read_field(&mut tcp).await?;
    if version != 1 || user != USER.as_bytes() || pass != jump.token.as_bytes() {
        tcp.write_all(&[1, 1]).await?;
        bail!("SOCKS credentials refused");
    }
    tcp.write_all(&[1, 0]).await?;

    let mut req = [0u8; 4];
    tcp.read_exact(&mut req).await?;
    if req[0] != 5 || req[1] != 1 {
        reply(&mut tcp, 7).await;
        bail!("SOCKS command {} not supported", req[1]);
    }
    let host = match req[3] {
        1 => {
            let mut a = [0u8; 4];
            tcp.read_exact(&mut a).await?;
            Ipv4Addr::from(a).to_string()
        }
        3 => String::from_utf8(read_field(&mut tcp).await?)?,
        4 => {
            let mut a = [0u8; 16];
            tcp.read_exact(&mut a).await?;
            Ipv6Addr::from(a).to_string()
        }
        _ => {
            reply(&mut tcp, 8).await;
            bail!("SOCKS address type {} not supported", req[3]);
        }
    };
    let port = tcp.read_u16().await?;
    // The host is typed into a remote shell: anything beyond a host name is refused outright.
    if !is_host(&host) {
        reply(&mut tcp, 2).await;
        bail!(lang::fill(lang::active().jump_bad_target, &[("target", &host)]));
    }
    let (session, first) = match jump.stream(&host, port).await {
        Ok(s) => s,
        Err(e) => {
            reply(&mut tcp, 1).await;
            return Err(e);
        }
    };
    reply(&mut tcp, 0).await;
    // Encoded, the upstream never carries an escape character for ssh to act on.
    let upstream = if jump.cfg.encode { Upstream::Encoded } else { Upstream::Raw(jump.escape) };
    relay(session, first, tcp, upstream).await
}

async fn read_field(tcp: &mut TcpStream) -> io::Result<Vec<u8>> {
    let len = tcp.read_u8().await?;
    let mut v = vec![0u8; len as usize];
    tcp.read_exact(&mut v).await?;
    Ok(v)
}

async fn reply(tcp: &mut TcpStream, code: u8) {
    let _ = tcp.write_all(&[5, code, 0, 1, 0, 0, 0, 0, 0, 0]).await;
}

fn is_account(user: &str) -> bool {
    !user.is_empty()
        && !user.starts_with('-')
        && user.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '@'))
}

fn is_host(host: &str) -> bool {
    !host.is_empty()
        && !host.starts_with('-')
        && host.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '_'))
}

async fn relay(session: Session, first: Vec<u8>, mut tcp: TcpStream, upstream: Upstream) -> Result<()> {
    let (mut rd, mut wr) = tcp.split();
    if !first.is_empty() {
        wr.write_all(&first).await?;
    }
    let pty = &session.pty;
    let up = async {
        let mut buf = [0u8; 16 * 1024];
        let mut out = Vec::with_capacity(buf.len() + 64);
        // The stream command ended with a carriage return: ssh is at the start of a line.
        let mut line_start = true;
        loop {
            let n = rd.read(&mut buf).await?;
            if n == 0 {
                return Ok::<_, io::Error>(());
            }
            match upstream {
                Upstream::Raw(escape) => escape_into(&buf[..n], escape, &mut line_start, &mut out),
                Upstream::Encoded => encode_into(&buf[..n], &mut out),
            }
            pty.write_all(&out).await?;
            out.clear();
        }
    };
    let down = async {
        let mut buf = [0u8; 16 * 1024];
        loop {
            let n = pty.read(&mut buf).await?;
            if n == 0 {
                let _ = wr.shutdown().await;
                return Ok::<_, io::Error>(());
            }
            wr.write_all(&buf[..n]).await?;
        }
    };
    tokio::select! {
        r = up => r?,
        r = down => r?,
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum Upstream {
    /// As is, an ssh escape character at the start of a line doubled.
    Raw(Option<u8>),
    /// Escaped for the `python3` relay of [`RELAY`].
    Encoded,
}

// The byte that announces an escaped one, and what is escaped: every control byte, the ssh escape
// character, DEL, and the announcing byte itself. Printable and 8-bit bytes pass as they are.
const ESC: u8 = b'!';

fn encode_into(data: &[u8], out: &mut Vec<u8>) {
    for &b in data {
        if b < 0x20 || b == ESC || b == b'~' || b == 0x7f {
            out.push(ESC);
            out.push(b.wrapping_add(0x40));
        } else {
            out.push(b);
        }
    }
}

// The last hop's end of `encode`: connects to the apiserver, decodes what comes from the terminal,
// copies the answer back untouched. Shipped in base64 so that it is typed as one line with no quote
// of its own.
const RELAY: &str = "import os,socket,select,sys
s=socket.create_connection((sys.argv[1],int(sys.argv[2])))
i=sys.stdin.fileno()
o=sys.stdout.fileno()
p=False
while True:
    r=select.select([i,s],[],[])[0]
    if s in r:
        d=s.recv(65536)
        if not d:
            break
        while d:
            d=d[os.write(o,d):]
    if i in r:
        d=os.read(i,65536)
        if not d:
            break
        b=bytearray()
        for c in d:
            if p:
                b.append((c-64)&255)
                p=False
            elif c==33:
                p=True
            else:
                b.append(c)
        s.sendall(b)
";

fn relay_command(host: &str, port: u16) -> String {
    use base64::Engine;
    let code = base64::engine::general_purpose::STANDARD.encode(RELAY);
    format!("python3 -c \"import base64;exec(base64.b64decode('{code}'))\" {host} {port}")
}

// What ssh's escape handling turns back into `data`: an escape character at the start of a line is
// doubled, the sequence ssh forwards as a single one.
fn escape_into(data: &[u8], escape: Option<u8>, line_start: &mut bool, out: &mut Vec<u8>) {
    let Some(esc) = escape else {
        out.extend_from_slice(data);
        return;
    };
    for &b in data {
        if *line_start && b == esc {
            out.push(esc);
        }
        out.push(b);
        *line_start = b == b'\r' || b == b'\n';
    }
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

fn random_hex(bytes: usize) -> io::Result<String> {
    use std::io::Read;
    let mut raw = vec![0u8; bytes];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut raw)?;
    Ok(raw.iter().map(|b| format!("{b:02x}")).collect())
}

// A question handed to the window, the answer awaited. `None` when the window abandoned or is gone.
async fn ask(asker: &Asker, prompt: &str, hidden: bool) -> Option<String> {
    let (reply, answer) = oneshot::channel();
    asker.send(JumpEvent::Ask { prompt: prompt.to_string(), hidden, reply }).ok()?;
    answer.await.ok().flatten()
}

struct Session {
    child: tokio::process::Child,
    pty: Pty,
    _slot: OwnedSemaphorePermit,
}

impl Session {
    fn alive(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }
}

impl Drop for Session {
    // The whole process group: the bastion CLI may have forked its ssh rather than exec'd it.
    fn drop(&mut self) {
        if let Some(pid) = self.child.id() {
            unsafe {
                libc::kill(-(pid as libc::pid_t), libc::SIGHUP);
            }
        }
    }
}

// What a session printed since the last line kdt typed, ANSI sequences stripped.
struct Screen {
    raw: Vec<u8>,
}

impl Screen {
    fn new() -> Self {
        Self { raw: Vec::new() }
    }

    fn push(&mut self, bytes: &[u8]) {
        self.raw.extend_from_slice(bytes);
        if self.raw.len() > SCREEN_MAX {
            let cut = self.raw.len() - SCREEN_MAX / 2;
            self.raw.drain(..cut);
        }
    }

    fn clear(&mut self) {
        self.raw.clear();
    }

    fn contains(&self, needle: &str) -> bool {
        strip_ansi(&self.raw).contains(needle)
    }

    fn last_line(&self) -> String {
        let text = strip_ansi(&self.raw);
        visible(text.rsplit('\n').next().unwrap_or("")).to_string()
    }

    fn tail(&self) -> String {
        Self::tail_of(&self.raw)
    }

    fn tail_of(raw: &[u8]) -> String {
        let text = strip_ansi(raw);
        let lines: Vec<&str> = text.split('\n').map(visible).map(str::trim).filter(|l| !l.is_empty()).collect();
        let from = lines.len().saturating_sub(4);
        lines[from..].join(" | ")
    }
}

// What a terminal would show of a line: the text after the last carriage return that has any.
fn visible(line: &str) -> &str {
    line.rsplit('\r').find(|s| !s.is_empty()).unwrap_or("").trim_end()
}

fn strip_ansi(raw: &[u8]) -> String {
    let s = String::from_utf8_lossy(raw);
    let mut out = String::with_capacity(s.len());
    let mut it = s.chars();
    while let Some(c) = it.next() {
        if c == '\x1b' {
            match it.next() {
                Some('[') => {
                    for c in it.by_ref() {
                        if ('@'..='~').contains(&c) {
                            break;
                        }
                    }
                }
                Some(']') => {
                    while let Some(c) = it.next() {
                        if c == '\x07' {
                            break;
                        }
                        if c == '\x1b' {
                            it.next();
                            break;
                        }
                    }
                }
                _ => {}
            }
        } else if matches!(c, '\n' | '\r' | '\t') || !c.is_control() {
            out.push(c);
        }
    }
    out
}

// The master side of a pseudo-terminal, non-blocking under tokio.
struct Pty(AsyncFd<OwnedFd>);

impl Pty {
    fn open() -> io::Result<(Pty, OwnedFd)> {
        let mut master: libc::c_int = -1;
        let mut slave: libc::c_int = -1;
        // Wide enough that no prompt or typed line wraps: the last line has to be read whole.
        let mut size = libc::winsize { ws_row: 50, ws_col: 400, ws_xpixel: 0, ws_ypixel: 0 };
        // `&mut`: macOS declares the size pointer mutable, where Linux takes it const.
        #[allow(clippy::unnecessary_mut_passed)]
        let rc = unsafe { libc::openpty(&mut master, &mut slave, std::ptr::null_mut(), std::ptr::null_mut(), &mut size) };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        let (master, slave) = unsafe { (OwnedFd::from_raw_fd(master), OwnedFd::from_raw_fd(slave)) };
        unsafe {
            libc::fcntl(master.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC);
            libc::fcntl(slave.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC);
            let flags = libc::fcntl(master.as_raw_fd(), libc::F_GETFL);
            libc::fcntl(master.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK);
        }
        Ok((Pty(AsyncFd::new(master)?), slave))
    }

    // Best effort: the ssh at the near end has normally done it already when it took the terminal.
    fn set_raw(&self) {
        let fd = self.0.as_raw_fd();
        unsafe {
            let mut t: libc::termios = std::mem::zeroed();
            if libc::tcgetattr(fd, &mut t) == 0 {
                libc::cfmakeraw(&mut t);
                libc::tcsetattr(fd, libc::TCSANOW, &t);
            }
        }
    }

    // End of file once the other side is gone: Linux reports it as EIO on the master.
    async fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            let mut guard = self.0.readable().await?;
            let res = guard.try_io(|fd| {
                let n = unsafe { libc::read(fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
                if n < 0 { Err(io::Error::last_os_error()) } else { Ok(n as usize) }
            });
            match res {
                Ok(Err(e)) if e.raw_os_error() == Some(libc::EIO) => return Ok(0),
                Ok(r) => return r,
                Err(_) => continue,
            }
        }
    }

    async fn write_all(&self, mut data: &[u8]) -> io::Result<()> {
        while !data.is_empty() {
            let mut guard = self.0.writable().await?;
            let res = guard.try_io(|fd| {
                let n = unsafe { libc::write(fd.as_raw_fd(), data.as_ptr().cast(), data.len()) };
                if n < 0 { Err(io::Error::last_os_error()) } else { Ok(n as usize) }
            });
            match res {
                Ok(Ok(n)) => data = &data[n..],
                Ok(Err(e)) => return Err(e),
                Err(_) => continue,
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn esc(chunks: &[&[u8]]) -> Vec<u8> {
        let mut line_start = true;
        let mut out = Vec::new();
        for c in chunks {
            escape_into(c, Some(b'~'), &mut line_start, &mut out);
        }
        out
    }

    #[test]
    fn a_tilde_is_doubled_only_at_the_start_of_a_line() {
        assert_eq!(esc(&[b"~.a~b\n~C\r~~x"]), b"~~.a~b\n~~C\r~~~x".to_vec());
    }

    #[test]
    fn the_line_start_survives_a_chunk_boundary() {
        assert_eq!(esc(&[b"ab\r", b"~."]), b"ab\r~~.".to_vec());
        assert_eq!(esc(&[b"ab", b"~."]), b"ab~.".to_vec());
    }

    #[test]
    fn the_encoded_upstream_carries_no_control_byte_and_decodes_back() {
        let all: Vec<u8> = (0..=255u8).chain([b'!', 0x1d, b'~', b'\n']).collect();
        let mut out = Vec::new();
        encode_into(&all, &mut out);
        assert!(!out.iter().any(|&b| b < 0x20 || b == 0x7f || b == b'~'), "{out:?}");
        // The decoder of RELAY, byte for byte.
        let (mut back, mut pending) = (Vec::new(), false);
        for c in out {
            if pending {
                back.push(c.wrapping_sub(64));
                pending = false;
            } else if c == ESC {
                pending = true;
            } else {
                back.push(c);
            }
        }
        assert_eq!(back, all);
        assert_eq!(ESC, 33, "RELAY tests c==33");
    }

    #[test]
    fn without_an_escape_character_nothing_changes() {
        let mut line_start = true;
        let mut out = Vec::new();
        escape_into(b"~.\n~.", None, &mut line_start, &mut out);
        assert_eq!(out, b"~.\n~.".to_vec());
    }

    #[test]
    fn the_last_line_is_what_a_terminal_shows() {
        let mut s = Screen::new();
        s.push(b"Last login: x\r\n\x1b]0;title\x07\x1b[?2004h[me@jump ~]$ ");
        assert_eq!(s.last_line(), "[me@jump ~]$");
        s.push(b"\r\n\rspinning\rpassword for me: ");
        assert_eq!(s.last_line(), "password for me:");
    }

    #[test]
    fn the_default_patterns_tell_a_prompt_from_a_shell() {
        let ready = Regex::new(&default_ready()).unwrap();
        let prompt = Regex::new(&default_prompt()).unwrap();
        assert!(ready.is_match("[me@jump ~]$"));
        assert!(ready.is_match("root@jump:~#"));
        assert!(!ready.is_match("Welcome"));
        assert!(prompt.is_match("me@fpciadm3001's password:"));
        assert!(prompt.is_match("Mot de passe :"));
        assert!(!prompt.is_match("[me@jump ~]$"));
    }

    #[test]
    fn only_an_account_name_reaches_the_remote_shell() {
        assert!(is_account("jdoe"));
        assert!(is_account("j.doe@corp.example"));
        assert!(!is_account("-oProxyCommand=x"));
        assert!(!is_account("a b"));
        assert!(!is_account("$(id)"));
        assert!(!is_account(""));
    }

    #[test]
    fn only_a_host_name_reaches_the_remote_shell() {
        assert!(is_host("api.cluster.example"));
        assert!(is_host("10.0.0.1"));
        assert!(is_host("2001:db8::1"));
        assert!(!is_host("-oProxyCommand=x"));
        assert!(!is_host("a;rm -rf"));
        assert!(!is_host("$(id)"));
        assert!(!is_host(""));
    }

    #[test]
    fn a_context_is_matched_by_its_exact_name() {
        let j: Vec<JumpConfig> = serde_json::from_str(
            r#"[{"name":"j","contexts":["prod"],"command":["cli","connect","jump-01"]}]"#,
        )
        .unwrap();
        assert!(for_context(&j, "prod").is_some());
        assert!(for_context(&j, "prod2").is_none());
        assert_eq!(j[0].connect, "nc %h %p");
        assert_eq!(j[0].escape, "~");
    }
}
