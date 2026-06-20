//! PDF report rendering via an embedded Typst template. Rust builds a Typst input dictionary
//! (brand, diagnostic, node tables, AI blocks); the template at `TEMPLATE` lays out the document.
//!
//! Security note: AI/markdown content is rendered by evaluating Typst markup. `convert_inline_md`
//! escapes the characters Typst treats as code (`#`, `[`, `]`, `<`, `>`, `@`, `$`, `~`, `\`) so
//! model output cannot inject Typst function calls; code blocks go through `raw()` which never
//! evaluates. Keep that escaping in sync with the `eval(...)` calls in the template.

use std::path::{Path, PathBuf};

use typst::foundations::{Array, Dict, Str, Value};
use typst_as_lib::{TypstEngine, typst_kit_options::TypstKitFontOptions};

const BRAND_RED: &str = "#E60028";
const BRAND_RED_DARK: &str = "#A30021";
const BRAND_RED_LIGHT_BG: &str = "#FCE4E8";
const BRAND_RED_BORDER: &str = "#F4B5C0";
const BRAND_TEXT_DARK: &str = "#1F1F1F";

const BRAND_FONT_SANS: &[&str] = &[
    "Claranet Sans",
    "Effra",
    "Inter",
    "Helvetica Neue",
    "Arial",
    "DejaVu Sans",
];
const BRAND_FONT_MONO: &[&str] = &[
    "DejaVu Sans Mono",
    "Liberation Mono",
    "Menlo",
    "Consolas",
    "Courier New",
];

const TEMPLATE: &str = r###"
#let inp = sys.inputs
#let brand = inp.brand

#set document(title: inp.title, author: "kdt")
#set page(
  paper: "a4",
  margin: (x: 1.8cm, y: 1.8cm),
  header: context if counter(page).get().first() > 1 {
    align(right, text(fill: rgb("#888"), size: 8pt)[kdt · #inp.context])
    v(-4pt)
    line(length: 100%, stroke: 0.4pt + rgb(brand.red_border))
  },
  footer: context align(center, text(fill: rgb("#888"), size: 8pt)[
    #counter(page).display() / #counter(page).final().first()
  ]),
)
#set text(font: brand.font_sans, size: 10pt, lang: "fr", fill: rgb(brand.text_dark), hyphenate: false)
#set par(justify: false, leading: 0.55em, linebreaks: "simple")

#show heading.where(level: 1): it => block(below: 0.6em)[
  #set text(size: 24pt, weight: "bold", fill: rgb(brand.red))
  #it.body
]
#show heading.where(level: 2): it => block(above: 1.2em, below: 0.4em)[
  #set text(size: 14pt, weight: "bold", fill: rgb(brand.red))
  #it.body
  #v(2pt)
  #line(length: 100%, stroke: 0.6pt + rgb(brand.red_border))
]
#show heading.where(level: 3): it => block(above: 0.7em, below: 0.2em)[
  #set text(size: 11pt, weight: "bold", fill: rgb(brand.red_dark))
  #it.body
]

#show raw.where(block: true): it => block(
  fill: rgb("#f6f8fa"),
  stroke: 0.5pt + rgb("#d0d7de"),
  inset: 8pt, radius: 3pt, width: 100%,
  breakable: true,
)[#set par(justify: false, leading: 0.45em, linebreaks: "simple")
  #set text(font: brand.font_mono, size: 8.5pt, hyphenate: false, costs: (hyphenation: 100%, runt: 100%, widow: 0%, orphan: 0%))
  #it]
#show raw.where(block: false): it => box(
  fill: rgb("#f6f8fa"),
  stroke: 0.4pt + rgb("#d0d7de"),
  inset: (x: 3pt, y: 1pt), radius: 2pt,
  outset: (y: 2pt),
)[#text(font: brand.font_mono, size: 9pt, hyphenate: false)[#it]]

#let badge(label, fg, bg) = box(
  fill: bg, inset: (x: 6pt, y: 2pt), radius: 3pt, baseline: 1pt,
)[#text(fill: fg, weight: "bold", size: 8pt)[#label]]

#let status-badge(s) = {
  if s == "ok" { badge("OK", white, rgb("#2e7d32")) }
  else if s == "warn" { badge("WARN", white, rgb("#ef6c00")) }
  else if s == "err" { badge("ERR", white, rgb(brand.red)) }
  else if s == "info" { badge("INFO", white, rgb("#1565c0")) }
  else { badge(upper(s), white, rgb("#616161")) }
}

#let line-fill(c) = {
  if c == "ok" { rgb("#1b5e20") }
  else if c == "warn" { rgb("#bf6500") }
  else if c == "err" { rgb(brand.red_dark) }
  else if c == "info" { rgb("#0d47a1") }
  else if c == "dim" { rgb("#777777") }
  else { rgb(brand.text_dark) }
}

#let render-ai(ai) = {
  if ai.error != "" {
    block(fill: rgb(brand.red_light_bg), stroke: 0.5pt + rgb(brand.red_border), inset: 10pt, radius: 4pt, width: 100%)[
      #text(fill: rgb(brand.red_dark), weight: "bold")[Erreur :] #h(4pt) #ai.error
    ]
  } else if ai.blocks.len() == 0 {
    text(fill: rgb("#888"))[(pas de réponse IA)]
  } else {
    if ai.model != "" {
      text(fill: rgb("#666"), size: 8pt)[Modèle : ]
      raw(ai.model, block: false)
      v(0.3em)
    }
    for b in ai.blocks {
      if b.kind == "h1" { heading(level: 2, b.text) }
      else if b.kind == "h2" { heading(level: 3, b.text) }
      else if b.kind == "h3" { heading(level: 3, b.text) }
      else if b.kind == "code" { raw(b.text, lang: b.lang, block: true) }
      // b.text is pre-escaped by convert_inline_md, so evaluating it as markup is safe.
      else if b.kind == "list" [
        - #eval("[" + b.text + "]", mode: "markup")
      ]
      else if b.kind == "spacer" { v(0.4em) }
      else {
        eval("[" + b.text + "]", mode: "markup")
        parbreak()
      }
    }
  }
}

#let cell-bg(lvl) = {
  if lvl == 1 { rgb("#503737") }
  else if lvl == 2 { rgb("#6e3c3c") }
  else if lvl == 3 { rgb("#8c3737") }
  else if lvl == 4 { rgb("#aa2d2d") }
  else if lvl == 5 { rgb("#c81e1e") }
  else { none }
}

#let marker-fg(m) = {
  if m == "▲" or m == "↑" { rgb("#ffe082") }
  else if m == "▼" or m == "↓" or m == "↡" { rgb("#fff59d") }
  else if m == "≫" { rgb("#ffccbc") }
  else { white }
}

#let usage-cell(c) = {
  let marker-span = if c.marker != "" {
    [#h(3pt)#text(fill: rgb(brand.red), weight: "bold", size: 8pt)[#c.marker]]
  } else { [] }
  if c.level == 6 {
    table.cell()[#text(font: brand.font_mono, fill: rgb(brand.red), weight: "bold", size: 8pt)[#c.text]#marker-span]
  } else if c.level == 0 {
    table.cell()[#text(font: brand.font_mono, size: 8pt)[#c.text]#if c.marker != "" [#h(3pt)#text(fill: rgb("#bf6500"), weight: "bold")[#c.marker]]]
  } else {
    table.cell(fill: cell-bg(c.level))[#text(font: brand.font_mono, fill: white, weight: "bold", size: 8pt)[#c.text]#if c.marker != "" [#h(3pt)#text(fill: marker-fg(c.marker), weight: "bold")[#c.marker]]]
  }
}

// Helper: render text where the first letter of each word is bigger than the rest.
// `txt` should be lowercase. Words are split on spaces.
#let big-first(txt, big-size, small-size, fill-color) = {
  let words = txt.split(" ")
  for (i, w) in words.enumerate() {
    if i > 0 { text(size: small-size, fill: fill-color)[ ] }
    if w.len() > 0 {
      text(size: big-size, fill: fill-color, weight: "bold")[#w.first()]
      if w.len() > 1 {
        text(size: small-size, fill: fill-color, weight: "bold")[#w.slice(1)]
      }
    }
  }
}

// ===== Cover page =====
#v(2.5cm)

#align(center)[
  #big-first("kdt", 90pt, 56pt, rgb(brand.red))
]

#v(0.5cm)

#align(center)[
  #big-first("kubernetes diagnostic tools", 22pt, 16pt, rgb(brand.red_dark))
]

#v(2.8cm)

#align(center)[
  #line(length: 6cm, stroke: 1pt + rgb(brand.red))
]

#v(1.2cm)

#align(center)[
  #text(size: 28pt, weight: "bold", fill: rgb(brand.text_dark))[#inp.title]
]

#v(2cm)

#align(center)[
  #block(width: 70%)[
    #align(left)[
      #grid(
        columns: (auto, 1fr),
        column-gutter: 1.5em,
        row-gutter: 0.6em,
        text(fill: rgb(brand.red_dark), weight: "bold", size: 11pt)[Contexte],
        text(size: 11pt)[#inp.context],
        text(fill: rgb(brand.red_dark), weight: "bold", size: 11pt)[Namespace],
        text(size: 11pt)[#inp.namespace],
        text(fill: rgb(brand.red_dark), weight: "bold", size: 11pt)[Généré le],
        text(size: 11pt)[#inp.generated_at],
      )
    ]
  ]
]

#v(1.5cm)

#let summary = inp.summary
#align(center)[
  #block(width: 70%, fill: rgb(brand.red_light_bg), stroke: 0.5pt + rgb(brand.red_border), inset: 14pt, radius: 4pt)[
    #text(weight: "bold", fill: rgb(brand.red_dark), size: 11pt)[Contenu de l'extraction] \
    #v(4pt)
    #if summary.has_diagnostic [
      · diagnostic cluster (#summary.diag_total étapes) \
    ]
    #if summary.node_count > 0 [
      · usage détaillé de #summary.node_count noeud(s) avec analyse IA \
    ]
  ]
]

#align(bottom + center)[
  #v(1fr)
  #text(fill: rgb("#999"), size: 8pt)[
    rapport généré automatiquement par #big-first("kdt", 9pt, 8pt, rgb("#999"))
  ]
]

#if inp.has_diagnostic [
  #pagebreak()
  #let d = inp.diagnostic
  #let counts = d.counts
  = Diagnostic cluster

  #block(fill: rgb(brand.red_light_bg), stroke: 0.5pt + rgb(brand.red_border), inset: 8pt, radius: 4pt, width: 100%)[
    #text(weight: "bold", fill: rgb(brand.red_dark))[Bilan] — #counts.total étapes : #h(0.4em)
    #status-badge("ok") #h(2pt) #counts.ok #h(0.8em)
    #status-badge("info") #h(2pt) #counts.info #h(0.8em)
    #status-badge("warn") #h(2pt) #counts.warn #h(0.8em)
    #status-badge("err") #h(2pt) #counts.err
  ]

  == Étapes
  #for step in d.steps [
    #block(above: 0.9em, below: 0.4em)[
      #status-badge(step.status) #h(6pt)
      #text(weight: "bold", size: 11pt)[#step.title]
    ]

    #raw(step.command, lang: "sh", block: true)

    #for line in step.lines [
      #block(above: 1pt, below: 1pt)[
        #text(fill: line-fill(line.color), size: 9.5pt)[#line.text]
      ]
    ]
  ]

  == Analyse IA
  #render-ai(d.ai)
]

#set page(flipped: true)

#for node in inp.nodes [
  #pagebreak()
  = Noeud : #raw(node.name, block: false)

    #text(fill: rgb("#666"), size: 9pt)[
      allocatable cpu=*#node.alloc_cpu*, mem=*#node.alloc_mem*  ·  metrics-server : #if node.metrics_available [#text(fill: rgb("#1b5e20"))[disponible]] else [#text(fill: rgb("#bf6500"))[indisponible]]  ·  *#node.user_count* user · *#node.system_count* system
    ]

    #v(0.4em)

    #grid(
      columns: (1fr, 1fr),
      gutter: 10pt,
      block(fill: rgb("#f1f8e9"), inset: 8pt, radius: 4pt, width: 100%)[
        #text(weight: "bold")[User containers (#node.user_count)] \
        cpu req=*#node.user_cpu_req* lim=*#node.user_cpu_lim* use=*#node.user_cpu_use* \
        mem req=*#node.user_mem_req* lim=*#node.user_mem_lim* use=*#node.user_mem_use*
      ],
      block(fill: rgb("#eceff1"), inset: 8pt, radius: 4pt, width: 100%)[
        #text(weight: "bold")[System containers (#node.system_count)] \
        cpu req=*#node.sys_cpu_req* use=*#node.sys_cpu_use* \
        mem req=*#node.sys_mem_req* use=*#node.sys_mem_use*
      ],
    )

    #v(0.5em)

    #let lvl-swatch(lvl, label) = box(inset: 0pt)[
      #box(width: 14pt, height: 9pt, fill: cell-bg(lvl), stroke: 0.3pt + rgb("#999"))
      #h(2pt)
      #text(size: 7.5pt)[#label]
    ]

    #block(
      fill: rgb("#f8f9fa"),
      stroke: 0.4pt + rgb("#cfd8dc"),
      inset: 8pt,
      radius: 3pt,
      width: 100%,
    )[
      #text(weight: "bold", fill: rgb(brand.red_dark), size: 9pt)[Légende] \
      #v(2pt)
      #grid(
        columns: (1fr, 1fr),
        column-gutter: 12pt,
        row-gutter: 3pt,
        // Left: symbols
        block[
          #text(size: 8pt, weight: "bold", fill: rgb(brand.text_dark))[Symboles dans les cellules] \
          #text(size: 8pt)[
            #text(fill: rgb(brand.red), weight: "bold")[▲] use ≥ limit (cpuMax / OOMrisk) \
            #text(fill: rgb(brand.red), weight: "bold")[▼] sous-utilisé (use < 30 % de request) \
            #text(fill: rgb(brand.red), weight: "bold")[↡] sous-utilisé extrême (use < 5 %) \
            #text(fill: rgb(brand.red), weight: "bold")[≫] limit ≫ request (limit > 4× req) \
            #text(fill: rgb(brand.red), weight: "bold")[—] valeur manquante (request ou limit non définie) \
            #text(fill: rgb("#999"))[·] préfixe = conteneur système
          ]
        ],
        // Right: color scale
        block[
          #text(size: 8pt, weight: "bold", fill: rgb(brand.text_dark))[Surlignage rouge — impact sur le noeud] \
          #text(size: 7.5pt, fill: rgb("#666"))[(% de l'allocatable du noeud occupé par la valeur)] \
          #v(2pt)
          #lvl-swatch(1, "2 – 6 %")  #h(6pt)
          #lvl-swatch(2, "6 – 12 %") #h(6pt)
          #lvl-swatch(3, "12 – 20 %") \
          #v(2pt)
          #lvl-swatch(4, "20 – 30 %") #h(6pt)
          #lvl-swatch(5, "≥ 30 %") \
          #v(2pt)
          #text(size: 7.5pt, fill: rgb("#666"))[Plus le rouge est vif, plus la valeur consomme une part importante du noeud.]
        ]
      )
    ]

    #v(0.5em)

    #table(
      columns: (auto, auto, 1fr, 1fr, auto, auto, auto, auto, auto, auto, auto, auto),
      stroke: 0.4pt + rgb("#cfd8dc"),
      align: (center, left, left, left, right, right, right, right, right, right, center, center),
      table.header(
        text(weight: "bold", size: 8pt)[],
        text(weight: "bold", size: 8pt)[NS],
        text(weight: "bold", size: 8pt)[POD],
        text(weight: "bold", size: 8pt)[CONTAINER],
        text(weight: "bold", size: 8pt)[CPU req],
        text(weight: "bold", size: 8pt)[CPU lim],
        text(weight: "bold", size: 8pt)[CPU use],
        text(weight: "bold", size: 8pt)[MEM req],
        text(weight: "bold", size: 8pt)[MEM lim],
        text(weight: "bold", size: 8pt)[MEM use],
        text(weight: "bold", size: 8pt)[R],
        text(weight: "bold", size: 8pt)[RST],
      ),
      ..for r in node.rows {
        let sys-marker = if r.system { "·" } else { " " }
        let id-color = if r.system { rgb("#777777") } else { rgb(brand.text_dark) }
        (
          table.cell()[#text(fill: rgb("#999"), size: 8pt)[#sys-marker]],
          table.cell()[#text(fill: id-color, font: brand.font_mono, size: 8pt)[#r.namespace]],
          table.cell()[#text(fill: id-color, font: brand.font_mono, size: 8pt)[#r.pod]],
          table.cell()[#text(fill: id-color, font: brand.font_mono, size: 8pt)[#r.container]],
          usage-cell(r.cpu_req),
          usage-cell(r.cpu_lim),
          usage-cell(r.cpu_use),
          usage-cell(r.mem_req),
          usage-cell(r.mem_lim),
          usage-cell(r.mem_use),
          table.cell()[#text(fill: line-fill(r.ready_color), weight: "bold", size: 8pt)[#r.ready]],
          table.cell()[#text(fill: line-fill(r.restarts_color), font: brand.font_mono, size: 8pt)[#r.restarts]],
        )
      }
    )

    #v(0.6em)

    == Analyse IA
    #render-ai(node.ai)
]
"###;

#[derive(Debug, Clone)]
pub struct DiagLine {
    pub color: &'static str,
    pub text: String,
}

#[derive(Debug, Clone)]
pub struct DiagStep {
    pub status: &'static str,
    pub title: String,
    pub command: String,
    pub lines: Vec<DiagLine>,
}

#[derive(Debug, Clone)]
pub struct DiagDoc {
    pub ok: usize,
    pub warn: usize,
    pub err: usize,
    pub info: usize,
    pub steps: Vec<DiagStep>,
    pub ai_model: String,
    pub ai_content: String,
    pub ai_error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct UsageCell {
    pub text: String,
    pub level: u8,
    pub marker: String,
}

impl UsageCell {
    pub fn new(text: String, level: u8) -> Self { Self { text, level, marker: String::new() } }

    pub fn with_marker(mut self, m: &str) -> Self {
        self.marker = m.to_string();
        self
    }

    pub fn for_value(
        v: Option<i64>,
        alloc: i64,
        fmt: fn(i64) -> String,
        missing_is_problem: bool,
    ) -> Self {
        match v {
            None => UsageCell {
                text: "—".to_string(),
                level: if missing_is_problem { 6 } else { 0 },
                marker: String::new(),
            },
            Some(val) => UsageCell {
                text: fmt(val),
                level: incidence_level(val, alloc),
                marker: String::new(),
            },
        }
    }
}

// Map a value to a 0–5 heat level based on the share of node allocatable it represents,
// driving the red-shaded cell backgrounds in the usage table.
pub fn incidence_level(value: i64, alloc: i64) -> u8 {
    if alloc <= 0 || value <= 0 { return 0; }
    let pct = value.saturating_mul(1000) / alloc;
    if pct >= 300 { 5 }
    else if pct >= 200 { 4 }
    else if pct >= 120 { 3 }
    else if pct >= 60 { 2 }
    else if pct >= 20 { 1 }
    else { 0 }
}

#[derive(Debug, Clone)]
pub struct NodeRowData {
    pub system: bool,
    pub namespace: String,
    pub pod: String,
    pub container: String,
    pub cpu_req: UsageCell,
    pub cpu_lim: UsageCell,
    pub cpu_use: UsageCell,
    pub mem_req: UsageCell,
    pub mem_lim: UsageCell,
    pub mem_use: UsageCell,
    pub ready: String,
    pub ready_color: &'static str,
    pub restarts: i32,
    pub restarts_color: &'static str,
}

#[derive(Debug, Clone)]
pub struct NodeSection {
    pub name: String,
    pub allocatable_cpu: String,
    pub allocatable_mem: String,
    pub metrics_available: bool,
    pub user_count: usize,
    pub system_count: usize,
    pub user_cpu_req: String,
    pub user_cpu_lim: String,
    pub user_cpu_use: String,
    pub user_mem_req: String,
    pub user_mem_lim: String,
    pub user_mem_use: String,
    pub sys_cpu_req: String,
    pub sys_cpu_use: String,
    pub sys_mem_req: String,
    pub sys_mem_use: String,
    pub rows: Vec<NodeRowData>,
    pub ai_model: String,
    pub ai_content: String,
    pub ai_error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Report {
    pub title: String,
    pub context: String,
    pub namespace: String,
    pub generated_at: String,
    pub diagnostic: Option<DiagDoc>,
    pub nodes: Vec<NodeSection>,
}

// Compile the embedded Typst template with the report inputs and write the resulting PDF to `path`.
pub fn export_to_pdf(path: &Path, report: &Report) -> Result<(), String> {
    let inputs = build_inputs(report);
    let engine = TypstEngine::builder()
        .main_file(TEMPLATE)
        .search_fonts_with(
            TypstKitFontOptions::default()
                .include_system_fonts(true)
                .include_embedded_fonts(true),
        )
        .build();

    let warned = engine.compile_with_input::<Dict, typst::layout::PagedDocument>(inputs);
    let document = warned.output.map_err(|e| format!("typst compile: {:?}", e))?;
    let pdf = typst_pdf::pdf(&document, &Default::default())
        .map_err(|e| format!("typst pdf: {:?}", e))?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("mkdir: {}", e))?;
    }
    std::fs::write(path, pdf).map_err(|e| format!("write: {}", e))?;
    Ok(())
}

fn s(v: impl Into<String>) -> Value {
    Value::Str(Str::from(v.into()))
}

fn n(v: usize) -> Value {
    Value::Int(v as i64)
}

fn dict_from(pairs: &[(&str, Value)]) -> Dict {
    let mut d = Dict::new();
    for (k, v) in pairs {
        d.insert(Str::from(*k), v.clone());
    }
    d
}

fn build_ai_dict(model: &str, content: &str, error: &Option<String>) -> Dict {
    let blocks = render_ai_blocks(content);
    let blocks_val: Array = blocks
        .into_iter()
        .map(|b| {
            let d = dict_from(&[("kind", s(b.kind)), ("text", s(b.text)), ("lang", s(b.lang))]);
            Value::Dict(d)
        })
        .collect();
    dict_from(&[
        ("model", s(model.to_string())),
        ("error", s(error.clone().unwrap_or_default())),
        ("blocks", Value::Array(blocks_val)),
    ])
}

fn build_diag_dict(d: &DiagDoc) -> Dict {
    let counts = dict_from(&[
        ("total", n(d.steps.len())),
        ("ok", n(d.ok)),
        ("warn", n(d.warn)),
        ("err", n(d.err)),
        ("info", n(d.info)),
    ]);
    let steps: Array = d
        .steps
        .iter()
        .map(|st| {
            let lines: Array = st
                .lines
                .iter()
                .map(|l| {
                    let dl = dict_from(&[("color", s(l.color)), ("text", s(l.text.clone()))]);
                    Value::Dict(dl)
                })
                .collect();
            let dd = dict_from(&[
                ("status", s(st.status)),
                ("title", s(st.title.clone())),
                ("command", s(st.command.clone())),
                ("lines", Value::Array(lines)),
            ]);
            Value::Dict(dd)
        })
        .collect();
    dict_from(&[
        ("counts", Value::Dict(counts)),
        ("steps", Value::Array(steps)),
        ("ai", Value::Dict(build_ai_dict(&d.ai_model, &d.ai_content, &d.ai_error))),
    ])
}

fn build_usage_cell_dict(c: &UsageCell) -> Dict {
    dict_from(&[
        ("text", s(c.text.clone())),
        ("level", n(c.level as usize)),
        ("marker", s(c.marker.clone())),
    ])
}

fn build_node_dict(ns: &NodeSection) -> Dict {
    let rows: Array = ns
        .rows
        .iter()
        .map(|r| {
            let d = dict_from(&[
                ("system", Value::Bool(r.system)),
                ("namespace", s(r.namespace.clone())),
                ("pod", s(r.pod.clone())),
                ("container", s(r.container.clone())),
                ("cpu_req", Value::Dict(build_usage_cell_dict(&r.cpu_req))),
                ("cpu_lim", Value::Dict(build_usage_cell_dict(&r.cpu_lim))),
                ("cpu_use", Value::Dict(build_usage_cell_dict(&r.cpu_use))),
                ("mem_req", Value::Dict(build_usage_cell_dict(&r.mem_req))),
                ("mem_lim", Value::Dict(build_usage_cell_dict(&r.mem_lim))),
                ("mem_use", Value::Dict(build_usage_cell_dict(&r.mem_use))),
                ("ready", s(r.ready.clone())),
                ("ready_color", s(r.ready_color)),
                ("restarts", Value::Int(r.restarts as i64)),
                ("restarts_color", s(r.restarts_color)),
            ]);
            Value::Dict(d)
        })
        .collect();
    dict_from(&[
        ("name", s(ns.name.clone())),
        ("alloc_cpu", s(ns.allocatable_cpu.clone())),
        ("alloc_mem", s(ns.allocatable_mem.clone())),
        ("metrics_available", Value::Bool(ns.metrics_available)),
        ("user_count", n(ns.user_count)),
        ("system_count", n(ns.system_count)),
        ("user_cpu_req", s(ns.user_cpu_req.clone())),
        ("user_cpu_lim", s(ns.user_cpu_lim.clone())),
        ("user_cpu_use", s(ns.user_cpu_use.clone())),
        ("user_mem_req", s(ns.user_mem_req.clone())),
        ("user_mem_lim", s(ns.user_mem_lim.clone())),
        ("user_mem_use", s(ns.user_mem_use.clone())),
        ("sys_cpu_req", s(ns.sys_cpu_req.clone())),
        ("sys_cpu_use", s(ns.sys_cpu_use.clone())),
        ("sys_mem_req", s(ns.sys_mem_req.clone())),
        ("sys_mem_use", s(ns.sys_mem_use.clone())),
        ("rows", Value::Array(rows)),
        ("ai", Value::Dict(build_ai_dict(&ns.ai_model, &ns.ai_content, &ns.ai_error))),
    ])
}

fn font_array(stack: &[&str]) -> Value {
    let arr: Array = stack.iter().map(|f| s((*f).to_string())).collect();
    Value::Array(arr)
}

fn build_brand_dict() -> Dict {
    dict_from(&[
        ("red", s(BRAND_RED.to_string())),
        ("red_dark", s(BRAND_RED_DARK.to_string())),
        ("red_light_bg", s(BRAND_RED_LIGHT_BG.to_string())),
        ("red_border", s(BRAND_RED_BORDER.to_string())),
        ("text_dark", s(BRAND_TEXT_DARK.to_string())),
        ("font_sans", font_array(BRAND_FONT_SANS)),
        ("font_mono", font_array(BRAND_FONT_MONO)),
    ])
}

fn build_inputs(report: &Report) -> Dict {
    let nodes_arr: Array = report
        .nodes
        .iter()
        .map(|nd| Value::Dict(build_node_dict(nd)))
        .collect();
    let summary = dict_from(&[
        ("has_diagnostic", Value::Bool(report.diagnostic.is_some())),
        (
            "diag_total",
            n(report.diagnostic.as_ref().map(|d| d.steps.len()).unwrap_or(0)),
        ),
        ("node_count", n(report.nodes.len())),
    ]);
    let mut pairs = vec![
        ("title", s(report.title.clone())),
        ("context", s(report.context.clone())),
        ("namespace", s(report.namespace.clone())),
        ("generated_at", s(report.generated_at.clone())),
        ("summary", Value::Dict(summary)),
        ("has_diagnostic", Value::Bool(report.diagnostic.is_some())),
        ("nodes", Value::Array(nodes_arr)),
        ("brand", Value::Dict(build_brand_dict())),
    ];
    if let Some(d) = &report.diagnostic {
        pairs.push(("diagnostic", Value::Dict(build_diag_dict(d))));
    } else {
        pairs.push(("diagnostic", Value::Dict(Dict::new())));
    }
    let mut out = Dict::new();
    for (k, v) in pairs {
        out.insert(Str::from(k), v);
    }
    out
}

#[derive(Debug, Clone)]
struct AiBlock {
    kind: &'static str,
    text: String,
    lang: String,
}

// Parse the AI markdown into a sequence of typed blocks (headings, code fences, list items,
// paragraphs, spacers) that the template renders. Inline content is passed through
// `convert_inline_md` so it is safe to evaluate as Typst markup.
fn render_ai_blocks(content: &str) -> Vec<AiBlock> {
    let mut out: Vec<AiBlock> = Vec::new();
    let mut in_code: Option<String> = None;
    let mut code_buf = String::new();
    let mut paragraph = String::new();

    let flush_paragraph = |out: &mut Vec<AiBlock>, paragraph: &mut String| {
        let trimmed = paragraph.trim_end_matches('\n').to_string();
        if !trimmed.is_empty() {
            out.push(AiBlock {
                kind: "p",
                text: convert_inline_md(&trimmed),
                lang: String::new(),
            });
        }
        paragraph.clear();
    };

    for raw in content.lines() {
        if let Some(lang) = &in_code {
            if raw.trim_start().starts_with("```") {
                out.push(AiBlock {
                    kind: "code",
                    text: code_buf.trim_end_matches('\n').to_string(),
                    lang: lang.clone(),
                });
                code_buf.clear();
                in_code = None;
            } else {
                code_buf.push_str(raw);
                code_buf.push('\n');
            }
            continue;
        }

        let trimmed = raw.trim_start();
        if let Some(rest) = trimmed.strip_prefix("```") {
            flush_paragraph(&mut out, &mut paragraph);
            in_code = Some(rest.trim().to_string());
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("### ") {
            flush_paragraph(&mut out, &mut paragraph);
            out.push(AiBlock { kind: "h3", text: convert_inline_md(rest), lang: String::new() });
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("## ") {
            flush_paragraph(&mut out, &mut paragraph);
            out.push(AiBlock { kind: "h2", text: convert_inline_md(rest), lang: String::new() });
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("# ") {
            flush_paragraph(&mut out, &mut paragraph);
            out.push(AiBlock { kind: "h1", text: convert_inline_md(rest), lang: String::new() });
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("- ").or_else(|| trimmed.strip_prefix("* ")) {
            flush_paragraph(&mut out, &mut paragraph);
            out.push(AiBlock { kind: "list", text: convert_inline_md(rest), lang: String::new() });
            continue;
        }
        if trimmed.is_empty() {
            flush_paragraph(&mut out, &mut paragraph);
            out.push(AiBlock { kind: "spacer", text: String::new(), lang: String::new() });
            continue;
        }
        if !paragraph.is_empty() { paragraph.push(' '); }
        paragraph.push_str(trimmed);
    }
    if let Some(lang) = in_code {
        out.push(AiBlock {
            kind: "code",
            text: code_buf,
            lang,
        });
    }
    flush_paragraph(&mut out, &mut paragraph);
    out
}

// Translate inline markdown to Typst markup while neutralizing injection: characters with special
// meaning in Typst code are backslash-escaped, `**bold**` is kept and `*italic*` becomes `_italic_`.
// Text inside backticks is passed through verbatim (rendered as inline raw by the template).
fn convert_inline_md(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    let mut in_backtick = false;
    while i < chars.len() {
        let c = chars[i];
        if c == '`' {
            in_backtick = !in_backtick;
            out.push('`');
            i += 1;
            continue;
        }
        if in_backtick {
            out.push(c);
            i += 1;
            continue;
        }
        match c {
            '#' | '<' | '>' | '@' | '$' | '~' | '[' | ']' | '\\' => {
                out.push('\\');
                out.push(c);
                i += 1;
            }
            '*' if i + 1 < chars.len() && chars[i + 1] == '*' => {
                out.push('*');
                i += 2;
            }
            '*' => {
                out.push('_');
                i += 1;
            }
            _ => {
                out.push(c);
                i += 1;
            }
        }
    }
    out
}

// Target directory for exported reports: ~/Downloads, or /tmp when HOME is unset.
pub fn downloads_dir() -> PathBuf {
    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home).join("Downloads");
    }
    PathBuf::from("/tmp")
}

pub fn timestamped_filename(prefix: &str) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("{}-{}.pdf", prefix, now)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_diag() -> DiagDoc {
        DiagDoc {
            ok: 4, warn: 1, err: 1, info: 2,
            steps: vec![
                DiagStep {
                    status: "ok",
                    title: "API server /livez".to_string(),
                    command: "kubectl get --raw='/livez'".to_string(),
                    lines: vec![DiagLine { color: "ok", text: "réponse: ok".to_string() }],
                },
                DiagStep {
                    status: "warn",
                    title: "Pods kube-system".to_string(),
                    command: "kubectl -n kube-system get pods".to_string(),
                    lines: vec![
                        DiagLine { color: "warn", text: "12 pods, notReady=1, crashloop=0".to_string() },
                    ],
                },
            ],
            ai_model: "gpt-4o".to_string(),
            ai_content: "## Diagnostic\n\nLe cluster est globalement sain mais **3 pods** en CrashLoopBackOff.\n\n- erreur de configuration\n- image manquante\n\n```sh\nkubectl describe pod default/web-7cd5\n```\n".to_string(),
            ai_error: None,
        }
    }

    fn sample_node() -> NodeSection {
        let cell = |t: &str, lvl: u8| UsageCell::new(t.to_string(), lvl);
        NodeSection {
            name: "node-01.cluster.example".to_string(),
            allocatable_cpu: "8000m".to_string(),
            allocatable_mem: "32Gi".to_string(),
            metrics_available: true,
            user_count: 12, system_count: 4,
            user_cpu_req: "4500m".to_string(), user_cpu_lim: "8000m".to_string(), user_cpu_use: "2300m".to_string(),
            user_mem_req: "16Gi".to_string(), user_mem_lim: "24Gi".to_string(), user_mem_use: "11Gi".to_string(),
            sys_cpu_req: "200m".to_string(), sys_cpu_use: "80m".to_string(),
            sys_mem_req: "1Gi".to_string(), sys_mem_use: "650Mi".to_string(),
            rows: vec![
                NodeRowData {
                    system: false,
                    namespace: "default".to_string(),
                    pod: "web-7cd5".to_string(),
                    container: "app".to_string(),
                    cpu_req: cell("500m", 2),
                    cpu_lim: cell("2", 4).with_marker("≫"),
                    cpu_use: cell("2.1", 5).with_marker("▲"),
                    mem_req: cell("512Mi", 1),
                    mem_lim: cell("1Gi", 3),
                    mem_use: cell("980Mi", 3),
                    ready: "Y".to_string(),
                    ready_color: "ok",
                    restarts: 0,
                    restarts_color: "dim",
                },
                NodeRowData {
                    system: true,
                    namespace: "kube-system".to_string(),
                    pod: "kube-proxy-x5k2".to_string(),
                    container: "kube-proxy".to_string(),
                    cpu_req: cell("100m", 1),
                    cpu_lim: UsageCell::new("—".to_string(), 6),
                    cpu_use: cell("12m", 0),
                    mem_req: cell("128Mi", 0),
                    mem_lim: UsageCell::new("—".to_string(), 6),
                    mem_use: cell("48Mi", 0),
                    ready: "Y".to_string(),
                    ready_color: "ok",
                    restarts: 0,
                    restarts_color: "dim",
                },
            ],
            ai_model: "gpt-4o".to_string(),
            ai_content: "## Recommandations\n\n- réduire la limite CPU\n- ajuster les requests mémoire".to_string(),
            ai_error: None,
        }
    }

    #[test]
    fn smoke_export_produces_valid_pdf() {
        let report = Report {
            title: "Extraction complète".to_string(),
            context: "test-ctx".to_string(),
            namespace: "all".to_string(),
            generated_at: "2026-05-09 12:00".to_string(),
            diagnostic: Some(sample_diag()),
            nodes: vec![sample_node(), sample_node()],
        };
        let path = std::env::temp_dir().join("kdt_pdf_typst_test.pdf");
        export_to_pdf(&path, &report).expect("export");
        let bytes = std::fs::read(&path).expect("read back");
        assert!(bytes.starts_with(b"%PDF-"), "header");
        assert!(bytes.windows(5).any(|w| w == b"%%EOF"), "trailer");
    }
}
