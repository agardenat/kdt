// La vue Rancher : le couple *(identité Rancher `u-…`, identité réelle)*, sans ouvrir Rancher.
//
// Quatre mondes, comme dans le TUI, et ils n'ont rien en commun au-delà du cadre : les comptes, les
// accès (les trois kinds de binding ramenés à la même question), les projects, et les tokens
// précédés des réglages de TTL qui les gouvernent — dans cet ordre, parce que sur un cluster dont
// le défaut kubeconfig vaut 0 les réglages sont le titre et non une note de bas de page.
//
// Rien n'est jugé ici. La résolution d'un principal opaque, le rôle que Rancher pose sur tout
// compte, le ton d'un provider `local`, le token éternel, la portée vide qui vaut sur tous les
// clusters : tout arrive tout fait de `kdt::rancher`.
//
// Le cas qui décide de tout : zéro `User` sur un cluster qui sert les CRD n'est pas un annuaire
// vide, c'est un downstream — les identités sont en amont. Les écritures y sont refusées, et la
// barre le dit avant qu'on essaie.

import { useCallback, useEffect, useMemo, useState } from "react";
import * as api from "./api";
import { ApiError, NeedsAuth } from "./api";
import { CopyButton } from "./copy";
import { useDismiss } from "./dismiss";
import type { Lang, Strings } from "./i18n";
import { InspectPanel, PanelToggle, Splitter, type PanelTab } from "./panel";
import { ObjectActions } from "./objects";
import type {
  EventRecord,
  Hint,
  IssuedToken,
  RancherPayload,
  RanchBindingRow,
  RanchProjectRow,
  RanchSettingRow,
  RanchTokenRow,
  RanchUserRow,
} from "./types";

/** `RANCHER ID IDENTITY LOGIN PROVIDER GLOBAL ROLE GRP ACC TOK REFRESH STATE AGE`. */
const USER_COLUMNS =
  "minmax(110px,16ch) minmax(180px,26ch) minmax(90px,16ch) 104px minmax(140px,1fr)" +
  " 40px 40px 40px 64px 76px 48px";

/** `SCOPE TARGET SUBJECT TYPE PROVIDER ROLE AGE`. */
const BINDING_COLUMNS =
  "72px minmax(90px,16ch) minmax(180px,28ch) 56px 116px minmax(160px,1fr) 48px";

/** `PROJECT ID CLUSTER NS MEMBERS OWNERS QUOTA AGE`. */
const PROJECT_COLUMNS =
  "minmax(130px,20ch) 88px 96px 44px 68px minmax(160px,1fr) minmax(140px,26ch) 48px";

/** `TOKEN USER PROVIDER KIND SCOPE TTL STATE AGE`. */
const TOKEN_COLUMNS =
  "minmax(180px,32ch) minmax(160px,1fr) 116px 104px 96px 76px 76px 48px";

type World = "users" | "access" | "projects" | "tokens";
type Filter = "all" | "problems";
/** Le formulaire ouvert dans le menu de la barre. `null` = la liste des actions. */
type Form = null | { kind: "issue" } | { kind: "ttl" } | { kind: "revoke" } | { kind: "setting" };

export default function RancherView({
  lang,
  st,
  query,
  panelHeight,
  onPanelHeight,
  panelOpen,
  onPanelOpen,
  onNeedsAuth,
}: {
  lang: Lang;
  st: Strings;
  query: string;
  panelHeight: number;
  onPanelHeight: (h: number) => void;
  panelOpen: boolean;
  onPanelOpen: (open: boolean) => void;
  onNeedsAuth: (message: string) => void;
}) {
  const [payload, setPayload] = useState<RancherPayload | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loaded, setLoaded] = useState(false);
  const [world, setWorld] = useState<World>("users");
  const [filter, setFilter] = useState<Filter>("all");
  const [selected, setSelected] = useState<string | null>(null);
  const [tab, setTab] = useState<PanelTab>("detail");
  const [menuOpen, setMenuOpen] = useState(false);
  const [form, setForm] = useState<Form>(null);
  const [toast, setToast] = useState<{ tone: "ok" | "err"; text: string } | null>(null);
  const [busy, setBusy] = useState(false);
  // Le credential d'un token émis n'existe que là, le temps qu'on le copie. Il n'est écrit ni dans
  // l'état de la liste, ni dans un log, ni sur disque.
  const [issued, setIssued] = useState<IssuedToken | null>(null);

  const load = useCallback(async () => {
    try {
      setPayload(await api.rancherDirectory(lang));
      setError(null);
      setLoaded(true);
    } catch (e) {
      if (e instanceof NeedsAuth) onNeedsAuth(e.message);
      else if (e instanceof ApiError) setError(e.message);
      else setError(String(e));
      setLoaded(true);
    }
  }, [lang, onNeedsAuth]);

  useEffect(() => {
    void load();
    // Une minute, pas quelques secondes : sur un downstream la vue lit tout le RBAC projeté, ce qui
    // se compte en milliers de RoleBindings.
    const timer = window.setInterval(() => void load(), 60000);
    return () => window.clearInterval(timer);
  }, [load]);

  useEffect(() => {
    if (!toast) return;
    const timer = window.setTimeout(() => setToast(null), 8000);
    return () => window.clearTimeout(timer);
  }, [toast]);

  // `Échap` ferme le menu avant tout le reste, et un clic à côté aussi : c'est ce qui est ouvert
  // par-dessus. La ref va sur l'ancre — bouton **et** menu — sinon le bouton refermerait puis
  // rouvrirait dans le même geste. Le formulaire en cours part avec le menu : rouvrir sur une
  // saisie à moitié faite ferait agir sur un état qu'on ne relit pas.
  const closeMenu = useCallback(() => {
    setMenuOpen(false);
    setForm(null);
  }, []);
  const menuRef = useDismiss<HTMLDivElement>(menuOpen, closeMenu);

  const needle = query.trim().toLowerCase();
  const worse = (hints: Hint[]) => hints.some((h) => h.level !== "info");
  const keep = useCallback(
    (hints: Hint[], haystack: string[]) => {
      if (filter === "problems" && !worse(hints)) return false;
      if (!needle) return true;
      return haystack.join(" ").toLowerCase().includes(needle);
    },
    [filter, needle],
  );

  const users = useMemo(
    () =>
      (payload?.users ?? []).filter((u) =>
        // Le principal brut est dans le tamis : c'est ainsi qu'un GUID copié d'une ligne d'audit
        // retrouve son compte, et c'est la raison d'être de la vue.
        keep(u.hints, [u.id, u.identity, u.username, u.display_name, u.provider, u.principal,
          u.global_roles.join(" "), u.groups.join(" ")]),
      ),
    [payload, keep],
  );
  const bindings = useMemo(
    () =>
      (payload?.bindings ?? []).filter((b) =>
        keep(b.hints, [b.scope_kind, b.scope_label, b.subject_label, b.subject_id, b.provider,
          b.role, b.role_label]),
      ),
    [payload, keep],
  );
  const projects = useMemo(
    () =>
      (payload?.projects ?? []).filter((p) =>
        keep(p.hints, [p.id, p.display_name, p.cluster, p.namespaces.join(" "), p.owners.join(" ")]),
      ),
    [payload, keep],
  );
  const settings = useMemo(
    () =>
      (payload?.settings ?? []).filter((s) =>
        keep(s.hints, [s.name, s.effective, s.value_text, s.source_label]),
      ),
    [payload, keep],
  );
  const tokens = useMemo(
    () =>
      (payload?.tokens ?? []).filter((t) =>
        keep(t.hints, [t.name, t.user_id, t.user_label, t.provider, t.kind_label, t.cluster,
          t.description]),
      ),
    [payload, keep],
  );

  const selectedUser = users.find((u) => u.uid === selected) ?? null;
  const selectedBinding = bindings.find((b) => b.uid === selected) ?? null;
  const selectedProject = projects.find((p) => p.uid === selected) ?? null;
  const selectedSetting = settings.find((s) => s.uid === selected) ?? null;
  const selectedToken = tokens.find((t) => t.uid === selected) ?? null;
  const selectedRecord: EventRecord | null =
    selectedUser?.record ??
    selectedBinding?.record ??
    selectedProject?.record ??
    selectedSetting?.record ??
    selectedToken?.record ??
    null;

  const run = useCallback(
    async (request: Record<string, unknown>) => {
      setMenuOpen(false);
      setForm(null);
      setBusy(true);
      try {
        const { message, token } = await api.rancherWrite(request, lang);
        if (token) setIssued(token);
        else setToast({ tone: "ok", text: message });
        void load();
      } catch (e) {
        if (e instanceof NeedsAuth) onNeedsAuth(e.message);
        else setToast({ tone: "err", text: String((e as Error).message ?? e) });
      } finally {
        setBusy(false);
      }
    },
    [lang, load, onNeedsAuth],
  );

  const counts = payload?.counts;
  const writable = payload?.writable ?? false;
  // Pourquoi on ne peut pas écrire. « Downstream » n'est vrai que sur un cluster enregistré : sur un
  // cluster sans Rancher du tout, c'est le rôle lui-même qui l'explique, et servir la mauvaise
  // phrase enverrait chercher un serveur amont qui n'existe pas.
  const readOnlyReason =
    payload?.server.role === "downstream" ? st.ranchReadOnly : (payload?.server.role_label ?? "");
  const shownCount =
    world === "users"
      ? users.length
      : world === "access"
        ? bindings.length
        : world === "projects"
          ? projects.length
          : settings.length + tokens.length;

  // Sélectionner ne déplie pas le panneau : le pli est la décision de qui regarde, et le forcer à
  // chaque clic redécalait la table sous le curseur. Ce sont les commandes de la barre — celles qui
  // révèlent un contenu — qui l'ouvrent.
  const select = (uid: string) => {
    setSelected(uid);
    setTab("detail");
  };

  return (
    <>
            {/* Le panneau reste en place tant qu'il est déplié, sélection ou pas : le faire apparaître
          avec la sélection décalait la table de 300 px à chaque clic, et on perdait la ligne qu'on
          venait de viser. */}
      {panelOpen && (
        <>
          <InspectPanel
            record={selectedRecord}
            tab={tab}
            onTab={setTab}
            onClose={() => onPanelOpen(false)}
            height={panelHeight}
            lang={lang}
            st={st}
            onNeedsAuth={onNeedsAuth}
            onDeleted={() => {
              setSelected(null);
              void load();
            }}
            detail={{
              label: st.ranchDetail,
              node: selectedUser ? (
                <UserDetail user={selectedUser} st={st} />
              ) : selectedBinding ? (
                <BindingDetail binding={selectedBinding} st={st} />
              ) : selectedProject ? (
                <ProjectDetail project={selectedProject} st={st} />
              ) : selectedSetting ? (
                <SettingDetail setting={selectedSetting} st={st} />
              ) : selectedToken ? (
                <TokenDetail token={selectedToken} st={st} />
              ) : null,
            }}
          />
          <Splitter height={panelHeight} onHeight={onPanelHeight} lang={lang} />
        </>
      )}

      <div className="worlds" role="tablist">
        {(
          [
            ["users", st.ranchUsers, counts?.users],
            ["access", st.ranchAccess, counts?.bindings],
            ["projects", st.ranchProjects, counts?.projects],
            ["tokens", st.ranchTokens, counts?.tokens],
          ] as const
        ).map(([id, label, n]) => (
          <button
            key={id}
            role="tab"
            aria-selected={world === id}
            onClick={() => {
              setWorld(id);
              setSelected(null);
            }}
          >
            {label}
            {n !== undefined && <span className="count">{n}</span>}
          </button>
        ))}

        <div className="segmented" role="group">
          {(["all", "problems"] as const).map((f) => (
            <button key={f} aria-pressed={filter === f} onClick={() => setFilter(f)}>
              {f === "all" ? st.filterAll : st.filterProblems}
            </button>
          ))}
        </div>

        {counts && (
          <div className="tally">
            {world === "users" && (
              <>
                <span className="info" title={st.ranchProvider}>
                  ⇄{counts.external}
                </span>
                {counts.admins > 0 && (
                  <span className="warn" title={st.ranchGlobalRoles}>
                    ★{counts.admins}
                  </span>
                )}
              </>
            )}
            {world === "projects" && counts.orphan_namespaces > 0 && (
              <span className="warn" title={st.ranchOrphanNs}>
                ⚠{counts.orphan_namespaces}
              </span>
            )}
            {world === "tokens" && counts.expired_tokens > 0 && (
              <span className="warn" title={st.ranchTokens}>
                ⌛{counts.expired_tokens}
              </span>
            )}
          </div>
        )}

        <div className="right">
          {busy && <span>{st.objWorking}</span>}
          {toast && <span className={toast.tone === "err" ? "err" : "ok"}>{toast.text}</span>}
          <div className="menu-anchor" ref={menuRef}>
            <button
              className="panel-toggle action"
              // Un downstream n'a que des répliques : le menu ne s'ouvre pas, et l'infobulle dit
              // pourquoi plutôt que de laisser découvrir le refus après la confirmation.
              disabled={!writable}
              title={writable ? undefined : readOnlyReason}
              aria-expanded={menuOpen}
              onClick={() => {
                setMenuOpen((v) => !v);
                setForm(null);
              }}
            >
              {st.ranchActions} ▾
            </button>
            {menuOpen && writable && (
              <RancherMenu
                st={st}
                user={selectedUser}
                token={selectedToken}
                setting={selectedSetting}
                hashing={payload?.token_hashing ?? false}
                form={form}
                onForm={setForm}
                onRun={run}
              />
            )}
          </div>
          <ObjectActions
            record={selectedRecord}
            lang={lang}
            st={st}
            onOpen={(t) => {
              setTab(t);
              onPanelOpen(true);
            }}
            onNeedsAuth={onNeedsAuth}
          />
          <PanelToggle open={panelOpen} onOpen={onPanelOpen} lang={lang} />
        </div>
      </div>

      {issued && <IssuedPanel token={issued} st={st} onClose={() => setIssued(null)} />}

      <div className="body">
        {!loaded ? (
          <div className="center" />
        ) : shownCount === 0 ? (
          <div className="center">
            <div className="box">
              <h2>{st.ranchEmpty}</h2>
              {error && <p className="err">{error}</p>}
              {payload?.error && <p className="err">{payload.error}</p>}
              {/* Ce que ce cluster est pour Rancher : c'est la réponse à une liste vide — « les
                  comptes sont ailleurs » plutôt que « il n'y en a pas ». */}
              {payload && <p>{payload.server.role_label}</p>}
            </div>
          </div>
        ) : world === "users" ? (
          <UserTable rows={users} selected={selected} onSelect={select} />
        ) : world === "access" ? (
          <BindingTable rows={bindings} selected={selected} onSelect={select} />
        ) : world === "projects" ? (
          <ProjectTable rows={projects} selected={selected} onSelect={select} />
        ) : (
          <TokenTable
            settings={settings}
            tokens={tokens}
            selected={selected}
            st={st}
            onSelect={select}
          />
        )}
      </div>

      <div className="statusbar">
        <span>
          {shownCount} {st.rows}
        </span>
        {payload && <span>{payload.server.role_label}</span>}
        {payload && payload.server.providers.length > 0 && (
          <span>
            {st.ranchAuth}:{" "}
            {payload.server.providers
              .map((p) => (p.access_mode ? `${p.name} (${p.access_mode})` : p.name))
              .join(", ")}
          </span>
        )}
        {/* `token-hashing` change ce qu'une émission promet : dit avant, pas après. */}
        {payload?.token_hashing && world === "tokens" && (
          <span className="warn">{st.ranchIssueHashing}</span>
        )}
        {!writable && readOnlyReason && <span className="warn">{readOnlyReason}</span>}
        <span style={{ marginLeft: "auto" }}>{st.ranchScopeless}</span>
      </div>
    </>
  );
}

function UserTable({
  rows,
  selected,
  onSelect,
}: {
  rows: RanchUserRow[];
  selected: string | null;
  onSelect: (uid: string) => void;
}) {
  return (
    <div className="tbl">
      <div className="thead">
        <div className="tr" style={{ gridTemplateColumns: USER_COLUMNS }}>
          <div className="cell">RANCHER ID</div>
          <div className="cell">IDENTITY</div>
          <div className="cell">LOGIN</div>
          <div className="cell">PROVIDER</div>
          <div className="cell">GLOBAL ROLE</div>
          <div className="cell num">GRP</div>
          <div className="cell num">ACC</div>
          <div className="cell num">TOK</div>
          <div className="cell">REFRESH</div>
          <div className="cell">STATE</div>
          <div className="cell num">AGE</div>
        </div>
      </div>
      <div className="tbody">
        {rows.map((u) => (
          <Row key={u.uid} uid={u.uid} tone={u.record.tone} selected={selected} columns={USER_COLUMNS} onSelect={onSelect}>
            <div className="cell mono dim">{u.id}</div>
            {/* Un principal opaque — un GUID — est montré tel quel plutôt que déguisé en nom. */}
            <div className={`cell id ${u.identity_opaque ? "dim" : ""}`}>{u.identity_cell}</div>
            <div className="cell mono">{u.username}</div>
            <div className={`cell ${u.provider_tone}`}>{u.provider}</div>
            <div className={`cell ${u.is_admin ? "" : "dim"}`}>
              {u.global_roles.join(", ")}
              {u.is_admin && <span className="badge-admin">admin</span>}
            </div>
            <div className="cell num">{u.groups.length || "·"}</div>
            <div className="cell num">{u.binding_count || "·"}</div>
            <div className="cell num">{u.token_count || "·"}</div>
            <div className="cell dim">{u.refresh_label}</div>
            <div className={`cell ${u.state_tone}`}>{u.state_label}</div>
            <div className="cell num dim">{u.age}</div>
          </Row>
        ))}
      </div>
    </div>
  );
}

function BindingTable({
  rows,
  selected,
  onSelect,
}: {
  rows: RanchBindingRow[];
  selected: string | null;
  onSelect: (uid: string) => void;
}) {
  return (
    <div className="tbl">
      <div className="thead">
        <div className="tr" style={{ gridTemplateColumns: BINDING_COLUMNS }}>
          <div className="cell">SCOPE</div>
          <div className="cell">TARGET</div>
          <div className="cell">SUBJECT</div>
          <div className="cell">TYPE</div>
          <div className="cell">PROVIDER</div>
          <div className="cell">ROLE</div>
          <div className="cell num">AGE</div>
        </div>
      </div>
      <div className="tbody">
        {rows.map((b) => (
          <Row
            key={b.uid}
            uid={b.uid}
            tone={b.record.tone}
            selected={selected}
            columns={BINDING_COLUMNS}
            onSelect={onSelect}
            // Le rôle que Rancher pose sur tout compte se lit comme de l'arrière-plan : il est là
            // parce qu'il existe, pas parce que quelqu'un l'a décidé.
            className={b.automatic ? "automatic" : undefined}
          >
            <div className="cell mono">{b.scope_kind}</div>
            <div className="cell mono">{b.scope_label}</div>
            <div className="cell id">
              {b.subject_label}
              {!b.authoritative && <span className="badge-projected">projeté</span>}
            </div>
            <div className="cell dim">{b.subject_kind_label}</div>
            <div className={`cell ${b.provider_tone}`}>{b.provider}</div>
            <div className={`cell ${b.role_tone}`}>{b.role_label}</div>
            <div className="cell num dim">{b.age}</div>
          </Row>
        ))}
      </div>
    </div>
  );
}

function ProjectTable({
  rows,
  selected,
  onSelect,
}: {
  rows: RanchProjectRow[];
  selected: string | null;
  onSelect: (uid: string) => void;
}) {
  return (
    <div className="tbl">
      <div className="thead">
        <div className="tr" style={{ gridTemplateColumns: PROJECT_COLUMNS }}>
          <div className="cell">PROJECT</div>
          <div className="cell">ID</div>
          <div className="cell">CLUSTER</div>
          <div className="cell num">NS</div>
          <div className="cell num">MEMBERS</div>
          <div className="cell">OWNERS</div>
          <div className="cell">QUOTA</div>
          <div className="cell num">AGE</div>
        </div>
      </div>
      <div className="tbody">
        {rows.map((p) => (
          <Row key={p.uid} uid={p.uid} tone={p.record.tone} selected={selected} columns={PROJECT_COLUMNS} onSelect={onSelect}>
            <div className="cell id">{p.display_name}</div>
            <div className="cell mono dim">{p.id}</div>
            <div className="cell mono dim">{p.cluster}</div>
            <div className="cell num">{p.namespaces.length || "·"}</div>
            <div className="cell num">{p.members || "·"}</div>
            <div className="cell">{p.owners.join(", ")}</div>
            <div className="cell dim">{p.quota}</div>
            <div className="cell num dim">{p.age}</div>
          </Row>
        ))}
      </div>
    </div>
  );
}

/**
 * Les tokens, précédés des réglages qui décident de leur durée de vie.
 *
 * Les deux sortes de lignes partagent la table parce qu'elles répondent à la même question : combien
 * de temps un credential vit ici. Un réglage ne remplit que quatre colonnes sur huit, et c'est
 * précisément ce qui le distingue à l'œil d'un token.
 */
function TokenTable({
  settings,
  tokens,
  selected,
  st,
  onSelect,
}: {
  settings: RanchSettingRow[];
  tokens: RanchTokenRow[];
  selected: string | null;
  st: Strings;
  onSelect: (uid: string) => void;
}) {
  return (
    <div className="tbl">
      <div className="thead">
        <div className="tr" style={{ gridTemplateColumns: TOKEN_COLUMNS }}>
          <div className="cell">TOKEN</div>
          <div className="cell">USER</div>
          <div className="cell">PROVIDER</div>
          <div className="cell">KIND</div>
          <div className="cell">SCOPE</div>
          <div className="cell">TTL</div>
          <div className="cell">STATE</div>
          <div className="cell num">AGE</div>
        </div>
      </div>
      <div className="tbody">
        {settings.map((s) => (
          <Row key={s.uid} uid={s.uid} tone={s.record.tone} selected={selected} columns={TOKEN_COLUMNS} onSelect={onSelect}>
            {/* Un réglage qu'un opérateur a changé mérite de se voir comme changé : le défaut est
                de l'arrière-plan, une valeur délibérée non. */}
            <div className={`cell ${s.is_default ? "dim" : "id"}`}>{s.name}</div>
            <div className="cell" />
            <div className="cell" />
            <div className="cell info">setting</div>
            <div className="cell dim">{s.ceiling ? "ceiling" : ""}</div>
            <div className={`cell ${s.value_tone}`}>{s.value_text}</div>
            <div className={`cell ${s.is_default ? "dim" : "info"}`}>{s.source_label}</div>
            <div className="cell num dim">{s.age}</div>
          </Row>
        ))}
        {tokens.map((t) => (
          <Row key={t.uid} uid={t.uid} tone={t.record.tone} selected={selected} columns={TOKEN_COLUMNS} onSelect={onSelect}>
            <div className="cell mono">{t.name}</div>
            <div className="cell id" title={t.user_id}>
              {t.owner_label}
            </div>
            <div className={`cell ${t.provider_tone}`}>{t.provider}</div>
            <div className="cell dim" title={t.derived ? undefined : st.ranchRevokeSession}>
              {t.kind_label}
            </div>
            <div className={`cell ${t.scope_tone}`}>{t.scope_label}</div>
            <div className={`cell ${t.ttl_tone}`}>{t.ttl_label}</div>
            <div className={`cell ${t.state_tone}`}>{t.state_label}</div>
            <div className="cell num dim">{t.age}</div>
          </Row>
        ))}
      </div>
    </div>
  );
}

function Row({
  uid,
  tone,
  selected,
  columns,
  className,
  onSelect,
  children,
}: {
  uid: string;
  tone: string;
  selected: string | null;
  columns: string;
  className?: string;
  onSelect: (uid: string) => void;
  children: React.ReactNode;
}) {
  return (
    <div
      className={`tr sev-${tone}${className ? ` ${className}` : ""}`}
      style={{ gridTemplateColumns: columns }}
      aria-selected={selected === uid}
      tabIndex={0}
      onClick={() => onSelect(uid)}
      onKeyDown={(e) => {
        if (e.key === "Enter") onSelect(uid);
      }}
    >
      {children}
    </div>
  );
}

function UserDetail({ user, st }: { user: RanchUserRow; st: Strings }) {
  return (
    <div className="detail">
      {/* Les deux identités côte à côte : c'est tout l'intérêt de la vue. */}
      <Line label="rancher id" value={user.id} mono />
      <Line
        label={st.ranchIdentity}
        value={user.identity || "—"}
        tone={user.identity ? undefined : "dim"}
      />
      {user.display_name && user.display_name !== user.identity && (
        <Line label="display name" value={user.display_name} />
      )}
      {user.username && <Line label={st.ranchLogin} value={user.username} />}
      <Line label={st.ranchProvider} value={user.provider} tone={user.provider_tone} />
      {/* Le principal brut, pour qu'un GUID copié d'un log se retrouve ici. */}
      {user.principal && (
        <div className="keys-row">
          <div className="k-col">
            <span className="k">{st.ranchPrincipal}</span>
            <CopyButton text={user.principal} label={st.secCopy} done={st.secCopied} />
          </div>
          <span className="v mono">{user.principal}</span>
        </div>
      )}
      <Line label="state" value={user.state_label} tone={user.state_tone} />
      {user.global_roles.length > 0 && (
        <Line label={st.ranchGlobalRoles} value={user.global_roles.join(", ")} />
      )}
      <Line label="access" value={String(user.binding_count)} />
      <Line label="tokens" value={String(user.token_count)} />
      {user.last_refresh && <Line label="refresh" value={user.refresh_label} />}
      <Line label="age" value={user.age} />
      {user.groups.length > 0 && (
        <>
          <div className="sect">
            {st.ranchGroups} ({user.groups.length})
          </div>
          {user.groups.map((g) => (
            <div className="keys-row" key={g}>
              <div className="k-col">
                <span className="k" />
              </div>
              <span className="v mono">{g}</span>
            </div>
          ))}
        </>
      )}
      <Hints hints={user.hints} st={st} />
    </div>
  );
}

function BindingDetail({ binding, st }: { binding: RanchBindingRow; st: Strings }) {
  return (
    <div className="detail">
      <Line label="scope" value={`${binding.scope_kind} · ${binding.scope_label}`} />
      <Line label="subject" value={binding.subject_label} />
      {binding.subject_id !== binding.subject_label && (
        <Line label={st.ranchPrincipal} value={binding.subject_id} mono />
      )}
      <Line label={st.ranchProvider} value={binding.provider} tone={binding.provider_tone} />
      <Line
        label="role"
        value={
          binding.role === binding.role_label
            ? binding.role
            : `${binding.role_label} (${binding.role})`
        }
        tone={binding.role_tone}
      />
      <Line
        label="binding"
        value={
          binding.namespace
            ? `${binding.kind} ${binding.namespace}/${binding.name}`
            : `${binding.kind} ${binding.name}`
        }
        mono
      />
      <Line label="age" value={binding.age} />
      <Hints hints={binding.hints} st={st} />
    </div>
  );
}

function ProjectDetail({ project, st }: { project: RanchProjectRow; st: Strings }) {
  return (
    <div className="detail">
      <Line label="project" value={project.id} mono />
      <Line label="cluster" value={project.cluster} />
      <Line label="members" value={String(project.members)} />
      {project.owners.length > 0 && (
        <Line label={st.ranchOwners} value={project.owners.join(", ")} />
      )}
      {project.quota && <Line label="quota" value={project.quota} />}
      {project.creator && <Line label="creator" value={project.creator} />}
      {project.age && <Line label="age" value={project.age} />}
      {project.namespaces.length > 0 && (
        <>
          <div className="sect">
            {st.ranchNamespaces} ({project.namespaces.length})
          </div>
          {project.namespaces.map((ns) => (
            <div className="keys-row" key={ns}>
              <div className="k-col">
                <span className="k" />
              </div>
              <span className="v mono">{ns}</span>
            </div>
          ))}
        </>
      )}
      {/* Un project reconstruit depuis les annotations d'un downstream ne désigne aucun objet de
          ce cluster : les gestes génériques répondront « aucun objet ». */}
      {!project.local_object && <p className="guard info">{st.ranchNotAuthoritative}</p>}
      <Hints hints={project.hints} st={st} />
    </div>
  );
}

function SettingDetail({ setting, st }: { setting: RanchSettingRow; st: Strings }) {
  return (
    <div className="detail">
      <Line label="value" value={setting.value_text} tone={setting.value_tone} />
      {/* Le défaut livré à côté de la valeur en vigueur : « quelqu'un a changé ça, et c'était ça »
          est toute la question qu'on pose d'un réglage. */}
      <Line label="default" value={setting.default_text} />
      <Line label="origin" value={setting.source_label} />
      {setting.ceiling && <Line label="scope" value={st.ranchSetSettingHelp} />}
      <Line label="age" value={setting.age} />
      <Hints hints={setting.hints} st={st} />
    </div>
  );
}

function TokenDetail({ token, st }: { token: RanchTokenRow; st: Strings }) {
  return (
    <div className="detail">
      <Line
        label="user"
        value={token.user_label ? `${token.user_label} (${token.user_id})` : token.user_id}
      />
      <Line label={st.ranchProvider} value={token.provider} tone={token.provider_tone} />
      <Line label="kind" value={token.kind_label} />
      {/* `isDerived` est le seul discriminant qui reste : une session de connexion n'est pas une
          clé d'API, et la révoquer déconnecte la personne. */}
      {!token.derived && <p className="guard warn">{st.ranchRevokeSession}</p>}
      {token.description && <Line label="description" value={token.description} />}
      <Line label="ttl" value={token.ttl_label} tone={token.ttl_tone} />
      {token.expires_at && <Line label="expires" value={token.expires_at} />}
      <Line label="scope" value={token.scope_label} tone={token.scope_tone} />
      <Line label="age" value={token.age} />
      <Hints hints={token.hints} st={st} />
    </div>
  );
}

function Line({
  label,
  value,
  mono,
  tone,
}: {
  label: string;
  value: string;
  mono?: boolean;
  tone?: string;
}) {
  return (
    <div className="keys-row">
      <div className="k-col">
        <span className="k">{label}</span>
      </div>
      <span className={`v ${mono ? "mono" : ""} ${tone ?? ""}`}>{value}</span>
    </div>
  );
}

function Hints({ hints, st }: { hints: Hint[]; st: Strings }) {
  if (hints.length === 0) return null;
  return (
    <>
      <div className="sect">{st.sectionHints}</div>
      {hints.map((h) => (
        <p key={h.text} className={`guard ${h.level}`}>
          <span className="gl">{h.level === "danger" ? "✗" : h.level === "warn" ? "▲" : "·"}</span>{" "}
          {h.text}
        </p>
      ))}
    </>
  );
}

/**
 * Le credential émis, montré **une seule fois**.
 *
 * `bearer` est ce qu'un client envoie en `Authorization: Bearer …` et ce qu'un kubeconfig met dans
 * son champ `token`. Il n'existe que dans cette réponse : fermer ce panneau le perd, et c'est ce
 * qu'on veut.
 */
function IssuedPanel({
  token,
  st,
  onClose,
}: {
  token: IssuedToken;
  st: Strings;
  onClose: () => void;
}) {
  return (
    <div className="once">
      <p className="warn">
        {st.ranchTokenOnce} — {token.user_label || token.user_id}
      </p>
      <div className="keys-row">
        <div className="k-col">
          <span className="k">token</span>
          <CopyButton text={token.bearer} label={st.secCopy} done={st.secCopied} />
        </div>
        <span className="v mono">{token.bearer}</span>
      </div>
      <div className="menu-buttons">
        <button className="cta" onClick={onClose}>
          {st.ranchTokenClose}
        </button>
      </div>
    </div>
  );
}

/**
 * Le menu de la barre : les quatre écritures que kdt s'autorise.
 *
 * Tout le reste d'une identité — créer un compte, accorder un rôle — reste dans Rancher, où vivent
 * la piste d'audit et l'approbation. Le menu ne montre donc que ce qui porte sur la ligne lue.
 */
function RancherMenu({
  st,
  user,
  token,
  setting,
  hashing,
  form,
  onForm,
  onRun,
}: {
  st: Strings;
  user: RanchUserRow | null;
  token: RanchTokenRow | null;
  setting: RanchSettingRow | null;
  hashing: boolean;
  form: Form;
  onForm: (f: Form) => void;
  onRun: (request: Record<string, unknown>) => void;
}) {
  const [ttl, setTtl] = useState("0");
  const [value, setValue] = useState("");

  const target = user?.label ?? token?.name ?? setting?.name ?? null;

  return (
    <div className="pop menu" onClick={(e) => e.stopPropagation()}>
      <div className="pop-hd">
        <span>{st.ranchActions}</span>
      </div>
      {target && <div className="menu-target mono">{target}</div>}

      {form === null ? (
        <div className="menu-list">
          {user && (
            <MenuItem
              label={st.ranchIssue}
              desc={hashing ? `${st.ranchIssueHelp} ${st.ranchIssueHashing}` : st.ranchIssueHelp}
              onClick={() => {
                setTtl("0");
                onForm({ kind: "issue" });
              }}
            />
          )}
          {token && (
            <>
              <MenuItem
                label={st.ranchSetTtl}
                desc={`${st.ranchSetTtlHelp} (${token.ttl_label})`}
                onClick={() => {
                  setTtl(String(Math.round(token.ttl_ms / 60000)));
                  onForm({ kind: "ttl" });
                }}
              />
              <MenuItem
                label={st.ranchRevoke}
                // Révoquer une session de connexion est une déconnexion, pas la suppression d'une
                // clé : la description dit laquelle des deux avant la confirmation.
                desc={
                  token.derived
                    ? st.ranchRevokeHelp
                    : `${st.ranchRevokeHelp} ${st.ranchRevokeSession}`
                }
                onClick={() => onForm({ kind: "revoke" })}
              />
            </>
          )}
          {setting && (
            <MenuItem
              label={st.ranchSetSetting}
              desc={`${st.ranchSetSettingHelp} (${setting.value_text})`}
              onClick={() => {
                setValue(setting.effective);
                onForm({ kind: "setting" });
              }}
            />
          )}
          {!user && !token && !setting && <p className="menu-note">{st.ranchSelectRow}</p>}
        </div>
      ) : (
        <div className="menu-confirm">
          {form.kind === "issue" && user && (
            <>
              <p>{st.ranchIssueHelp}</p>
              {hashing && <p className="warn">{st.ranchIssueHashing}</p>}
              <div className="form-row">
                <label htmlFor="ranch-ttl">{st.ranchIssueTtl}</label>
                <input id="ranch-ttl" value={ttl} onChange={(e) => setTtl(e.target.value)} />
              </div>
              <Buttons
                st={st}
                disabled={!Number.isFinite(Number(ttl))}
                onCancel={() => onForm(null)}
                onConfirm={() =>
                  onRun({ action: "issue_token", user_id: user.id, ttl_minutes: Number(ttl) })
                }
              />
            </>
          )}

          {form.kind === "ttl" && token && (
            <>
              <p>{st.ranchSetTtlHelp}</p>
              <div className="form-row">
                <label htmlFor="ranch-ttl2">{st.ranchIssueTtl}</label>
                <input id="ranch-ttl2" value={ttl} onChange={(e) => setTtl(e.target.value)} />
              </div>
              <Buttons
                st={st}
                disabled={!Number.isFinite(Number(ttl))}
                onCancel={() => onForm(null)}
                onConfirm={() =>
                  onRun({ action: "set_token_ttl", name: token.name, ttl_minutes: Number(ttl) })
                }
              />
            </>
          )}

          {form.kind === "revoke" && token && (
            <>
              <p>{st.ranchRevokeHelp}</p>
              {!token.derived && <p className="warn">{st.ranchRevokeSession}</p>}
              <Buttons
                st={st}
                confirmLabel={st.ranchRevoke}
                danger
                onCancel={() => onForm(null)}
                onConfirm={() => onRun({ action: "revoke_token", name: token.name })}
              />
            </>
          )}

          {form.kind === "setting" && setting && (
            <>
              <p>{st.ranchSetSettingHelp}</p>
              <div className="form-row">
                <label htmlFor="ranch-setting">{setting.name}</label>
                <input
                  id="ranch-setting"
                  value={value}
                  onChange={(e) => setValue(e.target.value)}
                />
              </div>
              <Buttons
                st={st}
                onCancel={() => onForm(null)}
                onConfirm={() => onRun({ action: "set_setting", name: setting.name, value })}
              />
            </>
          )}
        </div>
      )}
    </div>
  );
}

function MenuItem({
  label,
  desc,
  onClick,
}: {
  label: string;
  desc: string;
  onClick: () => void;
}) {
  return (
    <button className="menu-item" onClick={onClick}>
      <span className="lbl">{label}</span>
      <span className="desc">{desc}</span>
    </button>
  );
}

/** La sortie par défaut est celle qui n'écrit rien : c'est elle qui a le focus. */
function Buttons({
  st,
  confirmLabel,
  danger,
  disabled,
  onCancel,
  onConfirm,
}: {
  st: Strings;
  confirmLabel?: string;
  danger?: boolean;
  disabled?: boolean;
  onCancel: () => void;
  onConfirm: () => void;
}) {
  return (
    <div className="menu-buttons">
      <button autoFocus onClick={onCancel}>
        {st.ranchCancel}
      </button>
      <button className={danger ? "cta danger" : "cta"} disabled={disabled} onClick={onConfirm}>
        {confirmLabel ?? st.ranchApply}
      </button>
    </div>
  );
}
