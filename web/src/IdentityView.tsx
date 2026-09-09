// La vue kdt-identity : les comptes locaux que ce cluster écrit, et ce qu'ils peuvent atteindre.
//
// Kubernetes n'a ni `User` ni `Group` : kdt-identity comble le trou avec deux CRD cluster-scoped et
// un controller. La vue est le côté exploitation — qui existe, qui est dans quoi, et surtout qui
// est *connecté*, parce que c'est la seule chose sur laquelle une révocation mord.
//
// Rien n'est jugé ici. La phase — `Locked` compris, qui est le verdict propre à kdt et que le
// controller n'écrit jamais —, le ton d'une invitation périmée, celui de la colonne des sessions,
// et le constat qu'un groupe ne donne aucun droit arrivent tout faits de `kdt::identity`. Ce qui
// reste au navigateur est ce qui le regarde : quel monde on affiche, quelle ligne on lit, et quel
// formulaire est ouvert.
//
// Deux silences qui ne sont pas des zéros, et que la vue doit rendre distinctement : un Secret de
// sessions illisible donne `?` et non `—`, et un compte sans session donne `—` et non `0`.

import { useCallback, useEffect, useMemo, useState } from "react";
import * as api from "./api";
import { ApiError, NeedsAuth } from "./api";
import { CopyButton } from "./copy";
import { useDismiss } from "./dismiss";
import type { Lang, Strings } from "./i18n";
import { ToastLine, useToastTimeout, type Toast } from "./toast";
import { InspectPanel, PanelToggle, Splitter, type PanelTab } from "./panel";
import { ObjectActions } from "./objects";
import type {
  EventRecord,
  Hint,
  IdentDelivery,
  IdentGroupRow,
  IdentDirectory,
  IdentInvite,
  IdentSource,
  IdentUserRow,
  IdentityPayload,
} from "./types";

/** `NAME EMAIL PHASE GROUPS INVITE SESS AGE` — les colonnes du TUI, dans le même ordre. */
const USER_COLUMNS =
  "minmax(140px,20ch) minmax(160px,24ch) 84px minmax(160px,1fr) 84px 52px 52px";

/**
 * Les mêmes, plus SRC avant l'âge.
 *
 * La colonne ne se paie que là où un annuaire est en jeu — le serveur tranche, avec la même règle
 * que le TUI. Ailleurs ce serait une colonne de tirets prise sur celles qui distinguent.
 */
const USER_COLUMNS_SOURCE =
  "minmax(140px,20ch) minmax(160px,24ch) 84px minmax(160px,1fr) 84px 52px 56px 52px";

/** `NAME MEM UNKNOWN RIGHTS DESCRIPTION AGE`. */
const GROUP_COLUMNS =
  "minmax(140px,20ch) 44px minmax(120px,20ch) 64px minmax(200px,1fr) 52px";

const GROUP_COLUMNS_SOURCE =
  "minmax(140px,20ch) 44px minmax(120px,20ch) 64px 56px minmax(200px,1fr) 52px";

type World = "users" | "groups";
type Filter = "all" | "problems";
/** Le formulaire ouvert dans le menu de la barre. `null` = la liste des actions. */
type Form =
  | null
  | { kind: "invite" }
  | { kind: "revoke" }
  | { kind: "disabled"; next: boolean }
  | { kind: "add-member" }
  | { kind: "remove-member" }
  | { kind: "create-user" }
  | { kind: "create-group" };

export default function IdentityView({
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
  const [payload, setPayload] = useState<IdentityPayload | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loaded, setLoaded] = useState(false);
  const [world, setWorld] = useState<World>("users");
  const [filter, setFilter] = useState<Filter>("all");
  const [selected, setSelected] = useState<string | null>(null);
  const [tab, setTab] = useState<PanelTab>("detail");
  const [menuOpen, setMenuOpen] = useState(false);
  const [form, setForm] = useState<Form>(null);
  const [toast, setToast] = useState<Toast>(null);
  const [busy, setBusy] = useState(false);
  // Une invitation n'existe qu'une fois : elle ne va ni dans l'état de la liste, ni dans un log.
  // Elle vit ici, le temps qu'on la copie, et le bouton de fermeture la jette.
  const [invite, setInvite] = useState<IdentInvite | null>(null);
  // Une création vise une ligne qui n'existe pas encore : son uid non plus, donc l'atterrissage se
  // retient par le **nom**, comme `ident_pending` dans le TUI.
  const [pending, setPending] = useState<{ world: World; name: string } | null>(null);

  const load = useCallback(async () => {
    try {
      setPayload(await api.identityDirectory(lang));
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
    // Un annuaire ne bouge pas à la seconde, et la lecture coûte deux Secrets par compte.
    const timer = window.setInterval(() => void load(), 30000);
    return () => window.clearInterval(timer);
  }, [load]);

  useToastTimeout(toast, setToast);

  // `Échap` ferme le menu avant tout le reste, et un clic à côté aussi : c'est ce qui est ouvert
  // par-dessus. La ref va sur l'ancre — bouton **et** menu — sinon le bouton refermerait puis
  // rouvrirait dans le même geste. Le formulaire en cours part avec le menu : rouvrir sur une
  // saisie à moitié faite ferait agir sur un état qu'on ne relit pas.
  const closeMenu = useCallback(() => {
    setMenuOpen(false);
    setForm(null);
  }, []);
  const menuRef = useDismiss<HTMLDivElement>(menuOpen, closeMenu);

  const users = payload?.users ?? [];
  const groups = payload?.groups ?? [];

  // L'atterrissage d'une création : la vue bascule sur le monde de l'objet créé et se pose dessus
  // dès qu'il apparaît. Attendre est nécessaire — le controller n'a pas encore réconcilié quand la
  // réponse arrive.
  useEffect(() => {
    if (!pending) return;
    const rows = pending.world === "users" ? users : groups;
    const hit = rows.find((r) => r.name === pending.name);
    if (!hit) return;
    setWorld(pending.world);
    setSelected(hit.uid);
    setTab("detail");
    onPanelOpen(true);
    setPending(null);
  }, [pending, users, groups, onPanelOpen]);

  const needle = query.trim().toLowerCase();
  const worse = (hints: Hint[]) => hints.some((h) => h.level !== "info");

  const shownUsers = useMemo(
    () =>
      users.filter((u) => {
        if (filter === "problems" && !worse(u.hints)) return false;
        if (!needle) return true;
        return [u.name, u.email, u.display_name, u.subject, u.member_of.join(" "), u.phase_label]
          .join(" ")
          .toLowerCase()
          .includes(needle);
      }),
    [users, filter, needle],
  );

  const shownGroups = useMemo(
    () =>
      groups.filter((g) => {
        if (filter === "problems" && !worse(g.hints)) return false;
        if (!needle) return true;
        return [g.name, g.subject, g.description, g.members.join(" "), g.bindings_labels.join(" ")]
          .join(" ")
          .toLowerCase()
          .includes(needle);
      }),
    [groups, filter, needle],
  );

  const selectedUser = useMemo(
    () => users.find((u) => u.uid === selected) ?? null,
    [users, selected],
  );
  const selectedGroup = useMemo(
    () => groups.find((g) => g.uid === selected) ?? null,
    [groups, selected],
  );
  const selectedRecord: EventRecord | null =
    selectedUser?.record ?? selectedGroup?.record ?? null;

  /** Une écriture, sa phrase, et la relecture qui suit. */
  const run = useCallback(
    async (request: Record<string, unknown>) => {
      setMenuOpen(false);
      setForm(null);
      setBusy(true);
      try {
        const result = await api.identityWrite(request, lang);
        if (result.outcome === "invited") {
          // Le lien et le code arrivent ici et nulle part ailleurs.
          setInvite(result.invite);
        } else if (result.outcome === "said") {
          // La sortie de la commande devient le message **telle quelle** : kdt ne reformule pas
          // « n sessions fermées, l'accès s'arrête sous X », et le navigateur non plus.
          setToast({ tone: "ok", text: result.message });
        }
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
  const controller = payload?.controller ?? null;

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
              label: st.identDetail,
              node: selectedUser ? (
                <UserDetail
                  user={selectedUser}
                  delivery={payload?.delivery}
                  directory={payload?.directory}
                  missing={payload?.missing_mapped_groups ?? []}
                  st={st}
                />
              ) : selectedGroup ? (
                <GroupDetail group={selectedGroup} st={st} />
              ) : null,
            }}
          />
          <Splitter height={panelHeight} onHeight={onPanelHeight} lang={lang} />
        </>
      )}

      <div className="worlds" role="tablist">
        <button
          role="tab"
          aria-selected={world === "users"}
          onClick={() => {
            setWorld("users");
            setSelected(null);
          }}
        >
          {st.identUsers}
          {counts && <span className="count">{counts.users}</span>}
        </button>
        <button
          role="tab"
          aria-selected={world === "groups"}
          onClick={() => {
            setWorld("groups");
            setSelected(null);
          }}
        >
          {st.identGroups}
          {counts && <span className="count">{counts.groups}</span>}
        </button>

        {/* Le filtre `f` du TUI, qui y cycle sur une touche. Ici les deux états tiennent côte à
            côte : on voit lequel est actif sans avoir à appuyer pour le découvrir. */}
        <div className="segmented" role="group">
          {(["all", "problems"] as const).map((f) => (
            <button key={f} aria-pressed={filter === f} onClick={() => setFilter(f)}>
              {f === "all" ? st.filterAll : st.filterProblems}
            </button>
          ))}
        </div>

        {counts && (
          <div className="tally">
            <span className="ok" title={st.identUsers}>
              ✓{counts.active}
            </span>
            {counts.pending > 0 && (
              <span className="info" title={st.identInvite}>
                ✉{counts.pending}
              </span>
            )}
            {/* Le nombre qui dit s'il y a quelque chose à révoquer. Ce n'est pas `active` : un
                compte peut être en règle et connecté de nulle part. */}
            <span className="info" title={st.identSessions}>
              ◉{counts.connected}
            </span>
            {counts.unbound > 0 && (
              <span className="warn" title={st.identRights}>
                ⚠{counts.unbound}
              </span>
            )}
          </div>
        )}

        <div className="right">
          {busy && <span>{st.objWorking}</span>}
          <ToastLine toast={toast} onDismiss={() => setToast(null)} lang={lang} />
          <div className="menu-anchor" ref={menuRef}>
            <button
              className="panel-toggle action"
              aria-expanded={menuOpen}
              onClick={() => {
                setMenuOpen((v) => !v);
                setForm(null);
              }}
            >
              {st.identActions} ▾
            </button>
            {menuOpen && (
              <IdentityMenu
                st={st}
                user={world === "users" ? selectedUser : null}
                group={world === "groups" ? selectedGroup : null}
                groups={groups}
                controller={controller}
                directory={payload?.directory ?? null}
                installed={payload?.installed ?? false}
                installCommand={payload?.install_command ?? ""}
                form={form}
                onForm={setForm}
                onRun={run}
                onCreated={(w, name) => setPending({ world: w, name })}
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

      {invite && <InvitePanel invite={invite} st={st} onClose={() => setInvite(null)} />}

      <div className="body">
        {!loaded ? (
          <div className="center" />
        ) : (world === "users" ? shownUsers : shownGroups).length === 0 ? (
          <div className="center">
            <div className="box">
              <h2>
                {payload && !payload.installed ? st.identNotInstalled : st.identEmpty}
              </h2>
              {error && <p className="err">{error}</p>}
              {payload?.error && <p className="err">{payload.error}</p>}
              {payload && !payload.installed && (
                <>
                  <p>{st.identInstallHelp}</p>
                  <pre className="logs">{payload.install_command}</pre>
                </>
              )}
            </div>
          </div>
        ) : world === "users" ? (
          <UserTable
            rows={shownUsers}
            selected={selected}
            showSource={payload?.shows_source ?? false}
            st={st}
            onSelect={(u) => {
              setSelected(u.uid);
              setTab("detail");
            }}
          />
        ) : (
          <GroupTable
            rows={shownGroups}
            selected={selected}
            showSource={payload?.shows_source ?? false}
            st={st}
            onSelect={(g) => {
              setSelected(g.uid);
              setTab("detail");
            }}
          />
        )}
      </div>

      <div className="statusbar">
        <span>
          {(world === "users" ? shownUsers : shownGroups).length} {st.rows}
        </span>
        {controller && (
          <span>
            {st.identOperator}: {controller.namespace}
          </span>
        )}
        {payload?.delivery && <DeliveryStatus delivery={payload.delivery} st={st} />}
        {payload?.directory && <DirectoryStatus directory={payload.directory} st={st} />}
        {/* Dit une fois, ici, plutôt qu'en tiret sur chaque ligne : les colonnes que ces deux
            lectures font taire sont celles que rien d'autre ne peut répondre. */}
        {payload?.creds_error && <span className="err">{payload.creds_error}</span>}
        {payload?.sessions_error && <span className="err">{payload.sessions_error}</span>}
        {!controller && payload?.installed && <span className="err">{st.identNoController}</span>}
        <span style={{ marginLeft: "auto" }}>{st.identScopeless}</span>
      </div>
    </>
  );
}

/** Ce que le déploiement déclare de la délivrance — la ligne qui rend la colonne SESS lisible. */
function DeliveryStatus({ delivery, st }: { delivery: IdentDelivery; st: Strings }) {
  if (!delivery.mode) {
    return (
      <span className="dim">
        {st.identMode}: {st.identModeUnknown}
      </span>
    );
  }
  return (
    <>
      <span>
        {st.identMode}: {delivery.mode}
        {delivery.revocation_window ? ` ≤ ${delivery.revocation_window}` : ""}
      </span>
      {/* Le seul accès que ni la révocation ni `spec.disabled` n'atteignent. C'est le défaut du
          chart, donc jamais un badge par ligne : une ligne au niveau de la vue. */}
      {delivery.download_open && <span className="warn">{st.identDownloadOpen}</span>}
    </>
  );
}

/**
 * Le second axe, dit une fois : qui le portail reconnaît.
 *
 * `local` ne s'affiche pas — c'est ce qu'était tout déploiement jusqu'à 1.2, et un badge marque
 * l'écart à la norme. Le mode non déclaré, lui, se dit : il n'est pas `local`, il est inconnu.
 */
function DirectoryStatus({ directory, st }: { directory: IdentDirectory; st: Strings }) {
  if (!directory.auth_mode) {
    return (
      <span className="dim">
        {st.identAuth}: {st.identAuthUnknown}
      </span>
    );
  }
  if (!directory.federated) return null;
  return (
    <>
      <span>
        {st.identAuth}: {directory.auth_mode}
        {directory.url ? ` · ${directory.url}` : ""}
      </span>
      {/* Une table illisible n'est pas une table vide : ce qui se tait, ce sont les constats sur
          ce qui alimente les groupes. */}
      {directory.mappings_error && <span className="warn">{st.identMappingsUnreadable}</span>}
    </>
  );
}

function UserTable({
  rows,
  selected,
  showSource,
  st,
  onSelect,
}: {
  rows: IdentUserRow[];
  selected: string | null;
  showSource: boolean;
  st: Strings;
  onSelect: (u: IdentUserRow) => void;
}) {
  return (
    <div className="tbl">
      <div className="thead">
        <div
          className="tr"
          style={{ gridTemplateColumns: showSource ? USER_COLUMNS_SOURCE : USER_COLUMNS }}
        >
          <div className="cell">NAME</div>
          <div className="cell">EMAIL</div>
          <div className="cell">PHASE</div>
          <div className="cell">GROUPS</div>
          <div className="cell">INVITE</div>
          <div className="cell num">SESS</div>
          {showSource && <div className="cell">SRC</div>}
          <div className="cell num">AGE</div>
        </div>
      </div>
      <div className="tbody">
        {rows.map((u) => (
          <div
            key={u.uid}
            className={`tr sev-${u.record.tone}`}
            style={{ gridTemplateColumns: showSource ? USER_COLUMNS_SOURCE : USER_COLUMNS }}
            aria-selected={selected === u.uid}
            tabIndex={0}
            onClick={() => onSelect(u)}
            onKeyDown={(e) => {
              if (e.key === "Enter") onSelect(u);
            }}
          >
            <div className="cell id">{u.name}</div>
            <div className="cell dim">{u.email}</div>
            <div className={`cell ${u.phase_tone}`}>{u.phase_label}</div>
            {/* Les groupes décident de ce que le compte peut faire : la colonne prend le mou. */}
            <div className={`cell ${u.member_of.length ? "" : "dim"}`}>
              {u.member_of.length ? u.member_of.join(", ") : "—"}
            </div>
            <div className={`cell ${u.invitation_tone}`}>{u.invitation_label}</div>
            <div className={`cell num ${u.sessions_tone}`} title={st.identSessions}>
              {u.sessions_cell}
            </div>
            {/* La valeur du label, telle quelle : la ligne dit `ldap` parce que l'objet dit
                `ldap`. */}
            {showSource && <SourceCell source={u.source} st={st} />}
            <div className="cell num dim">{u.age}</div>
          </div>
        ))}
      </div>
    </div>
  );
}

function SourceCell({ source, st }: { source: IdentSource; st: Strings }) {
  return (
    <div className={`cell ${source === "ldap" ? "info" : "dim"}`} title={st.identSource}>
      {source === "ldap" ? "ldap" : "—"}
    </div>
  );
}

function GroupTable({
  rows,
  selected,
  showSource,
  st,
  onSelect,
}: {
  rows: IdentGroupRow[];
  selected: string | null;
  showSource: boolean;
  st: Strings;
  onSelect: (g: IdentGroupRow) => void;
}) {
  return (
    <div className="tbl">
      <div className="thead">
        <div
          className="tr"
          style={{ gridTemplateColumns: showSource ? GROUP_COLUMNS_SOURCE : GROUP_COLUMNS }}
        >
          <div className="cell">NAME</div>
          <div className="cell num">MEM</div>
          <div className="cell">UNKNOWN</div>
          <div className="cell num">RIGHTS</div>
          {showSource && <div className="cell">SRC</div>}
          <div className="cell">DESCRIPTION</div>
          <div className="cell num">AGE</div>
        </div>
      </div>
      <div className="tbody">
        {rows.map((g) => (
          <div
            key={g.uid}
            className={`tr sev-${g.record.tone}`}
            style={{ gridTemplateColumns: showSource ? GROUP_COLUMNS_SOURCE : GROUP_COLUMNS }}
            aria-selected={selected === g.uid}
            tabIndex={0}
            onClick={() => onSelect(g)}
            onKeyDown={(e) => {
              if (e.key === "Enter") onSelect(g);
            }}
          >
            <div className="cell id">{g.name}</div>
            {/* Un zéro se lit comme rien plutôt que comme « 0 » : dans une colonne de comptes, ce
                qui compte est les lignes qui en ont. */}
            <div className="cell num">{g.resolved.length || "·"}</div>
            <div className={`cell ${g.unknown.length ? "warn" : "dim"}`}>
              {g.unknown.join(", ")}
            </div>
            <div className={`cell num ${g.rights_tone}`}>
              {g.bindings.length ? g.bindings.length : "—"}
            </div>
            {showSource && <SourceCell source={g.source} st={st} />}
            <div className="cell dim">{g.description}</div>
            <div className="cell num dim">{g.age}</div>
          </div>
        ))}
      </div>
    </div>
  );
}

/** Le détail d'un compte : ce que le TUI met dans son panneau, dans le même ordre. */
function UserDetail({
  user,
  delivery,
  directory,
  missing,
  st,
}: {
  user: IdentUserRow;
  delivery?: IdentDelivery;
  directory?: IdentDirectory;
  missing: string[];
  st: Strings;
}) {
  return (
    <div className="detail">
      {/* L'identité que l'apiserver voit, en premier : c'est le préfixe qui empêche un compte
          `kdt:` d'hériter d'un binding destiné à quelqu'un du même nom ailleurs. */}
      <Line label={st.identSubject} value={user.subject} mono />
      <Line label={st.identEmail} value={user.email} />
      {user.display_name && <Line label={st.identDisplayName} value={user.display_name} />}
      {/* D'où vient le compte, et le DN auquel il est épinglé. L'épinglage est la barrière qui
          empêche deux identifiants d'annuaire normalisés vers le même nom de partager un compte :
          il est montré verbatim plutôt que résumé. */}
      {user.source === "ldap" && (
        <>
          <Line label={st.identSource} value="ldap" />
          {user.ldap_dn && <Line label={st.identLdapDn} value={user.ldap_dn} mono />}
        </>
      )}
      {/* La phase de kdt et celle du controller côte à côte quand elles diffèrent : un `Locked`
          qui n'existe qu'ici ne doit jamais passer pour ce que la CRD dit. */}
      {user.raw_phase && user.raw_phase !== user.phase_label && (
        <Line label="status.phase" value={user.raw_phase} />
      )}
      <Line
        label={st.identGroupsLabel}
        value={user.member_of.length ? user.member_of.join(", ") : st.identNone}
      />
      {user.creds?.locked_until != null && (
        <Line label="locked until" value={stamp(user.creds.locked_until)} />
      )}
      {user.creds != null && user.creds.failed_attempts > 0 && (
        <Line label="failed attempts" value={String(user.creds.failed_attempts)} />
      )}
      <Line label={st.identInvite} value={user.invitation_label} tone={user.invitation_tone} />
      {/* Sessions et délivrance ensemble : « trois ouvertes » n'est pas actionnable sans « et les
          fermer coupe l'accès sous dix minutes ». */}
      <Line
        label={st.identSessions}
        value={
          user.sessions === null
            ? "?"
            : user.sessions.open === 0
              ? st.identNone
              : `${user.sessions.open}` +
                (user.sessions.last_expiry ? ` → ${stamp(user.sessions.last_expiry)}` : "") +
                (user.sessions.stale ? ` · ${user.sessions.stale} stale` : "")
        }
        tone={user.sessions_tone}
      />
      {delivery && <DeliveryLines delivery={delivery} st={st} />}
      {directory && <DirectoryLines directory={directory} missing={missing} st={st} />}
      <Line label="age" value={user.age} />
      <Hints hints={user.hints} st={st} />
    </div>
  );
}

function DeliveryLines({ delivery, st }: { delivery: IdentDelivery; st: Strings }) {
  if (!delivery.mode) return <Line label={st.identMode} value={st.identModeUnknown} tone="dim" />;
  return (
    <>
      <Line label={st.identMode} value={delivery.mode} />
      {delivery.revocation_window && (
        <Line label={st.identRevocation} value={`≤ ${delivery.revocation_window}`} />
      )}
      {delivery.refresh_ttl && <Line label={st.identRefresh} value={delivery.refresh_ttl} />}
      {/* En mode OIDC le portail n'a rien à télécharger : une ligne « fermé » laisserait croire
          que quelqu'un l'a fermé. */}
      {delivery.mode === "certificate" && delivery.kubeconfig_download !== null && (
        <Line
          label={st.identDownload}
          value={delivery.kubeconfig_download ? st.identDownloadOpen : st.identDownloadClosed}
          tone={delivery.kubeconfig_download ? "warn" : "dim"}
        />
      )}
    </>
  );
}

/**
 * Ce que le déploiement déclare de l'annuaire, et rien de plus.
 *
 * Un déploiement `local` tient en une ligne : il n'a pas d'annuaire à décrire. Un mode non déclaré
 * en tient une aussi, celle qui nomme l'absence — jamais un bloc de champs vides.
 */
function DirectoryLines({
  directory,
  missing,
  st,
}: {
  directory: IdentDirectory;
  missing: string[];
  st: Strings;
}) {
  if (!directory.auth_mode)
    return <Line label={st.identAuth} value={st.identAuthUnknown} tone="dim" />;
  if (!directory.federated) return <Line label={st.identAuth} value={directory.auth_mode} />;
  return (
    <>
      <Line label={st.identAuth} value={directory.auth_mode} />
      {directory.url && (
        <Line
          label={st.identLdapUrl}
          value={directory.start_tls ? `${directory.url} (StartTLS)` : directory.url}
          mono
        />
      )}
      {directory.profile && <Line label={st.identLdapProfile} value={directory.profile} />}
      {directory.search_base && <Line label={st.identLdapBase} value={directory.search_base} mono />}
      {/* Le délai qu'un retrait de groupe côté annuaire attend pour devenir un retrait de droits. */}
      {directory.resync && <Line label={st.identLdapResync} value={directory.resync} />}
      {directory.mappings_error && (
        <Line label={st.identLdapMappings} value={st.identMappingsUnreadable} tone="warn" />
      )}
      {directory.mappings && (
        <>
          <Line label={st.identLdapMappings} value={String(directory.mappings.length)} />
          {directory.mappings.map((m) => (
            <div className="keys-row" key={`${m.dn}→${m.group}`}>
              <div className="k-col">
                <span className="k" />
              </div>
              <span className="v mono">
                · {m.dn} → {m.group}
              </span>
            </div>
          ))}
        </>
      )}
      {/* Déclarés dans la table et pas encore là : jamais une faute, l'amont crée chaque groupe à
          la première connexion d'un de ses membres. */}
      {missing.length > 0 && (
        <p className="guard info">
          <span className="gl">·</span> {st.identMappingsMissing} {missing.join(", ")}
        </p>
      )}
    </>
  );
}

function GroupDetail({ group, st }: { group: IdentGroupRow; st: Strings }) {
  return (
    <div className="detail">
      {/* Le subject verbatim : le guide amont demande qu'un binding cite cette chaîne plutôt qu'une
          chaîne retapée à la main. La copie est posée sous le nom, pas au bout de la valeur. */}
      <div className="keys-row">
        <div className="k-col">
          <span className="k">{st.identSubject}</span>
          <CopyButton text={group.subject} label={st.secCopy} done={st.secCopied} />
        </div>
        <span className="v mono">{group.subject}</span>
      </div>
      {group.description && <Line label={st.identDescription} value={group.description} />}
      {/* Un groupe fédéré le dit même quand plus rien ne l'alimente — cet écart-là est justement
          ce que le constat en bas de panneau nomme. */}
      {group.source === "ldap" && <Line label={st.identSource} value="ldap" />}
      {group.ldap_dns.length > 0 && (
        <Line label={st.identLdapMappings} value={group.ldap_dns.join(", ")} mono />
      )}
      <Line
        label={st.identMembers}
        value={group.resolved.length ? group.resolved.join(", ") : st.identNone}
      />
      {group.unknown.length > 0 && (
        <Line label={st.identUnknownMembers} value={group.unknown.join(", ")} tone="warn" />
      )}
      {/* Ce que le groupe accorde réellement. Une liste vide est la réponse à « pourquoi ses
          membres prennent 403 partout », donc elle est écrite plutôt que laissée blanche. */}
      <Line
        label={st.identRights}
        value={group.bindings_labels.length ? "" : st.identNone}
        tone={group.rights_tone}
      />
      {group.bindings_labels.map((b) => (
        <div className="keys-row" key={b}>
          <div className="k-col">
            <span className="k" />
          </div>
          <span className="v mono">· {b}</span>
        </div>
      ))}
      <Line label="age" value={group.age} />
      <Hints hints={group.hints} st={st} />
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
 * L'invitation, montrée **une seule fois**.
 *
 * Le lien et le code sont volontairement séparés : ils sont censés voyager par deux canaux
 * différents, d'où deux copies distinctes plutôt qu'un bloc à copier d'un coup.
 */
function InvitePanel({
  invite,
  st,
  onClose,
}: {
  invite: IdentInvite;
  st: Strings;
  onClose: () => void;
}) {
  return (
    <div className="once">
      <p className="warn">
        {st.identInviteOnce} — {invite.user}
        {invite.expires ? ` · ${invite.expires}` : ""}
      </p>
      {invite.link && (
        <div className="keys-row">
          <div className="k-col">
            <span className="k">{st.identInviteLink}</span>
            <CopyButton text={invite.link} label={st.secCopy} done={st.secCopied} />
          </div>
          <span className="v">{invite.link}</span>
        </div>
      )}
      {invite.code && (
        <div className="keys-row">
          <div className="k-col">
            <span className="k">{st.identInviteCode}</span>
            <CopyButton text={invite.code} label={st.secCopy} done={st.secCopied} />
          </div>
          <span className="v">{invite.code}</span>
        </div>
      )}
      {/* Si les deux champs n'ont pas pu être tirés de la sortie — un libellé qui a changé en
          amont —, on montre ce que la commande a réellement imprimé plutôt que rien. */}
      {!invite.link && !invite.code && (
        <div className="keys-row">
          <div className="k-col">
            <span className="k">{st.identInviteRaw}</span>
            <CopyButton text={invite.raw} label={st.secCopy} done={st.secCopied} />
          </div>
          <pre className="v">{invite.raw}</pre>
        </div>
      )}
      <div className="menu-buttons">
        <button className="cta" onClick={onClose}>
          {st.identInviteClose}
        </button>
      </div>
    </div>
  );
}

/**
 * Le menu de la barre : ce que kdt offre sur `o`, entier.
 *
 * Les deux créations sont proposées depuis les deux mondes — un groupe se crée en regardant le
 * compte qu'il est censé contenir — et les entrées qui ne peuvent pas aboutir le disent au lieu de
 * le découvrir après la confirmation.
 */
/**
 * L'aide de l'appartenance, avec ce que l'annuaire en fera.
 *
 * L'écriture aboutit : ce n'est pas un refus, et le dire comme un blocage serait faux. C'est la
 * relecture suivante qui la défait, et c'est ce qu'il faut savoir avant de cliquer.
 */
function memberHelp(st: Strings, federated: boolean): string {
  return federated ? `${st.identMemberHelp} · ${st.identMembershipLdap}` : st.identMemberHelp;
}

function IdentityMenu({
  st,
  user,
  group,
  groups,
  controller,
  directory,
  installed,
  installCommand,
  form,
  onForm,
  onRun,
  onCreated,
}: {
  st: Strings;
  user: IdentUserRow | null;
  group: IdentGroupRow | null;
  groups: IdentGroupRow[];
  controller: { namespace: string; pod: string; container: string } | null;
  directory: IdentDirectory | null;
  installed: boolean;
  installCommand: string;
  form: Form;
  onForm: (f: Form) => void;
  onRun: (request: Record<string, unknown>) => void;
  onCreated: (world: World, name: string) => void;
}) {
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [display, setDisplay] = useState("");
  const [description, setDescription] = useState("");
  const [validity, setValidity] = useState("72h");
  const [target, setTarget] = useState("");

  return (
    <div className="pop menu" onClick={(e) => e.stopPropagation()}>
      <div className="pop-hd">
        <span>{st.identActions}</span>
      </div>
      {(user || group) && (
        <div className="menu-target mono">{user ? user.name : group?.name}</div>
      )}

      {form === null ? (
        <div className="menu-list">
          {user && (
            <>
              {/* En `ldap` l'invitation n'existe pas : les comptes naissent d'une connexion
                  réussie, et la commande amont refuse de s'exécuter. Ce qui ne peut pas aboutir
                  est éteint ici plutôt que découvert après la confirmation. */}
              <MenuItem
                label={st.identInvite}
                desc={
                  directory?.federated
                    ? st.identInviteLdap
                    : controller
                      ? st.identInviteHelp
                      : st.identNoController
                }
                disabled={!controller || user.disabled || !!directory?.federated}
                onClick={() => onForm({ kind: "invite" })}
              />
              {/* À côté d'inviter, parce que les deux tournent dans le pod et parlent d'accès. Le
                  libellé dit ce que ça fait — déconnecter toutes les machines — jamais « révoquer
                  le compte », qui est l'autre geste. */}
              <MenuItem
                label={st.identRevoke}
                desc={controller ? st.identRevokeHelp : st.identNoController}
                disabled={!controller}
                onClick={() => onForm({ kind: "revoke" })}
              />
              <MenuItem
                label={user.disabled ? st.identEnable : st.identDisable}
                desc={
                  !user.disabled
                    ? st.identDisableHelp
                    : user.source === "ldap"
                      ? `${st.identEnableHelp} · ${st.identEnableLdap}`
                      : st.identEnableHelp
                }
                onClick={() => onForm({ kind: "disabled", next: !user.disabled })}
              />
              <MenuItem
                label={st.identAddMember}
                desc={memberHelp(st, directory?.federated ?? false)}
                disabled={groups.length === 0}
                onClick={() => {
                  setTarget(groups[0]?.name ?? "");
                  onForm({ kind: "add-member" });
                }}
              />
              {/* Retirer se fait depuis le compte, en nommant le groupe : c'est là qu'on voit à
                  quoi il appartient, et l'écriture porte de toute façon sur le groupe. */}
              <MenuItem
                label={st.identRemoveMember}
                desc={memberHelp(st, directory?.federated ?? false)}
                disabled={user.member_of.length === 0}
                onClick={() => {
                  setTarget(user.member_of[0] ?? "");
                  onForm({ kind: "remove-member" });
                }}
              />
            </>
          )}
          {group && (
            <MenuItem
              label={st.identAddMember}
              desc={memberHelp(st, group.source === "ldap")}
              onClick={() => {
                setTarget("");
                onForm({ kind: "add-member" });
              }}
            />
          )}
          <MenuItem
            label={st.identCreateUser}
            desc={st.identMemberHelp}
            onClick={() => {
              setName("");
              setEmail("");
              setDisplay("");
              onForm({ kind: "create-user" });
            }}
          />
          <MenuItem
            label={st.identCreateGroup}
            desc={st.identMemberHelp}
            onClick={() => {
              setName("");
              setDescription("");
              onForm({ kind: "create-group" });
            }}
          />
          {/* Sur un cluster sans kdt-identity, créer un KdtUser n'est pas le geste suivant : la
              commande qui l'installerait, si. */}
          {!installed && (
            <div className="menu-confirm">
              <p>{st.identInstallHelp}</p>
              <CopyButton text={installCommand} label={st.secCopy} done={st.secCopied} />
            </div>
          )}
        </div>
      ) : (
        <div className="menu-confirm">
          {form.kind === "invite" && (
            <>
              <p>{st.identInviteHelp}</p>
              <div className="form-row">
                <label htmlFor="ident-validity">{st.identInviteValidity}</label>
                <input
                  id="ident-validity"
                  value={validity}
                  onChange={(e) => setValidity(e.target.value)}
                />
              </div>
              <Buttons
                st={st}
                onCancel={() => onForm(null)}
                onConfirm={() =>
                  onRun({ action: "invite", user: user!.name, validity })
                }
              />
            </>
          )}

          {form.kind === "revoke" && (
            <>
              <p>{st.identRevokeHelp}</p>
              <Buttons
                st={st}
                onCancel={() => onForm(null)}
                onConfirm={() => onRun({ action: "revoke", user: user!.name })}
              />
            </>
          )}

          {form.kind === "disabled" && (
            <>
              <p>{form.next ? st.identDisableHelp : st.identEnableHelp}</p>
              <Buttons
                st={st}
                onCancel={() => onForm(null)}
                onConfirm={() =>
                  onRun({ action: "set_disabled", user: user!.name, disabled: form.next })
                }
              />
            </>
          )}

          {form.kind === "add-member" && (
            <>
              <p>{st.identMemberHelp}</p>
              <div className="form-row">
                {/* Depuis un compte, on choisit le groupe ; depuis un groupe, on saisit le compte.
                    Dans les deux cas l'écriture porte sur `spec.members` du groupe. */}
                <label htmlFor="ident-target">
                  {user ? st.identGroups : st.identMembers}
                </label>
                <input
                  id="ident-target"
                  list={user ? "ident-group-list" : undefined}
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                />
                {user && (
                  <datalist id="ident-group-list">
                    {groups.map((g) => (
                      <option key={g.uid} value={g.name} />
                    ))}
                  </datalist>
                )}
              </div>
              <Buttons
                st={st}
                disabled={!target.trim()}
                onCancel={() => onForm(null)}
                onConfirm={() =>
                  onRun(
                    user
                      ? { action: "add_member", group: target.trim(), user: user.name }
                      : { action: "add_member", group: group!.name, user: target.trim() },
                  )
                }
              />
            </>
          )}

          {form.kind === "remove-member" && user && (
            <>
              <p>{st.identMemberHelp}</p>
              <div className="form-row">
                <label htmlFor="ident-remove">{st.identGroups}</label>
                <input
                  id="ident-remove"
                  list="ident-member-of"
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                />
                <datalist id="ident-member-of">
                  {user.member_of.map((g) => (
                    <option key={g} value={g} />
                  ))}
                </datalist>
              </div>
              <Buttons
                st={st}
                disabled={memberIndex(groups, target, user.name) < 0}
                onCancel={() => onForm(null)}
                onConfirm={() =>
                  onRun({
                    action: "remove_member",
                    group: target.trim(),
                    user: user.name,
                    // L'index dans `spec.members`, lu sur le groupe affiché. Un index périmé ne
                    // retire pas le mauvais membre : le patch porte un `test` sur le nom, et
                    // l'apiserver refuse plutôt que d'obéir.
                    index: memberIndex(groups, target, user.name),
                  })
                }
              />
            </>
          )}

          {form.kind === "create-user" && (
            <>
              <Field id="cu-name" label={st.identName} value={name} onChange={setName} />
              <Field id="cu-mail" label={st.identEmail} value={email} onChange={setEmail} />
              <Field
                id="cu-disp"
                label={st.identDisplayName}
                value={display}
                onChange={setDisplay}
              />
              <Buttons
                st={st}
                confirmLabel={st.identCreate}
                disabled={!name.trim()}
                onCancel={() => onForm(null)}
                onConfirm={() => {
                  onCreated("users", name.trim());
                  onRun({
                    action: "create_user",
                    name: name.trim(),
                    email,
                    display_name: display,
                  });
                }}
              />
            </>
          )}

          {form.kind === "create-group" && (
            <>
              <Field id="cg-name" label={st.identName} value={name} onChange={setName} />
              <Field
                id="cg-desc"
                label={st.identDescription}
                value={description}
                onChange={setDescription}
              />
              <Buttons
                st={st}
                confirmLabel={st.identCreate}
                disabled={!name.trim()}
                onCancel={() => onForm(null)}
                onConfirm={() => {
                  onCreated("groups", name.trim());
                  onRun({ action: "create_group", name: name.trim(), description });
                }}
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
  disabled,
  onClick,
}: {
  label: string;
  desc: string;
  disabled?: boolean;
  onClick: () => void;
}) {
  return (
    <button className="menu-item" disabled={disabled} onClick={onClick}>
      <span className="lbl">{label}</span>
      <span className="desc">{desc}</span>
    </button>
  );
}

function Field({
  id,
  label,
  value,
  onChange,
}: {
  id: string;
  label: string;
  value: string;
  onChange: (v: string) => void;
}) {
  return (
    <div className="form-row">
      <label htmlFor={id}>{label}</label>
      <input id={id} value={value} spellCheck={false} onChange={(e) => onChange(e.target.value)} />
    </div>
  );
}

/** La sortie par défaut est celle qui n'écrit rien : c'est elle qui a le focus. */
function Buttons({
  st,
  confirmLabel,
  disabled,
  onCancel,
  onConfirm,
}: {
  st: Strings;
  confirmLabel?: string;
  disabled?: boolean;
  onCancel: () => void;
  onConfirm: () => void;
}) {
  return (
    <div className="menu-buttons">
      <button autoFocus onClick={onCancel}>
        {st.ranchCancel}
      </button>
      <button className="cta" disabled={disabled} onClick={onConfirm}>
        {confirmLabel ?? st.ranchApply}
      </button>
    </div>
  );
}

/**
 * La place du compte dans le `spec.members` du groupe, ou `-1`.
 *
 * C'est `members` qu'on lit et non `resolved` : le patch adresse le tableau tel qu'il est écrit,
 * membres inconnus compris, et se décaler d'un cran viserait quelqu'un d'autre.
 */
function memberIndex(groups: IdentGroupRow[], group: string, user: string): number {
  const hit = groups.find((g) => g.name === group.trim());
  return hit ? hit.members.indexOf(user) : -1;
}

/** Un instant epoch, dans la forme que kdt utilise dans son panneau. */
function stamp(epoch: number): string {
  return new Date(epoch * 1000).toISOString().replace("T", " ").slice(0, 16);
}
