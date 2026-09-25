// La vue réseau : Services, Ingress et policies — les trois mondes de la vue réseau de kdt.
//
// Rien n'est jugé ici. Le compte d'endpoints prêts et son ton, l'état de chaque Secret TLS, le
// détail que l'onglet Status du TUI rédige pour un Ingress, le `DirEffect` d'une policy : tout
// arrive tout fait de `kdt::svc` et `kdt::netpol`. Le navigateur range et peint.
//
// # Ce qui ne passe pas
//
// Le port-forward (`f`/`F` du TUI) ouvre un port sur le poste qui lance kdt : depuis un navigateur,
// ce poste est le serveur, et le port n'y servirait à personne. La colonne FORWARD part avec lui.
//
// # Les deux regroupements
//
// Le `t` du TUI range les endpoints sous leur Service, ou les Ingress sous leur IngressClass. Ici
// c'est une case, qui dit l'état et l'action d'un même objet, et chaque parent se replie sur
// lui-même. Pas de cascade de sélection : un Service ne possède pas les pods qu'il sert, ni une
// classe les Ingress qui la nomment — supprimer l'un n'emporte pas les autres.

import { Fragment, useCallback, useEffect, useMemo, useState, type KeyboardEvent } from "react";
import * as api from "./api";
import { ApiError, NeedsAuth } from "./api";
import type { Lang, Strings } from "./i18n";
import { BulkDeletePane, RowMenu, type ObjectTab } from "./objects";
import {
  RowCheckbox,
  SelectionBar,
  SelectionHead,
  TreeCheckbox,
  useMultiSelect,
  withoutSelTrack,
} from "./selection";
import { InspectPanel, PanelToggle, Splitter, ViewBody, type PanelTab } from "./panel";
import type {
  EndpointRow,
  EventRecord,
  IngressClassRow,
  IngressPayload,
  IngressRow,
  NetPolRow,
  NetpolPayload,
  ServiceRow,
  ServicesPayload,
} from "./types";
import { cols } from "./table";

/** `NAMESPACE NAME TYPE CLUSTER-IP EXTERNAL-IP PORTS ENDPOINTS NODE AGE`, dans l'ordre du TUI moins
 * FORWARD. La première piste (`34px`) porte la case de sélection multiple, la dernière le hamburger
 * de la ligne ; en arbre, la case passe dans la cellule du nom. */
const SVC_COLUMNS =
  "34px fit-content(18ch) fit-content(44ch) fit-content(12ch) fit-content(16ch) fit-content(20ch)" +
  " minmax(14ch,1fr) fit-content(12ch) fit-content(22ch) 52px 34px";

/** `NAMESPACE NAME CLASS/CTRL HOSTS ROUTES TLS ADDRESS AGE`, dans l'ordre du TUI. */
const ING_COLUMNS =
  "34px fit-content(18ch) fit-content(30ch) fit-content(22ch) fit-content(28ch) minmax(26ch,1fr)" +
  " fit-content(32ch) fit-content(18ch) 52px 34px";

/** `NAMESPACE NAME ENGINE TARGET TYPES INGRESS EGRESS AGE`, dans l'ordre du TUI. */
const POL_COLUMNS =
  "34px fit-content(18ch) fit-content(24ch) 72px fit-content(26ch) fit-content(14ch)" +
  " minmax(22ch,1fr) minmax(22ch,1fr) 52px 34px";

type World = "services" | "ingress" | "policies";

/** Une ligne adressable de la vue, sous la forme qu'il faut pour en montrer le détail. */
type Picked =
  | { k: "svc"; row: ServiceRow }
  | { k: "ep"; row: EndpointRow }
  | { k: "ing"; row: IngressRow }
  | { k: "cls"; row: IngressClassRow; count: number }
  | { k: "pol"; row: NetPolRow };

/** Un groupe du monde Ingress rangé par classe ; `cls` nul pour les Ingress sans classe connue. */
interface IngGroup {
  cls: IngressClassRow | null;
  items: IngressRow[];
}

/** Les routes d'un Ingress, telles que `kdt::svc` les joint pour sa colonne. */
const routesOf = (i: IngressRow) => (i.rules ? i.rules.split("  ·  ") : []);

export default function NetworkView({
  lang,
  st,
  query,
  namespaces,
  panelHeight,
  onPanelHeight,
  panelOpen,
  onPanelOpen,
  onNeedsAuth,
  onOpenSecret,
}: {
  lang: Lang;
  st: Strings;
  query: string;
  namespaces: string[];
  panelHeight: number;
  onPanelHeight: (h: number) => void;
  panelOpen: boolean;
  onPanelOpen: (open: boolean) => void;
  onNeedsAuth: (message: string) => void;
  onOpenSecret: (namespace: string, name: string) => void;
}) {
  const [world, setWorld] = useState<World>("services");
  const [svc, setSvc] = useState<ServicesPayload | null>(null);
  const [ing, setIng] = useState<IngressPayload | null>(null);
  const [pol, setPol] = useState<NetpolPayload | null>(null);
  const [errors, setErrors] = useState<Record<World, string | null>>({
    services: null,
    ingress: null,
    policies: null,
  });
  const [loaded, setLoaded] = useState<Record<World, boolean>>({
    services: false,
    ingress: false,
    policies: false,
  });
  const [selected, setSelected] = useState<string | null>(null);
  const [tab, setTab] = useState<PanelTab>("detail");
  const { checked, toggle: toggleChecked, clear, setAll } = useMultiSelect();
  const [bulkOpen, setBulkOpen] = useState(false);
  // À plat par défaut, comme le TUI : la question qu'on vient poser est d'abord « quels Services,
  // et sont-ils servis ? », la colonne ENDPOINTS y répond sans déplier.
  const [svcGroup, setSvcGroup] = useState(false);
  const [ingGroup, setIngGroup] = useState(false);
  // Les parents **repliés** : ouvrir le regroupement sert à voir les enfants.
  const [folded, setFolded] = useState<Set<string>>(new Set());

  // Un seul namespace, comme les autres vues qui listent des objets namespacés.
  const scope = namespaces[0] ?? "";

  // Une autre portée rend périmé ce qui a été lu des trois mondes, y compris les compteurs des
  // onglets qu'on ne regarde pas.
  useEffect(() => {
    setSvc(null);
    setIng(null);
    setPol(null);
    setLoaded({ services: false, ingress: false, policies: false });
  }, [scope]);

  const load = useCallback(
    async (w: World) => {
      try {
        if (w === "services") setSvc(await api.services(scope));
        else if (w === "ingress") setIng(await api.ingress(scope, lang));
        else setPol(await api.netpol(scope));
        setErrors((prev) => ({ ...prev, [w]: null }));
      } catch (e) {
        if (e instanceof NeedsAuth) onNeedsAuth(e.message);
        else {
          const message = e instanceof ApiError ? e.message : String(e);
          setErrors((prev) => ({ ...prev, [w]: message }));
        }
      }
      setLoaded((prev) => ({ ...prev, [w]: true }));
    },
    [scope, lang, onNeedsAuth],
  );

  useEffect(() => {
    void load(world);
    // Des endpoints passent prêts ou non à la minute : quinze secondes. Le monde Ingress relit
    // chaque Secret TLS qu'il nomme à chaque appel, sans cache partagé entre comptes — et les
    // policies coûtent une lecture par CRD découverte : une minute pour ces deux-là.
    const period = world === "services" ? 15000 : 60000;
    const timer = window.setInterval(() => void load(world), period);
    return () => window.clearInterval(timer);
  }, [load, world]);

  const needle = query.trim().toLowerCase();
  const hit = useCallback(
    (haystack: Array<string | null>) =>
      !needle || haystack.join(" ").toLowerCase().includes(needle),
    [needle],
  );

  // Un Service reste si lui-même ou l'un de ses endpoints passe le tamis : chercher un pod doit
  // retrouver le Service qu'il sert.
  const services = useMemo(
    () =>
      (svc?.services ?? []).filter(
        (s) =>
          hit([s.namespace, s.name, s.type_, s.cluster_ip, s.external_ip, s.ports]) ||
          s.endpoints.some((e) => hit([e.target_name, e.address, e.node])),
      ),
    [svc, hit],
  );

  const ingresses = useMemo(
    () =>
      (ing?.ingresses ?? []).filter((i) =>
        hit([
          i.namespace,
          i.name,
          i.class,
          i.hosts,
          i.rules,
          i.address,
          i.tls.map((t) => t.label).join(" "),
        ]),
      ),
    [ing, hit],
  );

  // Les Ingress rangés sous leur classe. Le rattachement est un champ — `ingressClassName` — pas
  // une règle. Ceux qui ne nomment aucune classe connue ferment la marche, comme dans le TUI.
  const ingGroups = useMemo(() => {
    const classes = ing?.classes ?? [];
    const known = new Set(classes.map((c) => c.name));
    const groups: IngGroup[] = classes
      .map((cls) => ({ cls, items: ingresses.filter((i) => i.class === cls.name) }))
      .filter((g) => g.items.length > 0 || hit([g.cls.name, g.cls.controller]));
    const orphans = ingresses.filter((i) => !i.class || !known.has(i.class));
    if (orphans.length > 0) groups.push({ cls: null, items: orphans });
    return groups;
  }, [ing, ingresses, hit]);

  const policies = useMemo(
    () =>
      (pol?.rows ?? []).filter((p) =>
        hit([p.namespace, p.name, p.engine_label, p.kind, p.target, p.types, p.ingress, p.egress]),
      ),
    [pol, hit],
  );

  // Tout ce que le monde affiché sait désigner, replié ou non : le détail et la suppression
  // groupée partent de là.
  const index = useMemo(() => {
    const m = new Map<string, Picked>();
    if (world === "services") {
      for (const s of svc?.services ?? []) {
        m.set(s.uid, { k: "svc", row: s });
        for (const e of s.endpoints) if (e.addressable) m.set(e.uid, { k: "ep", row: e });
      }
    } else if (world === "ingress") {
      for (const i of ing?.ingresses ?? []) m.set(i.uid, { k: "ing", row: i });
      for (const c of ing?.classes ?? [])
        m.set(c.uid, {
          k: "cls",
          row: c,
          count: (ing?.ingresses ?? []).filter((i) => i.class === c.name).length,
        });
    } else {
      for (const p of pol?.rows ?? []) m.set(p.uid, { k: "pol", row: p });
    }
    return m;
  }, [world, svc, ing, pol]);

  // Les lignes adressables **visibles** du monde affiché — les enfants repliés compris, parce que
  // « tout sélectionner » porte sur ce qui est listé.
  const selectableKeys = useMemo(() => {
    if (world === "services")
      return services.flatMap((s) => [
        s.uid,
        ...(svcGroup ? s.endpoints.filter((e) => e.addressable).map((e) => e.uid) : []),
      ]);
    if (world === "ingress")
      return ingGroup
        ? ingGroups.flatMap((g) => [...(g.cls ? [g.cls.uid] : []), ...g.items.map((i) => i.uid)])
        : ingresses.map((i) => i.uid);
    return policies.map((p) => p.uid);
  }, [world, services, svcGroup, ingGroup, ingGroups, ingresses, policies]);

  const shownCount =
    world === "services"
      ? services.length
      : world === "ingress"
        ? ingresses.length
        : policies.length;

  const picked = selected ? (index.get(selected) ?? null) : null;
  const selectedRecord: EventRecord | null = picked?.row.record ?? null;
  const tlsTarget =
    picked?.k === "ing" && picked.row.first_tls_secret
      ? { namespace: picked.row.namespace, name: picked.row.first_tls_secret }
      : null;

  const select = (uid: string) => {
    setSelected(uid);
    setTab("detail");
  };
  const openTab = (uid: string, t: ObjectTab) => {
    setSelected(uid);
    setTab(t);
  };
  const fold = (uid: string) =>
    setFolded((prev) => {
      const next = new Set(prev);
      if (next.has(uid)) next.delete(uid);
      else next.add(uid);
      return next;
    });
  // Changer de monde ou de forme change ce qui est à l'écran : une case cochée qu'on ne voit plus
  // partirait quand même à la suppression groupée.
  const reshape = () => {
    setSelected(null);
    setBulkOpen(false);
    clear();
  };

  const error = errors[world];
  const emptyText =
    world === "services" ? st.netSvcEmpty : world === "ingress" ? st.netIngEmpty : st.netpolEmpty;
  const common = {
    lang,
    st,
    selected,
    onSelect: select,
    onOpenTab: openTab,
    onNeedsAuth,
    checked,
    onToggleCheck: toggleChecked,
  };

  return (
    <>
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
            detail={
              picked
                ? {
                    label: st.tabDetail,
                    node: <PickedDetail picked={picked} st={st} onOpenSecret={onOpenSecret} />,
                  }
                : undefined
            }
          />
          <Splitter height={panelHeight} onHeight={onPanelHeight} lang={lang} />
        </>
      )}

      <div className="worlds" role="tablist">
        {(
          [
            ["services", "Services", svc?.services.length],
            ["ingress", "Ingress", ing?.ingresses.length],
            // « Policies » et non « NetworkPolicy » : les CRD des CNI portent d'autres kinds et
            // sont dans la même liste.
            ["policies", "Policies", pol?.rows.length],
          ] as const
        ).map(([id, label, n]) => (
          <button
            key={id}
            role="tab"
            aria-selected={world === id}
            onClick={() => {
              setWorld(id);
              reshape();
            }}
          >
            {label}
            {n !== undefined && <span className="count">{n}</span>}
          </button>
        ))}

        {world === "services" && (
          <label className="opt" title={st.netSvcGroupHelp}>
            <input
              type="checkbox"
              checked={svcGroup}
              onChange={(e) => {
                setSvcGroup(e.target.checked);
                reshape();
              }}
            />
            {st.netSvcGroup}
          </label>
        )}
        {world === "ingress" && (
          <label className="opt" title={st.netIngGroupHelp}>
            <input
              type="checkbox"
              checked={ingGroup}
              onChange={(e) => {
                setIngGroup(e.target.checked);
                reshape();
              }}
            />
            {st.netIngGroup}
          </label>
        )}

        {world === "services" && svc && (
          <div className="tally">
            <span className="info">endpoints {svc.endpoints_total}</span>
          </div>
        )}
        {world === "ingress" && ing && ing.classes.length > 0 && (
          <div className="tally">
            <span className="info">{ing.classes.length} class</span>
          </div>
        )}
        {world === "policies" && pol && (
          <div className="tally">
            <span className="info">k8s {pol.counts.k8s}</span>
            {pol.counts.cilium > 0 && <span className="info">cilium {pol.counts.cilium}</span>}
            {pol.counts.calico > 0 && <span className="info">calico {pol.counts.calico}</span>}
          </div>
        )}

        <div className="right">
          {/* Le `s` du TUI : la vue Secrets sait déjà décoder un certificat, celle-ci lui passe la
              main plutôt que d'en refaire une moitié. Une navigation, donc dans la barre. */}
          {world === "ingress" && (
            <button
              className="panel-toggle"
              disabled={!tlsTarget}
              title={tlsTarget ? st.netOpenSecretHelp : st.netSelectTls}
              onClick={() => tlsTarget && onOpenSecret(tlsTarget.namespace, tlsTarget.name)}
            >
              {st.netOpenSecret}
            </button>
          )}
          <SelectionBar
            keys={selectableKeys}
            checked={checked}
            onSetAll={setAll}
            onClear={clear}
            onBulkDelete={() => setBulkOpen(true)}
            st={st}
          />
          <PanelToggle open={panelOpen} onOpen={onPanelOpen} lang={lang} />
        </div>
      </div>

      <ViewBody
        tab={tab}
        record={selectedRecord}
        lang={lang}
        st={st}
        onTab={setTab}
        onNeedsAuth={onNeedsAuth}
        hasDetail={Boolean(picked)}
        onDeleted={() => {
          setSelected(null);
          void load(world);
        }}
        bulk={
          bulkOpen
            ? {
                label: st.bulkDeleteTitle,
                count: checked.size,
                node: (
                  <BulkDeletePane
                    records={[...checked]
                      .map((uid) => index.get(uid)?.row.record)
                      .filter((r): r is EventRecord => Boolean(r))}
                    lang={lang}
                    st={st}
                    onCancel={() => setBulkOpen(false)}
                    onDone={() => {
                      setBulkOpen(false);
                      setSelected(null);
                      clear();
                      void load(world);
                    }}
                    onNeedsAuth={onNeedsAuth}
                  />
                ),
              }
            : null
        }
        onBulkClose={() => setBulkOpen(false)}
      >
        {!loaded[world] ? (
          <div className="center" />
        ) : shownCount === 0 ? (
          <div className="center">
            <div className="box">
              <h2>{emptyText}</h2>
              {error && <p className="err">{error}</p>}
              {world === "policies" && pol?.error && <p className="err">{pol.error}</p>}
              <p>
                {st.emptyScope} <code>{scope || st.scopeAll}</code>
              </p>
            </div>
          </div>
        ) : world === "services" ? (
          <ServiceTable
            rows={services}
            tree={svcGroup}
            folded={folded}
            onFold={fold}
            {...common}
          />
        ) : world === "ingress" ? (
          ingGroup ? (
            <IngressTree groups={ingGroups} folded={folded} onFold={fold} {...common} />
          ) : (
            <IngressTable rows={ingresses} {...common} />
          )
        ) : (
          <PolicyTable rows={policies} {...common} />
        )}
      </ViewBody>

      <div className="statusbar">
        <span>
          {shownCount} {st.rows}
        </span>
        <span>
          {st.scopeLabel}: {scope || st.scopeAll}
        </span>
        {/* Un refus partiel voyage avec les lignes déjà lues, et se dit : « ? » dans la colonne
            ENDPOINTS, ou des Ingress sans leur classe, ne doivent pas se lire comme un constat. */}
        {world === "services" && svc?.endpoints_error && (
          <span className="warn">{st.netEndpointsUnknown.replace("{err}", svc.endpoints_error)}</span>
        )}
        {world === "ingress" && ing?.classes_error && (
          <span className="warn">{st.netClassesUnknown.replace("{err}", ing.classes_error)}</span>
        )}
        {world === "policies" && pol?.error && <span className="err">{pol.error}</span>}
        {error && <span className="err">{error}</span>}
      </div>
    </>
  );
}

interface TableProps {
  lang: Lang;
  st: Strings;
  selected: string | null;
  onSelect: (uid: string) => void;
  onOpenTab: (uid: string, tab: ObjectTab) => void;
  onNeedsAuth: (message: string) => void;
  checked: Set<string>;
  onToggleCheck: (key: string) => void;
}

/** Les attributs communs d'une ligne cliquable. */
function rowProps(uid: string, tone: string, extra: string, p: TableProps) {
  return {
    className: `tr ${extra} sev-${tone}`,
    "aria-selected": p.selected === uid,
    tabIndex: 0,
    onClick: () => p.onSelect(uid),
    onKeyDown: (e: KeyboardEvent) => {
      if (e.key === "Enter") p.onSelect(uid);
    },
  };
}

function Menu({ uid, record, p }: { uid: string; record: EventRecord; p: TableProps }) {
  return (
    <div className="cell act">
      <RowMenu
        record={record}
        lang={p.lang}
        st={p.st}
        onOpen={(t) => p.onOpenTab(uid, t)}
        onNeedsAuth={p.onNeedsAuth}
      />
    </div>
  );
}

function FoldButton({
  folded,
  empty,
  onFold,
}: {
  folded: boolean;
  empty: boolean;
  onFold: () => void;
}) {
  return (
    <button
      className="fold"
      aria-expanded={!folded}
      disabled={empty}
      onClick={(e) => {
        e.stopPropagation();
        onFold();
      }}
    >
      {empty ? "·" : folded ? "▸" : "▾"}
    </button>
  );
}

function ServiceTable({
  rows,
  tree,
  folded,
  onFold,
  ...p
}: {
  rows: ServiceRow[];
  tree: boolean;
  folded: Set<string>;
  onFold: (uid: string) => void;
} & TableProps) {
  const { st, checked, onToggleCheck } = p;
  return (
    <div className="tbl" style={cols(tree ? withoutSelTrack(SVC_COLUMNS) : SVC_COLUMNS)}>
      <div className="thead">
        <div className="tr">
          {!tree && <SelectionHead />}
          <div className="cell">NAMESPACE</div>
          <div className="cell">NAME</div>
          <div className="cell">TYPE</div>
          <div className="cell">CLUSTER-IP</div>
          <div className="cell">EXTERNAL-IP</div>
          <div className="cell">PORTS</div>
          <div className="cell">ENDPOINTS</div>
          <div className="cell">NODE</div>
          <div className="cell num">AGE</div>
          <div className="cell act" />
        </div>
      </div>
      <div className="tbody">
        {rows.map((s) => {
          const isFolded = folded.has(s.uid);
          return (
            <div className="grp" key={s.uid}>
              <div {...rowProps(s.uid, s.record.tone, tree ? "net-parent" : "", p)}>
                {!tree && (
                  <RowCheckbox
                    checked={checked.has(s.uid)}
                    onToggle={() => onToggleCheck(s.uid)}
                    label={st.selectRow}
                  />
                )}
                <div className="cell mono dim">{s.namespace}</div>
                <div className="cell id">
                  {tree && (
                    <>
                      <FoldButton
                        folded={isFolded}
                        empty={s.endpoints.length === 0}
                        onFold={() => onFold(s.uid)}
                      />
                      <TreeCheckbox
                        checked={checked.has(s.uid)}
                        onToggle={() => onToggleCheck(s.uid)}
                        label={st.selectRow}
                        st={st}
                      />
                    </>
                  )}
                  {s.name}
                </div>
                <div className="cell">{s.type_}</div>
                <div className="cell mono">{s.cluster_ip}</div>
                <div className="cell mono dim">{s.external_ip}</div>
                <div className="cell mono dim wrap">{s.ports || "—"}</div>
                <div className={`cell mono net-count ${s.endpoints_tone}`}>{s.endpoints_label}</div>
                <div className="cell" />
                <div className="cell num dim">{s.age}</div>
                <Menu uid={s.uid} record={s.record} p={p} />
              </div>
              {tree &&
                !isFolded &&
                s.endpoints.map((e) => (
                  <div key={e.uid} {...rowProps(e.uid, e.record.tone, "net-child", p)}>
                    <div className="cell" />
                    <div className="cell id nested">
                      <span className="fold-gap" />
                      <TreeCheckbox
                        checked={checked.has(e.uid)}
                        onToggle={e.addressable ? () => onToggleCheck(e.uid) : undefined}
                        label={st.selectRow}
                        st={st}
                      />
                      {e.target_name}
                    </div>
                    <div className="cell mono dim">{e.target_kind}</div>
                    <div className="cell mono">{e.address}</div>
                    <div className="cell" />
                    <div className="cell" />
                    <div className={`cell ${e.ready_tone}`}>{e.ready_label}</div>
                    <div className="cell mono dim">{e.node}</div>
                    <div className="cell" />
                    {e.addressable ? (
                      <Menu uid={e.uid} record={e.record} p={p} />
                    ) : (
                      <div className="cell act" />
                    )}
                  </div>
                ))}
            </div>
          );
        })}
      </div>
    </div>
  );
}

const ING_HEAD = ["NAMESPACE", "NAME", "CLASS/CTRL", "HOSTS", "ROUTES", "TLS", "ADDRESS"];

/** Chaque Secret dans le ton de ce qu'il tient, comme la colonne du TUI. */
function TlsCell({ row }: { row: IngressRow }) {
  if (row.tls.length === 0) return <div className="cell dim">—</div>;
  return (
    <div className="cell mono wrap">
      {row.tls.map((t, n) => (
        <Fragment key={n}>
          {n > 0 && <span className="dim">, </span>}
          <span className={`net-tls ${t.tone}`}>{t.label}</span>
        </Fragment>
      ))}
    </div>
  );
}

function IngressCells({ row }: { row: IngressRow }) {
  return (
    <>
      <div className="cell mono dim">{row.namespace}</div>
      <div className="cell id">{row.name}</div>
      <div className="cell mono dim">{row.class ?? "—"}</div>
      <div className="cell mono wrap">{row.hosts}</div>
      <div className="cell mono dim wrap">{row.rules || "—"}</div>
      <TlsCell row={row} />
      <div className="cell mono dim">{row.address}</div>
      <div className="cell num dim">{row.age}</div>
    </>
  );
}

function IngressTable({ rows, ...p }: { rows: IngressRow[] } & TableProps) {
  const { st, checked, onToggleCheck } = p;
  return (
    <div className="tbl" style={cols(ING_COLUMNS)}>
      <div className="thead">
        <div className="tr">
          <SelectionHead />
          {ING_HEAD.map((h) => (
            <div className="cell" key={h}>
              {h}
            </div>
          ))}
          <div className="cell num">AGE</div>
          <div className="cell act" />
        </div>
      </div>
      <div className="tbody">
        {rows.map((i) => (
          <div key={i.uid} {...rowProps(i.uid, i.record.tone, "", p)}>
            <RowCheckbox
              checked={checked.has(i.uid)}
              onToggle={() => onToggleCheck(i.uid)}
              label={st.selectRow}
            />
            <IngressCells row={i} />
            <Menu uid={i.uid} record={i.record} p={p} />
          </div>
        ))}
      </div>
    </div>
  );
}

function IngressTree({
  groups,
  folded,
  onFold,
  ...p
}: {
  groups: IngGroup[];
  folded: Set<string>;
  onFold: (uid: string) => void;
} & TableProps) {
  const { st, checked, onToggleCheck } = p;
  return (
    <div className="tbl" style={cols(withoutSelTrack(ING_COLUMNS))}>
      <div className="thead">
        <div className="tr">
          {ING_HEAD.map((h) => (
            <div className="cell" key={h}>
              {h}
            </div>
          ))}
          <div className="cell num">AGE</div>
          <div className="cell act" />
        </div>
      </div>
      <div className="tbody">
        {groups.map((g) => {
          // Le seau « sans classe » n'est pas un objet : il ne se replie pas, et ne se coche pas.
          const key = g.cls ? g.cls.uid : "net|no-class";
          const isFolded = g.cls ? folded.has(key) : false;
          return (
            <div className="grp" key={key}>
              {g.cls ? (
                <div {...rowProps(g.cls.uid, g.cls.record.tone, "net-parent", p)}>
                  <div className="cell" />
                  <div className="cell id">
                    <FoldButton
                      folded={isFolded}
                      empty={g.items.length === 0}
                      onFold={() => onFold(key)}
                    />
                    <TreeCheckbox
                      checked={checked.has(g.cls.uid)}
                      onToggle={() => onToggleCheck(g.cls!.uid)}
                      label={st.selectRow}
                      st={st}
                    />
                    {g.cls.name}
                    {g.cls.is_default && <span className="badge-default">{st.netDefault}</span>}
                    <span className="grp-count">{g.items.length}</span>
                  </div>
                  <div className="cell mono dim">{g.cls.controller}</div>
                  <div className="cell" />
                  <div className="cell" />
                  <div className="cell" />
                  <div className="cell" />
                  <div className="cell num dim">{g.cls.age}</div>
                  <Menu uid={g.cls.uid} record={g.cls.record} p={p} />
                </div>
              ) : (
                <div className="tr net-parent">
                  <div className="cell" />
                  <div className="cell id dim">
                    <span className="fold-gap">·</span>
                    <TreeCheckbox checked={false} label={st.selectRow} st={st} />
                    {st.netNoClass}
                    <span className="grp-count">{g.items.length}</span>
                  </div>
                  <div className="cell" />
                  <div className="cell" />
                  <div className="cell" />
                  <div className="cell" />
                  <div className="cell" />
                  <div className="cell" />
                  <div className="cell act" />
                </div>
              )}
              {!isFolded &&
                g.items.map((i) => (
                  <div key={i.uid} {...rowProps(i.uid, i.record.tone, "net-child", p)}>
                    <div className="cell mono dim">{i.namespace}</div>
                    <div className="cell id nested">
                      <span className="fold-gap" />
                      <TreeCheckbox
                        checked={checked.has(i.uid)}
                        onToggle={() => onToggleCheck(i.uid)}
                        label={st.selectRow}
                        st={st}
                      />
                      {i.name}
                    </div>
                    {/* Rangé sous sa classe, un Ingress ne la répète pas. */}
                    <div className="cell" />
                    <div className="cell mono wrap">{i.hosts}</div>
                    <div className="cell mono dim wrap">{i.rules || "—"}</div>
                    <TlsCell row={i} />
                    <div className="cell mono dim">{i.address}</div>
                    <div className="cell num dim">{i.age}</div>
                    <Menu uid={i.uid} record={i.record} p={p} />
                  </div>
                ))}
            </div>
          );
        })}
      </div>
    </div>
  );
}

function PolicyTable({ rows, ...p }: { rows: NetPolRow[] } & TableProps) {
  const { st, checked, onToggleCheck } = p;
  return (
    <div className="tbl" style={cols(POL_COLUMNS)}>
      <div className="thead">
        <div className="tr">
          <SelectionHead />
          <div className="cell">NAMESPACE</div>
          <div className="cell">NAME</div>
          <div className="cell">ENGINE</div>
          <div className="cell">TARGET</div>
          <div className="cell">TYPES</div>
          <div className="cell">INGRESS</div>
          <div className="cell">EGRESS</div>
          <div className="cell num">AGE</div>
          <div className="cell act" />
        </div>
      </div>
      <div className="tbody">
        {rows.map((r) => (
          <div key={r.uid} {...rowProps(r.uid, r.record.tone, "", p)}>
            <RowCheckbox
              checked={checked.has(r.uid)}
              onToggle={() => onToggleCheck(r.uid)}
              label={st.selectRow}
            />
            <div className="cell mono dim">{r.cluster_scoped ? st.netpolCluster : r.namespace}</div>
            <div className="cell id">{r.name}</div>
            <div className={`cell mono engine-${r.engine}`}>{r.engine_label}</div>
            <div className="cell mono">{r.target}</div>
            <div className="cell dim">{r.types || "—"}</div>
            {/* `deny` est une **bonne** nouvelle — la direction est gouvernée et rien n'y est
                autorisé — donc le vert va là et pas sur `allow-all`. */}
            <div
              className={`cell wrap ${r.ingress_tone}`}
              title={r.ingress_effect === "unknown" ? st.netpolNoVerdict : undefined}
            >
              {r.ingress}
            </div>
            <div
              className={`cell wrap ${r.egress_tone}`}
              title={r.egress_effect === "unknown" ? st.netpolNoVerdict : undefined}
            >
              {r.egress}
            </div>
            <div className="cell num dim">{r.age}</div>
            <Menu uid={r.uid} record={r.record} p={p} />
          </div>
        ))}
      </div>
    </div>
  );
}

function PickedDetail({
  picked,
  st,
  onOpenSecret,
}: {
  picked: Picked;
  st: Strings;
  onOpenSecret: (namespace: string, name: string) => void;
}) {
  switch (picked.k) {
    case "svc":
      return <ServiceDetail svc={picked.row} st={st} />;
    case "ep":
      return <EndpointDetail ep={picked.row} />;
    case "ing":
      return <IngressDetail ing={picked.row} st={st} onOpenSecret={onOpenSecret} />;
    case "cls":
      return <ClassDetail cls={picked.row} count={picked.count} st={st} />;
    case "pol":
      return <PolicyDetail policy={picked.row} st={st} />;
  }
}

function ServiceDetail({ svc, st }: { svc: ServiceRow; st: Strings }) {
  return (
    <div className="detail">
      <Line label="type" value={svc.type_} />
      <Line label="clusterIP" value={svc.cluster_ip} mono />
      <Line label={svc.external_name ? "externalName" : "externalIP"} value={svc.external_ip} mono />
      <Line
        label="ports"
        value={
          svc.port_specs.length === 0
            ? "—"
            : svc.port_specs
                .map((p) => `${p.name ? `${p.name} ` : ""}${p.port} → ${p.target}/${p.protocol}`)
                .join("\n")
        }
        mono
      />
      <Line label="endpoints" value={svc.endpoints_label} tone={svc.endpoints_tone} mono />
      {/* Qui sert ce Service, sans avoir à déplier : c'est la question qu'on vient lui poser. */}
      <div className="keys-row">
        <div className="k-col">
          <span className="k">pods</span>
        </div>
        {svc.endpoints.length === 0 ? (
          <span className="v dim">{st.netNoEndpoint}</span>
        ) : (
          <div className="v statuslines">
            {svc.endpoints.map((e) => (
              <div key={e.uid} className={`ln ${e.ready_tone}`}>
                {e.ready_label} {e.target_name} · {e.address}
                {e.node ? ` · ${e.node}` : ""}
              </div>
            ))}
          </div>
        )}
      </div>
      <Line label="age" value={svc.age} />
    </div>
  );
}

function EndpointDetail({ ep }: { ep: EndpointRow }) {
  return (
    <div className="detail">
      <Line label="Service" value={`${ep.service_namespace}/${ep.service_name}`} mono />
      <Line label={ep.target_kind} value={ep.target_name} mono />
      <Line label="address" value={ep.address} mono />
      <Line label="node" value={ep.node || "—"} mono />
      <Line label="ready" value={ep.ready_label} tone={ep.ready_tone} />
    </div>
  );
}

function IngressDetail({
  ing,
  st,
  onOpenSecret,
}: {
  ing: IngressRow;
  st: Strings;
  onOpenSecret: (namespace: string, name: string) => void;
}) {
  const secrets = [...new Set(ing.tls.flatMap((t) => (t.secret ? [t.secret] : [])))];
  const routes = routesOf(ing);
  return (
    <div className="detail">
      <Line label="ingressClassName" value={ing.class ?? "—"} mono />
      <Line label="address" value={ing.address || "—"} mono />
      <Line label="hosts" value={ing.hosts || "—"} mono />
      <Line label={st.netRoutes} value={routes.length === 0 ? "—" : routes.join("\n")} mono />
      <Line label="age" value={ing.age} />
      {/* Le bloc TLS tel que le TUI le rédige — Secret, émetteur, échéance, hosts hors SAN — et
          sous chaque nom de Secret, le saut vers la vue qui le décode. */}
      <div className="keys-row">
        <div className="k-col">
          <span className="k">TLS</span>
          {secrets.map((name) => (
            <button
              key={name}
              className="inv-pill"
              title={st.netOpenSecretHelp}
              onClick={() => onOpenSecret(ing.namespace, name)}
            >
              {st.netOpenSecret} {name}
            </button>
          ))}
        </div>
        <div className="v statuslines">
          {ing.tls_lines
            .filter((l) => l.text !== "")
            .map((l, n) => (
              <div key={n} className={`ln ${l.tone}`}>
                {l.text}
              </div>
            ))}
        </div>
      </div>
    </div>
  );
}

function ClassDetail({ cls, count, st }: { cls: IngressClassRow; count: number; st: Strings }) {
  return (
    <div className="detail">
      <Line label="controller" value={cls.controller || "—"} mono />
      <Line label={st.netDefault} value={String(cls.is_default)} />
      <Line label="Ingress" value={String(count)} />
      <Line label="age" value={cls.age} />
    </div>
  );
}

function PolicyDetail({ policy, st }: { policy: NetPolRow; st: Strings }) {
  return (
    <div className="detail">
      <Line label="kind" value={`${policy.kind} (${policy.api_version})`} mono />
      <Line label="engine" value={policy.engine_label} />
      <Line label={st.netpolTarget} value={policy.target} mono />
      <Line label="policyTypes" value={policy.types || "—"} />
      <Line label="ingress" value={policy.ingress} tone={policy.ingress_tone} />
      <Line label="egress" value={policy.egress} tone={policy.egress_tone} />
      <Line label="age" value={policy.age} />
      {/* Le refus de juger, écrit là où quelqu'un se demanderait pourquoi il n'y a pas de verdict. */}
      {policy.engine !== "k8s" && <p className="hint-note info">{st.netpolNoVerdict}</p>}
    </div>
  );
}

/** Une valeur par ligne quand elle contient des retours à la ligne : ports, routes. */
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
      <span className={`v net-lines ${mono ? "mono" : ""} ${tone ?? ""}`}>{value}</span>
    </div>
  );
}
