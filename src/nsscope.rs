//! La portée namespace d'une session : tout le cluster, ou une liste de namespaces tapée à la suite
//! (`:wl ns1 ns2 ns3`).
//!
//! Une portée à plusieurs namespaces se lit par une liste **par namespace**, en parallèle, jamais par
//! une liste cluster-wide filtrée ensuite : celui qui n'a des droits que sur quelques namespaces — un
//! membre de projet Rancher — n'a pas le droit de lister tout le cluster, et c'est précisément lui que
//! cette portée sert. Un seul namespace garde le chemin d'avant, un seul appel.

use std::fmt::Debug;

use kube::api::{Api, ApiResource, DynamicObject, ListParams};
use kube::core::NamespaceResourceScope;
use kube::{Client, Resource};
use serde::de::DeserializeOwned;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum NsScope {
    #[default]
    All,
    /// Jamais vide, sans doublon, dans l'ordre où les namespaces ont été tapés.
    Only(Vec<String>),
}

impl NsScope {
    pub fn one(ns: impl Into<String>) -> Self {
        NsScope::Only(vec![ns.into()])
    }

    /// Les mots séparés par des espaces ou des virgules. `all`, `*` ou `0` parmi eux l'emportent :
    /// demander tout le cluster et un namespace à la fois ne peut vouloir dire que tout le cluster.
    pub fn parse(arg: &str) -> Self {
        let mut names: Vec<String> = Vec::new();
        for w in arg.split(|c: char| c.is_whitespace() || c == ',').filter(|w| !w.is_empty()) {
            if matches!(w, "all" | "*" | "0") {
                return NsScope::All;
            }
            if !names.iter().any(|n| n == w) {
                names.push(w.to_string());
            }
        }
        if names.is_empty() { NsScope::All } else { NsScope::Only(names) }
    }

    pub fn is_all(&self) -> bool {
        matches!(self, NsScope::All)
    }

    /// Vide pour tout le cluster.
    pub fn names(&self) -> &[String] {
        match self {
            NsScope::All => &[],
            NsScope::Only(n) => n,
        }
    }

    pub fn contains(&self, ns: &str) -> bool {
        match self {
            NsScope::All => true,
            NsScope::Only(n) => n.iter().any(|x| x == ns),
        }
    }

    pub fn single(&self) -> Option<&str> {
        match self.names() {
            [one] => Some(one),
            _ => None,
        }
    }

    /// `all`, ou les namespaces joints par des virgules.
    pub fn label(&self) -> String {
        match self {
            NsScope::All => "all".to_string(),
            NsScope::Only(n) => n.join(","),
        }
    }

    /// Le libellé du bandeau, qui partage sa ligne avec le contexte : au-delà de trois namespaces,
    /// les deux premiers et le compte du reste.
    pub fn short_label(&self) -> String {
        match self.names() {
            n if n.len() > 3 => format!("{},{} +{}", n[0], n[1], n.len() - 2),
            _ => self.label(),
        }
    }

    /// `ns` ajouté s'il n'y est pas, retiré s'il y est. `None` quand le retirer viderait la portée :
    /// une portée vide voudrait dire tout le cluster, ce que `0` dit déjà sans surprise.
    pub fn toggled(&self, ns: &str) -> Option<NsScope> {
        match self {
            NsScope::All => Some(NsScope::one(ns)),
            NsScope::Only(n) if n.iter().any(|x| x == ns) => {
                let rest: Vec<String> = n.iter().filter(|x| *x != ns).cloned().collect();
                if rest.is_empty() { None } else { Some(NsScope::Only(rest)) }
            }
            NsScope::Only(n) => {
                let mut more = n.clone();
                more.push(ns.to_string());
                Some(NsScope::Only(more))
            }
        }
    }
}

impl From<Option<String>> for NsScope {
    fn from(ns: Option<String>) -> Self {
        ns.map_or(NsScope::All, NsScope::one)
    }
}

impl From<Option<&str>> for NsScope {
    fn from(ns: Option<&str>) -> Self {
        ns.map_or(NsScope::All, NsScope::one)
    }
}

/// Les `Api` qui couvrent la portée : une seule cluster-wide, ou une par namespace.
pub fn apis<K>(scope: &NsScope, api: impl Fn(Option<&str>) -> Api<K>) -> Vec<Api<K>> {
    match scope {
        NsScope::All => vec![api(None)],
        NsScope::Only(n) => n.iter().map(|ns| api(Some(ns))).collect(),
    }
}

/// Liste `api` sur toute la portée. Un namespace refusé fait échouer l'ensemble : une liste qui
/// tairait un namespace demandé dirait « rien ici » là où la vérité est « pas le droit de regarder ».
pub async fn list_in<K>(
    scope: &NsScope,
    lp: &ListParams,
    api: impl Fn(Option<&str>) -> Api<K>,
) -> kube::Result<Vec<K>>
where
    K: Clone + DeserializeOwned + Debug,
{
    let lists = futures::future::try_join_all(apis(scope, api).into_iter().map(|a| async move {
        a.list(lp).await
    }))
    .await?;
    Ok(lists.into_iter().flat_map(|l| l.items).collect())
}

pub async fn list<K>(client: &Client, scope: &NsScope, lp: &ListParams) -> kube::Result<Vec<K>>
where
    K: Resource<Scope = NamespaceResourceScope, DynamicType = ()> + Clone + DeserializeOwned + Debug,
{
    list_in(scope, lp, |ns| match ns {
        Some(ns) => Api::namespaced(client.clone(), ns),
        None => Api::all(client.clone()),
    })
    .await
}

pub async fn list_dyn(
    client: &Client,
    scope: &NsScope,
    ar: &ApiResource,
    lp: &ListParams,
) -> kube::Result<Vec<DynamicObject>> {
    list_in(scope, lp, |ns| match ns {
        Some(ns) => Api::namespaced_with(client.clone(), ns, ar),
        None => Api::all_with(client.clone(), ar),
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_splits_on_spaces_and_commas() {
        assert_eq!(
            NsScope::parse("a b,c  a"),
            NsScope::Only(vec!["a".into(), "b".into(), "c".into()])
        );
    }

    #[test]
    fn parse_all_wins() {
        assert_eq!(NsScope::parse("a all"), NsScope::All);
        assert_eq!(NsScope::parse("*"), NsScope::All);
        assert_eq!(NsScope::parse("0"), NsScope::All);
        assert_eq!(NsScope::parse("  "), NsScope::All);
    }

    #[test]
    fn toggle_adds_removes_and_refuses_to_empty() {
        let s = NsScope::one("a");
        let s2 = s.toggled("b").unwrap();
        assert_eq!(s2.names(), ["a".to_string(), "b".to_string()]);
        assert_eq!(s2.toggled("a").unwrap(), NsScope::one("b"));
        assert_eq!(s.toggled("a"), None);
        assert_eq!(NsScope::All.toggled("a"), Some(NsScope::one("a")));
    }

    #[test]
    fn short_label_folds_past_three() {
        assert_eq!(NsScope::parse("a b c").short_label(), "a,b,c");
        assert_eq!(NsScope::parse("a b c d e").short_label(), "a,b +3");
        assert_eq!(NsScope::All.short_label(), "all");
    }
}
