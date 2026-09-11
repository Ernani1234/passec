//! Fusao de dois cofres que divergiram.
//!
//! O caso normal da sincronizacao nao e "um lado mudou". E os dois lados terem
//! mudado desde o ultimo encontro: voce editou uma senha no computador de casa
//! e cadastrou outra coisa no do trabalho. Sobrescrever um arquivo com o outro
//! — que e o que acontece se voce so jogar o cofre numa pasta compartilhada —
//! perde trabalho silenciosamente.
//!
//! Aqui a fusao e **por item**, nao por arquivo. Cada entrada tem `id` estavel
//! e `updated_at`, entao a regra e simples: para cada id, vence a versao
//! editada por ultimo.
//!
//! # Por que exclusoes precisam de lapide
//!
//! Apagar nao pode ser apenas sumir da lista. Se o computador A apaga um item e
//! o B ainda o tem, a regra "vence quem tem" o ressuscitaria — e o usuario
//! apagaria de novo, e de novo. A lapide registra *quando* a exclusao
//! aconteceu, e ela compete em pe de igualdade com a edicao: apagar as 10h
//! vence editar as 9h, e editar as 11h vence apagar as 10h.
//!
//! # O limite honesto desta abordagem
//!
//! O relogio de cada maquina e a arbitragem. Se um computador estiver com a
//! hora muito errada, ele vence disputas que nao deveria. Resolver isso de
//! verdade exigiria relogios vetoriais e um modelo de conflito explicito na
//! interface — trabalho que so se paga em edicao concorrente frequente, o que
//! nao e o caso de um cofre pessoal.

use crate::vault::model::{Tombstone, VaultBody, VaultEntry};

/// O que a fusao fez, para a interface relatar.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct MergeReport {
    /// Itens que vieram do outro lado e nao existiam aqui.
    pub added: usize,
    /// Itens em que a versao do outro lado era mais nova.
    pub updated: usize,
    /// Itens apagados no outro lado e removidos daqui.
    pub removed: usize,
    /// Itens em que a versao local prevaleceu.
    pub kept_local: usize,
    pub total: usize,
}

fn mais_recente(a: Option<&VaultEntry>, b: Option<&VaultEntry>) -> Option<VaultEntry> {
    match (a, b) {
        (Some(x), Some(y)) => {
            Some(if y.updated_at > x.updated_at { y.clone() } else { x.clone() })
        }
        (Some(x), None) => Some(x.clone()),
        (None, Some(y)) => Some(y.clone()),
        (None, None) => None,
    }
}

fn lapide_de(body: &VaultBody, id: &str) -> Option<i64> {
    body.deleted.iter().find(|t| t.id == id).map(|t| t.at)
}

/// Funde `remote` dentro de `local`, item a item.
///
/// A configuracao de sincronizacao local e preservada: ela guarda o token e o
/// `sha` desta maquina, que nao devem vir do outro lado.
pub fn merge_into(local: &mut VaultBody, remote: &VaultBody, agora: i64) -> MergeReport {
    let mut report = MergeReport::default();

    // Todos os ids que aparecem de qualquer forma nos dois lados.
    let mut ids: Vec<String> = Vec::new();
    for e in local.entries.iter().chain(remote.entries.iter()) {
        if !ids.contains(&e.id) {
            ids.push(e.id.clone());
        }
    }
    for t in local.deleted.iter().chain(remote.deleted.iter()) {
        if !ids.contains(&t.id) {
            ids.push(t.id.clone());
        }
    }

    let mut resultado: Vec<VaultEntry> = Vec::new();

    for id in &ids {
        let aqui = local.entries.iter().find(|e| &e.id == id);
        let la = remote.entries.iter().find(|e| &e.id == id);

        let tinha_aqui = aqui.is_some();
        let local_era_mais_nova = match (aqui, la) {
            (Some(x), Some(y)) => x.updated_at >= y.updated_at,
            (Some(_), None) => true,
            _ => false,
        };

        let vencedora = mais_recente(aqui, la);

        // A lapide mais recente dos dois lados compete com a edicao vencedora.
        let lapide = [lapide_de(local, id), lapide_de(remote, id)]
            .into_iter()
            .flatten()
            .max();

        // `None` aqui significa "este id nao sobrevive": ou a lapide venceu a
        // edicao, ou nao havia entrada nenhuma dos dois lados.
        let sobrevivente = match (&vencedora, lapide) {
            (Some(e), Some(quando)) if quando >= e.updated_at => None,
            (Some(e), _) => Some(e.clone()),
            (None, _) => None,
        };

        match sobrevivente {
            Some(e) => {
                if !tinha_aqui {
                    report.added += 1;
                } else if local_era_mais_nova {
                    report.kept_local += 1;
                } else {
                    report.updated += 1;
                }
                resultado.push(e);
            }
            None => {
                if tinha_aqui {
                    report.removed += 1;
                }
            }
        }
    }

    // Uniao das lapides, guardando a data mais recente de cada id.
    let mut lapides: Vec<Tombstone> = Vec::new();
    for t in local.deleted.iter().chain(remote.deleted.iter()) {
        match lapides.iter_mut().find(|x| x.id == t.id) {
            Some(existente) => existente.at = existente.at.max(t.at),
            None => lapides.push(t.clone()),
        }
    }

    // Um item vivo nao precisa de lapide: se a edicao venceu, a marca de
    // exclusao ja perdeu e so ocuparia espaco.
    lapides.retain(|t| !resultado.iter().any(|e| e.id == t.id));

    local.entries = resultado;
    local.deleted = lapides;
    local.prune_tombstones(agora);

    report.total = local.entries.len();
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::model::EntryKind;

    /// Origem da linha do tempo dos testes.
    ///
    /// Os instantes escritos nos testes sao **deslocamentos** a partir daqui, e
    /// nao datas absolutas. Sem isso, escrever `100` significaria janeiro de
    /// 1970, e a poda por idade descartaria toda lapide antes da asserção — foi
    /// exatamente o que aconteceu quando os testes usavam numeros crus.
    const T0: i64 = 1_800_000_000_000;
    const AGORA: i64 = T0 + 10_000;

    fn entrada(id: &str, titulo: &str, offset: i64) -> VaultEntry {
        let mut e = VaultEntry::new(EntryKind::Login, titulo.into());
        e.id = id.into();
        e.created_at = T0 + offset;
        e.updated_at = T0 + offset;
        e
    }

    fn corpo(entradas: Vec<VaultEntry>, lapides: Vec<(&str, i64)>) -> VaultBody {
        VaultBody {
            entries: entradas,
            deleted: lapides
                .into_iter()
                .map(|(id, offset)| Tombstone {
                    id: id.into(),
                    at: T0 + offset,
                })
                .collect(),
            sync: None,
        }
    }

    #[test]
    fn junta_itens_criados_dos_dois_lados() {
        let mut local = corpo(vec![entrada("a", "Banco", 100)], vec![]);
        let remoto = corpo(vec![entrada("b", "GitHub", 200)], vec![]);

        let r = merge_into(&mut local, &remoto, AGORA);

        assert_eq!(local.entries.len(), 2);
        assert_eq!(r.added, 1);
        assert_eq!(r.kept_local, 1);
        assert!(local.entries.iter().any(|e| e.id == "a"));
        assert!(local.entries.iter().any(|e| e.id == "b"));
    }

    #[test]
    fn vence_a_edicao_mais_recente() {
        let mut local = corpo(vec![entrada("a", "versao antiga", 100)], vec![]);
        let remoto = corpo(vec![entrada("a", "versao nova", 500)], vec![]);

        let r = merge_into(&mut local, &remoto, AGORA);

        assert_eq!(local.entries.len(), 1);
        assert_eq!(local.entries[0].title, "versao nova");
        assert_eq!(r.updated, 1);
    }

    #[test]
    fn edicao_local_mais_nova_prevalece() {
        let mut local = corpo(vec![entrada("a", "minha versao", 900)], vec![]);
        let remoto = corpo(vec![entrada("a", "versao do outro pc", 300)], vec![]);

        let r = merge_into(&mut local, &remoto, AGORA);

        assert_eq!(local.entries[0].title, "minha versao");
        assert_eq!(r.kept_local, 1);
        assert_eq!(r.updated, 0);
    }

    /// O motivo de existir lapide: sem ela, este teste ressuscitaria o item.
    #[test]
    fn item_apagado_no_outro_pc_nao_volta() {
        let mut local = corpo(vec![entrada("a", "Banco", 100)], vec![]);
        let remoto = corpo(vec![], vec![("a", 500)]);

        let r = merge_into(&mut local, &remoto, AGORA);

        assert!(local.entries.is_empty(), "o item apagado voltou");
        assert_eq!(r.removed, 1);
        // A lapide sobrevive, senao o proximo merge com um terceiro computador
        // ressuscitaria de novo.
        assert_eq!(local.deleted.len(), 1);
    }

    #[test]
    fn exclusao_local_nao_e_desfeita_pelo_remoto() {
        let mut local = corpo(vec![], vec![("a", 500)]);
        let remoto = corpo(vec![entrada("a", "Banco", 100)], vec![]);

        merge_into(&mut local, &remoto, AGORA);
        assert!(local.entries.is_empty());
    }

    /// Recriar um item depois de apaga-lo tem que valer.
    #[test]
    fn edicao_posterior_a_exclusao_vence() {
        let mut local = corpo(vec![], vec![("a", 300)]);
        let remoto = corpo(vec![entrada("a", "recriado", 800)], vec![]);

        let r = merge_into(&mut local, &remoto, AGORA);

        assert_eq!(local.entries.len(), 1);
        assert_eq!(local.entries[0].title, "recriado");
        assert_eq!(r.added, 1);
        // A lapide perdeu e nao deve mais ocupar espaco.
        assert!(local.deleted.is_empty());
    }

    #[test]
    fn exclusao_posterior_a_edicao_vence() {
        let mut local = corpo(vec![entrada("a", "editado", 300)], vec![]);
        let remoto = corpo(vec![], vec![("a", 800)]);

        merge_into(&mut local, &remoto, AGORA);
        assert!(local.entries.is_empty());
    }

    #[test]
    fn lapides_velhas_sao_descartadas() {
        use crate::vault::model::TOMBSTONE_TTL_MS;
        // Deslocamentos: a "velha" fica alem do prazo, a "nova" dentro dele.
        let antiga = -TOMBSTONE_TTL_MS;
        let recente = -1000;

        let mut local = corpo(vec![], vec![("velha", antiga), ("nova", recente)]);
        let remoto = corpo(vec![], vec![]);

        merge_into(&mut local, &remoto, AGORA);

        assert_eq!(local.deleted.len(), 1);
        assert_eq!(local.deleted[0].id, "nova");
    }

    /// Fundir duas vezes nao pode mudar o resultado da primeira.
    #[test]
    fn merge_e_idempotente() {
        let mut local = corpo(vec![entrada("a", "Banco", 100)], vec![]);
        let remoto = corpo(vec![entrada("b", "GitHub", 200)], vec![("c", 300)]);

        merge_into(&mut local, &remoto, AGORA);
        let primeira: Vec<String> = local.entries.iter().map(|e| e.id.clone()).collect();

        merge_into(&mut local, &remoto, AGORA);
        let segunda: Vec<String> = local.entries.iter().map(|e| e.id.clone()).collect();

        assert_eq!(primeira, segunda);
    }

    /// A ordem nao pode mudar o conjunto final.
    #[test]
    fn merge_e_comutativo_no_conteudo() {
        let a = corpo(vec![entrada("x", "de A", 400)], vec![("y", 100)]);
        let b = corpo(vec![entrada("y", "de B", 50), entrada("z", "so B", 700)], vec![]);

        let mut ab = a.clone();
        merge_into(&mut ab, &b, AGORA);
        let mut ba = b.clone();
        merge_into(&mut ba, &a, AGORA);

        let mut ids_ab: Vec<String> = ab.entries.iter().map(|e| e.id.clone()).collect();
        let mut ids_ba: Vec<String> = ba.entries.iter().map(|e| e.id.clone()).collect();
        ids_ab.sort();
        ids_ba.sort();

        assert_eq!(ids_ab, ids_ba);
        // "y" foi apagado em A depois de criado em B, entao nao sobrevive.
        assert!(!ids_ab.contains(&"y".to_string()));
    }

    #[test]
    fn config_de_sincronizacao_local_e_preservada() {
        use crate::vault::model::SyncConfig;
        let mut local = corpo(vec![], vec![]);
        local.sync = Some(SyncConfig {
            owner: "eu".into(),
            repo: "cofre".into(),
            path: "passec.vault".into(),
            token: "token-desta-maquina".into(),
            last_sha: "abc".into(),
            last_sync: 1,
        });

        let mut remoto = corpo(vec![], vec![]);
        remoto.sync = Some(SyncConfig {
            owner: "outro".into(),
            repo: "outro".into(),
            path: "outro".into(),
            token: "token-do-outro-pc".into(),
            last_sha: "zzz".into(),
            last_sync: 2,
        });

        merge_into(&mut local, &remoto, AGORA);

        let cfg = local.sync.as_ref().unwrap();
        assert_eq!(cfg.token, "token-desta-maquina");
        assert_eq!(cfg.last_sha, "abc");
    }

    #[test]
    fn cofre_vazio_dos_dois_lados_nao_quebra() {
        let mut local = corpo(vec![], vec![]);
        let r = merge_into(&mut local, &corpo(vec![], vec![]), AGORA);
        assert_eq!(r.total, 0);
        assert!(local.entries.is_empty());
    }
}
