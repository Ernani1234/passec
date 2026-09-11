//! Sincronizacao do cofre entre computadores.
//!
//! # O modelo: um cofre, varias copias
//!
//! Duas copias do mesmo cofre compartilham salt e VaultKey. Isso tem uma
//! consequencia que decide o desenho inteiro: **criar um cofre novo no segundo
//! computador com a mesma senha nao produz o mesmo cofre**. Cada criacao sorteia
//! seu proprio salt e sua propria VaultKey, e os dois arquivos ficam
//! mutuamente ilegiveis.
//!
//! Por isso o segundo computador *adota* o arquivo remoto ([`adopt`]) em vez de
//! criar o seu. A partir dai os dois falam a mesma lingua e o merge acontece no
//! nivel dos itens.
//!
//! # O ciclo
//!
//! ```text
//!   1. baixa a versao remota
//!   2. abre com as chaves da sessao
//!   3. funde item a item (ver merge.rs)
//!   4. grava o resultado remoto, citando o sha que leu
//!   5. grava o resultado local
//! ```
//!
//! O passo 4 cita o `sha`: se outro computador escreveu nesse meio tempo, o
//! GitHub recusa e a operacao vira um erro de conflito em vez de apagar o
//! trabalho alheio. Quem chama reage refazendo o ciclo, que agora le a versao
//! nova.

pub mod github;
pub mod merge;

pub use github::{GithubError, Repo};
pub use merge::MergeReport;

use crate::vault::model::{now_millis, SyncConfig};
use crate::vault::{UnlockedVault, VaultError};

#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    #[error(transparent)]
    Github(#[from] GithubError),

    #[error(transparent)]
    Vault(#[from] VaultError),

    #[error("a sincronizacao nao esta configurada neste cofre")]
    NotConfigured,

    #[error("ainda nao existe cofre neste repositorio")]
    NoRemote,
}

/// Resultado de uma sincronizacao, para a interface relatar.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SyncOutcome {
    pub report: MergeReport,
    /// Havia versao remota para fundir.
    pub had_remote: bool,
    pub synced_at: i64,
    /// Itens que estao na nuvem mas ficaram ocultos nesta maquina.
    pub archived: usize,
}

pub fn repo_from(cfg: &SyncConfig) -> Repo {
    Repo {
        owner: cfg.owner.clone(),
        repo: cfg.repo.clone(),
        path: cfg.path.clone(),
        token: cfg.token.clone(),
    }
}

/// Mensagem de commit.
///
/// Deliberadamente sem conteudo: o repositorio e privado, mas a lista de
/// commits e um canal lateral barato. "47 itens" ja diz ao observador o
/// tamanho do cofre e quando ele cresce — informacao que nao precisa estar la.
fn commit_message() -> String {
    "PASSEC: atualizacao do cofre".to_string()
}

/// Executa o ciclo completo de sincronizacao.
///
/// A nuvem recebe **a uniao completa**; o disco local recebe a uniao menos os
/// itens que esta maquina escolheu ocultar. Essa assimetria e o que permite
/// levar o cofre para um computador de trabalho carregando so o que interessa
/// ali, sem que os demais itens deixem de existir.
pub fn sync(vault: &mut UnlockedVault) -> Result<SyncOutcome, SyncError> {
    let cfg = vault.body.sync.clone().ok_or(SyncError::NotConfigured)?;
    let repo = repo_from(&cfg);

    let remoto = github::fetch(&repo)?;
    let agora = now_millis();

    // `completo` parte do corpo local — e portanto ja carrega a configuracao,
    // a combinacao e a lista de ocultos desta maquina, que o merge nao toca.
    let mut completo = vault.body.clone();
    let (report, sha_base) = match &remoto {
        // Primeira subida: nao ha o que fundir.
        None => (MergeReport::default(), None),
        Some(arquivo) => {
            let corpo_remoto = vault.open_sibling_body(&arquivo.bytes)?;
            let r = merge::merge_into(&mut completo, &corpo_remoto, agora);
            (r, Some(arquivo.sha.clone()))
        }
    };

    // Sobe tudo, inclusive o que esta maquina nao quer ter. `serialize_for_remote`
    // remove os campos que sao so daqui.
    let bytes = vault.serialize_for_remote(&completo)?;
    let novo_sha = github::put(&repo, &bytes, sha_base.as_deref(), &commit_message())?;

    // O que fica no disco: a uniao menos os ocultos.
    let ocultos = completo.archived_here.clone();
    let antes = completo.entries.len();
    completo.entries.retain(|e| !ocultos.iter().any(|a| a == &e.id));
    let archived = antes - completo.entries.len();

    vault.body = completo;
    if let Some(c) = vault.body.sync.as_mut() {
        c.last_sha = novo_sha;
        c.last_sync = agora;
    }

    Ok(SyncOutcome {
        report,
        had_remote: remoto.is_some(),
        synced_at: agora,
        archived,
    })
}

/// Baixa o cofre remoto sem abri-lo.
///
/// Usado na adocao, quando ainda nao ha chaves nesta maquina.
pub fn fetch_remote(repo: &Repo) -> Result<Vec<u8>, SyncError> {
    match github::fetch(repo)? {
        Some(f) => Ok(f.bytes),
        None => Err(SyncError::NoRemote),
    }
}

/// Sobe o cofre local sem fundir, sobrescrevendo o remoto.
///
/// So deve ser oferecido quando o usuario decidiu conscientemente descartar a
/// versao remota — por isso nao cita o `sha` anterior.
pub fn force_push(vault: &mut UnlockedVault) -> Result<String, SyncError> {
    let cfg = vault.body.sync.clone().ok_or(SyncError::NotConfigured)?;
    let repo = repo_from(&cfg);

    // Precisa do sha atual: o GitHub exige a versao anterior para substituir um
    // arquivo existente, mesmo quando a intencao e sobrescrever.
    let atual = github::fetch(&repo)?.map(|f| f.sha);

    let bytes = {
        let corpo = vault.body.clone();
        vault.serialize_for_remote(&corpo)?
    };
    let sha = github::put(&repo, &bytes, atual.as_deref(), &commit_message())?;

    if let Some(c) = vault.body.sync.as_mut() {
        c.last_sha = sha.clone();
        c.last_sync = now_millis();
    }
    Ok(sha)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> SyncConfig {
        SyncConfig {
            owner: "Ernani1234".into(),
            repo: "passec-vault".into(),
            path: "passec.vault".into(),
            token: "ghp_exemplo".into(),
            last_sha: "abc123".into(),
            last_sync: 42,
        }
    }

    #[test]
    fn converte_config_em_repositorio() {
        let r = repo_from(&cfg());
        assert_eq!(r.owner, "Ernani1234");
        assert_eq!(r.repo, "passec-vault");
        assert_eq!(r.path, "passec.vault");
        assert!(r.validate().is_ok());
    }

    /// A mensagem de commit fica visivel na lista de commits do repositorio;
    /// ela nao pode carregar nada sobre o conteudo.
    #[test]
    fn mensagem_de_commit_nao_vaza_conteudo() {
        let m = commit_message();
        assert!(!m.chars().any(|c| c.is_ascii_digit()), "mensagem: {m}");
        assert!(!m.to_lowercase().contains("item"));
        assert!(!m.to_lowercase().contains("senha"));
    }

    #[test]
    fn sem_configuracao_o_erro_e_claro() {
        use crate::crypto::kdf::{KdfParams, UnlockFactors};
        use crate::crypto::keyfile::KeyfileMode;

        let mut v = UnlockedVault::create(
            &UnlockFactors {
                password: "uma-senha-bem-comprida-aqui",
                keyfile_digest: None,
            },
            KeyfileMode::None,
            KdfParams {
                memory_kib: 16 * 1024,
                iterations: 2,
                parallelism: 1,
            },
        )
        .unwrap();

        // Sem rede: a falta de configuracao e detectada antes de qualquer
        // chamada HTTP.
        assert!(matches!(sync(&mut v), Err(SyncError::NotConfigured)));
        assert!(matches!(force_push(&mut v), Err(SyncError::NotConfigured)));
    }
}
