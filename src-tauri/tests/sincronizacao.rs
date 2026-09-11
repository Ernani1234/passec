//! Sincronizacao entre dois computadores, sem tocar na rede.
//!
//! O que a rede faz e mover bytes; o que decide se a sincronizacao presta e o
//! que acontece com esses bytes nas duas pontas. Estes testes exercitam
//! justamente essa parte: dois cofres reais, cifrados de verdade, divergindo e
//! convergindo. A camada HTTP e trocada por passar o `Vec<u8>` de um lado para
//! o outro — que e literalmente o que o GitHub faz.

use passec_lib::crypto::kdf::{KdfParams, UnlockFactors};
use passec_lib::crypto::keyfile::KeyfileMode;
use passec_lib::sync::merge;
use passec_lib::vault::model::{EntryKind, VaultEntry};
use passec_lib::vault::{UnlockedVault, VaultError};

fn params() -> KdfParams {
    KdfParams {
        memory_kib: 16 * 1024,
        iterations: 2,
        parallelism: 1,
    }
}

fn fatores(senha: &str) -> UnlockFactors<'_> {
    UnlockFactors {
        password: senha,
        keyfile_digest: None,
    }
}

fn agora() -> i64 {
    passec_lib::vault::model::now_millis()
}

fn item(titulo: &str, senha: &str, quando: i64) -> VaultEntry {
    let mut e = VaultEntry::new(EntryKind::Login, titulo.into());
    e.password = senha.into();
    e.created_at = quando;
    e.updated_at = quando;
    e
}

const SENHA: &str = "senha-mestra-de-verdade-comprida";

/// O cenario que a sincronizacao existe para resolver.
///
/// Dois computadores partem do mesmo cofre, cada um mexe no seu, e o encontro
/// precisa juntar os dois trabalhos em vez de um apagar o outro.
#[test]
fn dois_computadores_convergem_sem_perder_trabalho() {
    let t = agora();

    // --- PC de casa cria o cofre e o envia --------------------------------
    let mut casa = UnlockedVault::create(&fatores(SENHA), KeyfileMode::None, params()).unwrap();
    casa.body.entries.push(item("Banco", "senha-do-banco", t));
    casa.body.entries.push(item("Email", "senha-do-email", t));
    let subiu = casa.serialize().unwrap();

    // --- PC do trabalho adota o mesmo arquivo -----------------------------
    let mut trabalho = UnlockedVault::open(&subiu, &fatores(SENHA)).unwrap();
    assert_eq!(trabalho.body.entries.len(), 2);

    // --- os dois divergem --------------------------------------------------
    // Em casa: troca a senha do banco.
    let alvo = casa.body.entries[0].id.clone();
    {
        let e = casa.body.find_mut(&alvo).unwrap();
        e.password = "senha-nova-do-banco".into();
        e.updated_at = t + 5_000;
    }
    // No trabalho: cadastra um item novo e apaga o email.
    let email = trabalho.body.entries[1].id.clone();
    trabalho.body.entries.push(item("GitHub", "senha-do-github", t + 3_000));
    trabalho.body.remove(&email).unwrap();

    // --- o trabalho envia, a casa baixa e funde ----------------------------
    let do_trabalho = trabalho.serialize().unwrap();
    let corpo_remoto = casa.open_sibling_body(&do_trabalho).unwrap();
    let r = merge::merge_into(&mut casa.body, &corpo_remoto, agora());

    assert_eq!(casa.body.entries.len(), 2, "esperava Banco e GitHub");
    assert_eq!(r.added, 1, "o GitHub veio do outro computador");
    assert_eq!(r.removed, 1, "o Email foi apagado la");
    assert_eq!(r.kept_local, 1, "a edicao do Banco era mais nova aqui");

    // A edicao feita em casa sobreviveu.
    let banco = casa.body.find(&alvo).unwrap();
    assert_eq!(banco.password, "senha-nova-do-banco");
    // O item criado no trabalho chegou.
    assert!(casa.body.entries.iter().any(|e| e.title == "GitHub"));
    // O apagado nao voltou.
    assert!(casa.body.find(&email).is_none());

    // --- a casa devolve; o trabalho tambem converge ------------------------
    let de_volta = casa.serialize().unwrap();
    let corpo_casa = trabalho.open_sibling_body(&de_volta).unwrap();
    merge::merge_into(&mut trabalho.body, &corpo_casa, agora());

    let mut titulos_casa: Vec<&str> = casa.body.entries.iter().map(|e| e.title.as_str()).collect();
    let mut titulos_trab: Vec<&str> = trabalho
        .body
        .entries
        .iter()
        .map(|e| e.title.as_str())
        .collect();
    titulos_casa.sort_unstable();
    titulos_trab.sort_unstable();

    assert_eq!(titulos_casa, titulos_trab, "os dois lados nao convergiram");
    assert_eq!(
        trabalho.body.find(&alvo).unwrap().password,
        "senha-nova-do-banco"
    );
}

/// A decisao que molda o produto inteiro, escrita como teste.
///
/// Dois cofres criados separadamente com a **mesma senha** nao sao o mesmo
/// cofre: cada criacao sorteia salt e VaultKey proprios. E por isso que o
/// computador novo precisa *adotar* o arquivo remoto, e nao criar o seu.
#[test]
fn cofres_criados_separadamente_nao_se_fundem() {
    let a = UnlockedVault::create(&fatores(SENHA), KeyfileMode::None, params()).unwrap();

    let mut b = UnlockedVault::create(&fatores(SENHA), KeyfileMode::None, params()).unwrap();
    b.body.entries.push(item("Algo", "senha", agora()));
    let bytes_b = b.serialize().unwrap();

    // Mesma senha, cofre diferente: a fusao e recusada de forma explicita.
    match a.open_sibling_body(&bytes_b) {
        Err(VaultError::ForeignVault) => {}
        Err(outro) => panic!("erro inesperado: {outro}"),
        Ok(_) => panic!("dois cofres independentes nao deveriam se abrir entre si"),
    }

    // Mas a senha abre o arquivo pelo caminho normal — que e o que a adocao faz.
    let adotado = UnlockedVault::open(&bytes_b, &fatores(SENHA)).unwrap();
    assert_eq!(adotado.body.entries.len(), 1);
}

/// Copias do mesmo cofre continuam se entendendo depois de varias gravacoes.
///
/// Cada `serialize` sorteia nonces novos, entao os bytes nunca se repetem; o
/// que precisa permanecer estavel e o salt, que identifica a copia.
#[test]
fn copias_do_mesmo_cofre_se_reconhecem_apos_varias_gravacoes() {
    let mut original =
        UnlockedVault::create(&fatores(SENHA), KeyfileMode::None, params()).unwrap();
    original.body.entries.push(item("Item", "senha", agora()));

    let primeira = original.serialize().unwrap();
    let mut copia = UnlockedVault::open(&primeira, &fatores(SENHA)).unwrap();

    for volta in 0..5 {
        copia.body.entries.push(item(&format!("Item {volta}"), "x", agora()));
        let bytes = copia.serialize().unwrap();

        // Bytes sempre diferentes...
        assert_ne!(bytes, primeira);
        // ...mas a outra copia continua conseguindo ler.
        let corpo = original
            .open_sibling_body(&bytes)
            .unwrap_or_else(|e| panic!("volta {volta}: {e}"));
        merge::merge_into(&mut original.body, &corpo, agora());
    }

    assert_eq!(original.body.entries.len(), 6);
    assert_eq!(original.salt_hex(), copia.salt_hex());
}

/// Trocar a senha mestra num computador muda o salt, e a outra copia passa a
/// nao reconhecer o arquivo — precisa da senha nova.
#[test]
fn troca_de_senha_exige_reautenticacao_da_outra_copia() {
    let mut a = UnlockedVault::create(&fatores(SENHA), KeyfileMode::None, params()).unwrap();
    a.body.entries.push(item("Item", "senha", agora()));
    let bytes = a.serialize().unwrap();

    let b = UnlockedVault::open(&bytes, &fatores(SENHA)).unwrap();

    // A troca sorteia salt novo.
    a.change_master(&fatores("uma-senha-mestra-nova-comprida"), KeyfileMode::None)
        .unwrap();
    let depois = a.serialize().unwrap();

    assert!(matches!(
        b.open_sibling_body(&depois),
        Err(VaultError::ForeignVault)
    ));

    // Com a senha nova, abre normalmente.
    assert!(UnlockedVault::open(&depois, &fatores("uma-senha-mestra-nova-comprida")).is_ok());
}

/// Sincronizar sem ter mexido em nada nao pode inventar mudanca.
#[test]
fn sincronizar_sem_alteracoes_e_inocuo() {
    let mut a = UnlockedVault::create(&fatores(SENHA), KeyfileMode::None, params()).unwrap();
    a.body.entries.push(item("Banco", "senha", agora()));

    let bytes = a.serialize().unwrap();
    let corpo = a.open_sibling_body(&bytes).unwrap();
    let r = merge::merge_into(&mut a.body, &corpo, agora());

    assert_eq!(r.added, 0);
    assert_eq!(r.updated, 0);
    assert_eq!(r.removed, 0);
    assert_eq!(a.body.entries.len(), 1);
}
