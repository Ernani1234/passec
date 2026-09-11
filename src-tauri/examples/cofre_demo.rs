//! Gera um cofre de demonstracao para as capturas de tela do README.
//!
//! Andaime de desenvolvimento: nao faz parte do aplicativo. Recebe o caminho de
//! destino e uma senha, e grava um cofre com itens ficticios.
//!
//! ```text
//! cargo run --example cofre_demo -- <caminho> <senha>
//! ```

use passec_lib::crypto::kdf::{KdfParams, UnlockFactors};
use passec_lib::crypto::keyfile::KeyfileMode;
use passec_lib::vault::model::{EntryKind, VaultEntry};
use passec_lib::vault::UnlockedVault;

fn item(kind: EntryKind, titulo: &str, user: &str, senha: &str, url: &str, tags: &[&str]) -> VaultEntry {
    let mut e = VaultEntry::new(kind, titulo.into());
    e.username = user.into();
    e.password = senha.into();
    e.url = url.into();
    e.tags = tags.iter().map(|t| t.to_string()).collect();
    e
}

fn main() {
    let mut args = std::env::args().skip(1);
    let destino = args.next().expect("uso: cofre_demo <caminho> <senha>");
    let senha = args.next().expect("uso: cofre_demo <caminho> <senha>");

    let fatores = UnlockFactors {
        password: &senha,
        keyfile_digest: None,
    };

    let mut v = UnlockedVault::create(&fatores, KeyfileMode::None, KdfParams::default())
        .expect("criar cofre");

    let mut banco = item(
        EntryKind::Login,
        "Banco Cooperativo",
        "ernani.neto",
        "7#pR2vLq-Wk9!zTm4XdA",
        "https://banco.exemplo.com",
        &["financeiro", "critico"],
    );
    banco.favorite = true;
    banco.totp_secret = Some("JBSWY3DPEHPK3PXP".into());
    v.body.entries.push(banco);

    v.body.entries.push(item(
        EntryKind::Login,
        "GitHub",
        "Ernani1234",
        "Qz8!mNv3-Lp7wRt2YbEs",
        "https://github.com",
        &["dev"],
    ));

    v.body.entries.push(item(
        EntryKind::Wifi,
        "Wi-Fi de casa",
        "PASSEC-2G",
        "rede-domestica-4471",
        "",
        &["casa"],
    ));

    v.body.entries.push(item(
        EntryKind::Card,
        "Cartao de credito",
        "ERNANI NETO",
        "4111 1111 1111 1111",
        "",
        &["financeiro"],
    ));

    let mut nota = VaultEntry::new(EntryKind::Note, "Frase de recuperacao".into());
    nota.notes = "doze palavras guardadas fora deste computador".into();
    nota.tags = vec!["backup".into()];
    v.body.entries.push(nota);

    v.body.entries.push(item(
        EntryKind::Key,
        "Chave SSH do servidor",
        "deploy",
        "ed25519-chave-privada-ficticia",
        "servidor.exemplo.com",
        &["infra"],
    ));

    let bytes = v.serialize().expect("serializar");
    if let Some(pai) = std::path::Path::new(&destino).parent() {
        std::fs::create_dir_all(pai).expect("criar diretorio");
    }
    std::fs::write(&destino, &bytes).expect("gravar");
    println!("cofre de demonstracao: {destino} ({} bytes)", bytes.len());
}
