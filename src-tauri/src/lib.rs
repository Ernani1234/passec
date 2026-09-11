//! PASSEC — cofre de credenciais com transporte acustico.
//!
//! Camadas, de baixo para cima:
//!
//! * [`crypto`] — Argon2id, XChaCha20-Poly1305, derivacao de subchaves.
//! * [`vault`]  — modelo dos itens e o formato do arquivo.
//! * [`audio`]  — FEC, modem OFDM e esteganografia.
//! * [`auth`]   — TOTP e Windows Hello.
//! * [`generator`] — criacao e avaliacao de senhas.
//! * [`sync`]  — fusao item a item e o cofre num repositorio do GitHub.
//! * [`guard`] — modo "em guarda" para a pausa curta.
//! * [`session`], [`commands`] — estado da aplicacao e a fronteira com a interface.

pub mod audio;
pub mod auth;
pub mod commands;
pub mod crypto;
pub mod generator;
pub mod guard;
pub mod session;
pub mod sync;
pub mod util;
pub mod vault;

/// Ponto de entrada compartilhado entre o executavel e o empacotamento mobile.
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(session::AppState::default())
        .invoke_handler(commands::handlers())
        .setup(|app| {
            commands::spawn_autolock_watcher(app.handle().clone());
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("falha ao iniciar o PASSEC");
}
