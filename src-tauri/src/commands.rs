//! Fronteira entre a interface e o nucleo.
//!
//! Duas regras valem para tudo neste arquivo:
//!
//! 1. **Segredo so atravessa o IPC quando foi pedido nominalmente.** A lista de
//!    itens devolve resumos sem senha; a senha sai apenas em [`entry_get`],
//!    para um id especifico.
//! 2. **Toda mutacao grava em disco na hora.** Nao existe "salvar" na
//!    interface: um item editado ja esta cifrado no arquivo quando a chamada
//!    retorna, entao uma queda de energia nao custa trabalho.
//!
//! Os comandos sao sincronos de proposito. O trabalho pesado — o Argon2id de
//! 256 MiB — leva cerca de um segundo e acontece so em abertura e criacao de
//! cofre, momentos em que a interface ja esta mostrando progresso e nao ha
//! nada util para fazer em paralelo.

use std::fs;
use std::path::{Path, PathBuf};

use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager, State};

use crate::audio::{self, Robustness, TransportReport};
use crate::auth::{hello, totp};
use crate::crypto::{
    kdf::{KdfParams, UnlockFactors},
    keyfile::{self, KeyfileMode},
};
use crate::generator::{self, PasswordOptions, Strength};
use crate::session::AppState;
use crate::sync;
use crate::vault::{self, EntrySummary, UnlockedVault, VaultEntry, VaultMeta};

const VAULT_FILENAME: &str = "passec.vault";

/// Erro que atravessa o IPC. Serializa como string simples porque a interface
/// so precisa exibir a mensagem; detalhe estruturado aqui viraria superficie de
/// vazamento sem ganho.
#[derive(Debug)]
pub struct CmdError(String);

impl Serialize for CmdError {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}

impl<E: std::fmt::Display> From<E> for CmdError {
    fn from(e: E) -> Self {
        Self(e.to_string())
    }
}

type Cmd<T> = Result<T, CmdError>;

fn err(msg: impl Into<String>) -> CmdError {
    CmdError(msg.into())
}

// --- arquivos --------------------------------------------------------------

fn vault_path(app: &AppHandle) -> Cmd<PathBuf> {
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|e| err(format!("nao foi possivel localizar a pasta de dados: {e}")))?;
    fs::create_dir_all(&dir)?;
    Ok(dir.join(VAULT_FILENAME))
}

/// Grava de forma atomica: escreve num temporario e renomeia por cima.
///
/// Escrever direto no arquivo final deixa uma janela em que uma queda de
/// energia corromperia o cofre inteiro — e um cofre corrompido nao tem
/// recurso. O rename e atomico no NTFS, entao o arquivo antigo so desaparece
/// quando o novo esta inteiro no disco.
fn write_atomic(path: &Path, bytes: &[u8]) -> Cmd<()> {
    let tmp = path.with_extension("vault.tmp");
    fs::write(&tmp, bytes)?;
    fs::rename(&tmp, path)?;
    Ok(())
}

/// Persiste o cofre em memoria.
fn persist(state: &AppState, app: &AppHandle) -> Cmd<()> {
    let path = match state.vault_path() {
        Some(p) => p,
        None => vault_path(app)?,
    };
    let bytes = state.with_vault(|v| v.serialize())??;
    write_atomic(&path, &bytes)
}

fn read_vault_file(app: &AppHandle) -> Cmd<Vec<u8>> {
    let path = vault_path(app)?;
    fs::read(&path).map_err(|_| err("nenhum cofre encontrado nesta maquina"))
}

// --- keyfile ---------------------------------------------------------------

/// Calcula o digest do keyfile conforme o modo configurado.
fn keyfile_digest(path: &str, mode: KeyfileMode) -> Cmd<Option<[u8; 32]>> {
    match mode {
        KeyfileMode::None => Ok(None),
        KeyfileMode::Generated => {
            let bytes = fs::read(path)?;
            // Demodula: o digest vem do payload, nao das amostras, por isso o
            // arquivo tolera reamostragem e recompressao.
            let (payload, _) = audio::from_wav(&bytes)?;
            Ok(Some(keyfile::digest_payload(&payload)))
        }
        KeyfileMode::RawFile => {
            let bytes = fs::read(path)?;
            let pcm = audio::wav::decode(&bytes)?;
            Ok(Some(keyfile::digest_raw_pcm(&pcm.samples)))
        }
    }
}

fn factors<'a>(password: &'a str, digest: Option<[u8; 32]>) -> UnlockFactors<'a> {
    UnlockFactors {
        password,
        keyfile_digest: digest,
    }
}

// --- status ----------------------------------------------------------------

#[derive(Serialize)]
pub struct VaultStatus {
    /// Existe arquivo de cofre nesta maquina.
    pub exists: bool,
    pub unlocked: bool,
    pub meta: Option<VaultMeta>,
    pub hello_available: bool,
}

#[tauri::command]
pub fn vault_status(app: AppHandle, state: State<'_, AppState>) -> Cmd<VaultStatus> {
    let bytes = vault_path(&app).ok().and_then(|p| fs::read(p).ok());
    let meta = bytes.as_deref().and_then(|b| vault::peek(b).ok());

    Ok(VaultStatus {
        exists: bytes.is_some(),
        unlocked: state.is_unlocked(),
        meta,
        hello_available: hello::is_available(),
    })
}

#[derive(Serialize)]
pub struct SessionInfo {
    pub unlocked: bool,
    pub seconds_until_lock: Option<u64>,
    pub autolock_secs: u64,
}

#[tauri::command]
pub fn session_info(state: State<'_, AppState>) -> SessionInfo {
    SessionInfo {
        unlocked: state.is_unlocked(),
        seconds_until_lock: state.seconds_until_lock(),
        autolock_secs: state.autolock_secs(),
    }
}

/// Renova o relogio de inatividade. A interface chama a cada interacao real do
/// usuario — nao num timer, senao o auto-lock nunca dispararia.
#[tauri::command]
pub fn session_touch(state: State<'_, AppState>) {
    state.touch();
}

#[tauri::command]
pub fn session_set_autolock(state: State<'_, AppState>, secs: u64) -> u64 {
    state.set_autolock_secs(secs);
    state.autolock_secs()
}

// --- ciclo do cofre --------------------------------------------------------

#[tauri::command]
pub fn vault_create(
    app: AppHandle,
    state: State<'_, AppState>,
    password: String,
    keyfile_mode: KeyfileMode,
    keyfile_path: Option<String>,
) -> Cmd<VaultMeta> {
    let path = vault_path(&app)?;
    if path.exists() {
        return Err(err(
            "ja existe um cofre nesta maquina; mova o arquivo antes de criar outro",
        ));
    }

    let strength = generator::estimate_strength(&password);
    if strength.label == "weak" {
        return Err(err(format!(
            "senha mestra fraca ({}). Ela e a unica coisa entre um atacante e tudo que voce guardar aqui.",
            strength.warnings.join(", ")
        )));
    }

    let digest = match (keyfile_mode, keyfile_path.as_deref()) {
        (KeyfileMode::None, _) => None,
        (mode, Some(p)) => keyfile_digest(p, mode)?,
        (_, None) => return Err(err("o modo escolhido exige um arquivo de keyfile")),
    };

    let mut vault = UnlockedVault::create(
        &factors(&password, digest),
        keyfile_mode,
        KdfParams::default(),
    )?;
    let bytes = vault.serialize()?;
    write_atomic(&path, &bytes)?;

    let meta = vault.meta();
    state.set_vault(vault, path);
    state.record_success();
    Ok(meta)
}

#[tauri::command]
pub fn vault_unlock(
    app: AppHandle,
    state: State<'_, AppState>,
    password: String,
    keyfile_path: Option<String>,
    totp_code: Option<String>,
) -> Cmd<VaultMeta> {
    state.check_throttle()?;

    let bytes = read_vault_file(&app)?;
    let meta = vault::peek(&bytes)?;

    // Pede o que falta antes de gastar um segundo de Argon2id.
    if meta.keyfile_mode.requires_file() && keyfile_path.is_none() {
        return Err(err("este cofre exige o keyfile de audio"));
    }
    if meta.totp_enabled && totp_code.is_none() {
        return Err(err("este cofre exige o codigo TOTP"));
    }

    let digest = match keyfile_path.as_deref() {
        Some(p) => keyfile_digest(p, meta.keyfile_mode)?,
        None => None,
    };

    let vault = match UnlockedVault::open(&bytes, &factors(&password, digest)) {
        Ok(v) => v,
        Err(e) => {
            state.record_failure();
            return Err(e.into());
        }
    };

    // O TOTP so pode ser conferido depois de abrir, porque o segredo mora
    // dentro do cofre. Se falhar aqui, o cofre aberto e descartado sem nunca
    // chegar ao estado da aplicacao.
    if meta.totp_enabled {
        let segredo = vault
            .totp_secret()?
            .ok_or_else(|| err("cofre marcado com TOTP mas sem segredo gravado"))?;
        let agora = unix_now();
        let code = totp_code.unwrap_or_default();

        match totp::verify(&segredo, &code, agora)? {
            Some(step) if state.consume_totp_step(step) => {}
            Some(_) => {
                state.record_failure();
                return Err(err("este codigo TOTP ja foi usado; aguarde o proximo"));
            }
            None => {
                state.record_failure();
                return Err(err("codigo TOTP incorreto"));
            }
        }
    }

    let meta = vault.meta();
    state.set_vault(vault, vault_path(&app)?);
    state.record_success();
    Ok(meta)
}

#[tauri::command]
pub fn vault_unlock_hello(app: AppHandle, state: State<'_, AppState>) -> Cmd<VaultMeta> {
    state.check_throttle()?;

    let bytes = read_vault_file(&app)?;
    let meta = vault::peek(&bytes)?;
    if !meta.hello_enabled {
        return Err(err("o Windows Hello nao esta cadastrado para este cofre"));
    }

    // Lemos o blob sem abrir o cofre: ele fica em claro no arquivo e so
    // entrega a VaultKey a quem passar pelo gesto biometrico.
    let blob = {
        let parsed = vault::peek(&bytes)?;
        let _ = parsed;
        hello_blob_from_file(&bytes)?
    };

    let vault_key = match hello::unlock(&blob) {
        Ok(k) => k,
        Err(e) => {
            state.record_failure();
            return Err(e.into());
        }
    };

    let vault = UnlockedVault::open_with_vault_key(&bytes, vault_key)?;
    let meta = vault.meta();
    state.set_vault(vault, vault_path(&app)?);
    state.record_success();
    Ok(meta)
}

/// Extrai o blob do Hello direto do arquivo, sem chave nenhuma.
fn hello_blob_from_file(bytes: &[u8]) -> Cmd<Vec<u8>> {
    use crate::util::read_chunk;
    let mut cursor = 8; // pula o magic
    read_chunk(bytes, &mut cursor).ok_or_else(|| err("cofre malformado"))?; // core
    read_chunk(bytes, &mut cursor).ok_or_else(|| err("cofre malformado"))?; // wrapped
    read_chunk(bytes, &mut cursor).ok_or_else(|| err("cofre malformado"))?; // totp
    let blob = read_chunk(bytes, &mut cursor).ok_or_else(|| err("cofre malformado"))?;
    if blob.is_empty() {
        return Err(err("nenhum cadastro do Windows Hello neste cofre"));
    }
    Ok(blob.to_vec())
}

#[tauri::command]
pub fn vault_lock(state: State<'_, AppState>) -> bool {
    state.lock()
}

#[tauri::command]
pub fn master_change(
    app: AppHandle,
    state: State<'_, AppState>,
    new_password: String,
    keyfile_mode: KeyfileMode,
    keyfile_path: Option<String>,
) -> Cmd<()> {
    let strength = generator::estimate_strength(&new_password);
    if strength.label == "weak" {
        return Err(err(format!(
            "senha mestra fraca ({})",
            strength.warnings.join(", ")
        )));
    }

    let digest = match (keyfile_mode, keyfile_path.as_deref()) {
        (KeyfileMode::None, _) => None,
        (mode, Some(p)) => keyfile_digest(p, mode)?,
        (_, None) => return Err(err("o modo escolhido exige um arquivo de keyfile")),
    };

    state.with_vault(|v| v.change_master(&factors(&new_password, digest), keyfile_mode))??;
    persist(&state, &app)
}

// --- entradas --------------------------------------------------------------

#[tauri::command]
pub fn entries_list(state: State<'_, AppState>, query: Option<String>) -> Cmd<Vec<EntrySummary>> {
    let termo = query.unwrap_or_default().trim().to_lowercase();

    let mut lista = state.with_vault(|v| {
        v.body
            .entries
            .iter()
            .filter(|e| {
                if termo.is_empty() {
                    return true;
                }
                // A busca cobre so campos nao secretos: procurar dentro de
                // senhas permitiria confirmar um palpite pelo resultado.
                e.title.to_lowercase().contains(&termo)
                    || e.username.to_lowercase().contains(&termo)
                    || e.url.to_lowercase().contains(&termo)
                    || e.tags.iter().any(|t| t.to_lowercase().contains(&termo))
            })
            .map(|e| e.summary())
            .collect::<Vec<_>>()
    })?;

    lista.sort_by(|a, b| {
        b.favorite
            .cmp(&a.favorite)
            .then_with(|| a.title.to_lowercase().cmp(&b.title.to_lowercase()))
    });
    Ok(lista)
}

#[tauri::command]
pub fn entry_get(state: State<'_, AppState>, id: String) -> Cmd<VaultEntry> {
    state
        .with_vault(|v| v.body.find(&id).cloned())?
        .ok_or_else(|| err("item nao encontrado"))
}

#[tauri::command]
pub fn entry_save(
    app: AppHandle,
    state: State<'_, AppState>,
    mut entry: VaultEntry,
) -> Cmd<String> {
    if entry.title.trim().is_empty() {
        return Err(err("o item precisa de um titulo"));
    }
    // Valida o segredo TOTP na hora de salvar: descobrir que esta errado so na
    // hora de usar seria descobrir tarde demais.
    if let Some(secret) = entry.totp_secret.as_deref().filter(|s| !s.trim().is_empty()) {
        totp::code_at(secret, unix_now())
            .map_err(|_| err("o segredo TOTP deste item nao e um Base32 valido"))?;
    } else {
        entry.totp_secret = None;
    }

    entry.updated_at = vault::model::now_millis();

    let id = state.with_vault(|v| {
        match v.body.find_mut(&entry.id) {
            Some(existente) => {
                let criado = existente.created_at;
                *existente = entry.clone();
                existente.created_at = criado;
            }
            None => {
                let mut nova = entry.clone();
                if nova.id.trim().is_empty() {
                    nova.id = vault::model::new_id();
                }
                nova.created_at = vault::model::now_millis();
                v.body.entries.push(nova);
            }
        }
        // Reencontra para devolver o id definitivo (novo item ganhou um).
        v.body
            .entries
            .last()
            .map(|e| e.id.clone())
            .unwrap_or_default()
    })?;

    let id = if entry.id.trim().is_empty() {
        id
    } else {
        entry.id.clone()
    };

    persist(&state, &app)?;
    Ok(id)
}

#[tauri::command]
pub fn entry_delete(app: AppHandle, state: State<'_, AppState>, id: String) -> Cmd<()> {
    let removida = state.with_vault(|v| v.body.remove(&id).is_some())?;
    if !removida {
        return Err(err("item nao encontrado"));
    }
    persist(&state, &app)
}

#[derive(Serialize)]
pub struct TotpCode {
    pub code: String,
    pub seconds_remaining: u64,
}

/// Codigo TOTP *do item guardado* (o 2FA do site), nao o do cofre.
#[tauri::command]
pub fn entry_totp_code(state: State<'_, AppState>, id: String) -> Cmd<TotpCode> {
    let secret = state
        .with_vault(|v| v.body.find(&id).and_then(|e| e.totp_secret.clone()))?
        .ok_or_else(|| err("este item nao tem 2FA configurado"))?;

    let agora = unix_now();
    Ok(TotpCode {
        code: totp::code_at(&secret, agora)?,
        seconds_remaining: totp::seconds_remaining(agora),
    })
}

// --- gerador ---------------------------------------------------------------

#[derive(Serialize)]
pub struct GeneratedPassword {
    pub password: String,
    pub entropy_bits: f64,
}

#[tauri::command]
pub fn password_generate(options: PasswordOptions) -> Cmd<GeneratedPassword> {
    let senha = generator::generate(&options)?;
    Ok(GeneratedPassword {
        password: senha.to_string(),
        entropy_bits: generator::entropy_bits(&options),
    })
}

#[tauri::command]
pub fn password_strength(password: String) -> Strength {
    generator::estimate_strength(&password)
}

// --- TOTP do cofre ---------------------------------------------------------

#[derive(Serialize)]
pub struct TotpSetup {
    pub secret: String,
    pub uri: String,
    pub qr_svg: String,
}

/// Sorteia um segredo e devolve o QR. Nada e gravado ate [`totp_enable`]
/// confirmar que o usuario conseguiu ler o codigo — cadastrar antes da
/// confirmacao trancaria o cofre atras de um autenticador que talvez nao tenha
/// recebido o segredo.
#[tauri::command]
pub fn totp_setup_begin() -> Cmd<TotpSetup> {
    let secret = totp::generate_secret()?;
    let uri = totp::provisioning_uri(&secret, "cofre");
    let qr_svg = totp::qr_svg(&uri)?;
    Ok(TotpSetup {
        secret,
        uri,
        qr_svg,
    })
}

#[tauri::command]
pub fn totp_enable(
    app: AppHandle,
    state: State<'_, AppState>,
    secret: String,
    code: String,
) -> Cmd<()> {
    if totp::verify(&secret, &code, unix_now())?.is_none() {
        return Err(err(
            "o codigo nao confere — confira se o autenticador leu o QR corretamente",
        ));
    }
    state.with_vault(|v| v.set_totp_secret(&secret))??;
    persist(&state, &app)
}

#[tauri::command]
pub fn totp_disable(app: AppHandle, state: State<'_, AppState>) -> Cmd<()> {
    state.with_vault(|v| v.disable_totp())?;
    persist(&state, &app)
}

// --- Windows Hello ---------------------------------------------------------

#[tauri::command]
pub fn hello_status(state: State<'_, AppState>) -> Cmd<bool> {
    let _ = state;
    Ok(hello::is_available())
}

#[tauri::command]
pub fn hello_enroll(app: AppHandle, state: State<'_, AppState>) -> Cmd<()> {
    let vault_key = state.with_vault(|v| v.vault_key_copy())?;
    let blob = hello::enroll(&vault_key)?;
    state.with_vault(|v| v.set_hello_blob(blob))?;
    persist(&state, &app)
}

#[tauri::command]
pub fn hello_disable(app: AppHandle, state: State<'_, AppState>) -> Cmd<()> {
    state.with_vault(|v| v.disable_hello())?;
    persist(&state, &app)
}

// --- transporte acustico ---------------------------------------------------

fn robustness_from(s: &str) -> Robustness {
    match s {
        "airborne" => Robustness::Airborne,
        _ => Robustness::Digital,
    }
}

#[derive(Serialize)]
pub struct AudioExportResult {
    pub path: String,
    pub bytes: usize,
    pub duration_secs: f32,
}

/// Exporta o cofre inteiro como "fita": o arquivo `.vault` completo, modulado.
///
/// O que vai para o WAV e exatamente o arquivo de disco — ja cifrado, ja
/// autenticado, ja protegido pelo Argon2id. Restaurar exige a mesma senha
/// mestra de sempre, entao a fita pode ser guardada num lugar que o cofre nao
/// poderia.
#[tauri::command]
pub fn audio_export_vault(
    app: AppHandle,
    state: State<'_, AppState>,
    dest_path: String,
    robustness: String,
) -> Cmd<AudioExportResult> {
    // Serializa o estado atual em vez de ler o disco: garante que a fita
    // contenha ate a ultima edicao.
    let bytes = state.with_vault(|v| v.serialize())??;
    let _ = &app;

    let wav = audio::to_wav(&bytes, robustness_from(&robustness))?;
    fs::write(&dest_path, &wav)?;

    let pcm_len = wav.len().saturating_sub(44) / 2;
    Ok(AudioExportResult {
        path: dest_path,
        bytes: wav.len(),
        duration_secs: pcm_len as f32 / audio::wav::SAMPLE_RATE as f32,
    })
}

#[derive(Serialize)]
pub struct AudioImportResult {
    pub report: TransportReport,
    pub entries: usize,
}

/// Restaura um cofre a partir de uma fita.
///
/// Grava por cima do cofre local, por isso exige que a senha mestra abra a
/// fita primeiro: sem essa prova, um WAV qualquer conseguiria destruir o cofre
/// existente.
#[tauri::command]
pub fn audio_import_vault(
    app: AppHandle,
    state: State<'_, AppState>,
    source_path: String,
    password: String,
    keyfile_path: Option<String>,
) -> Cmd<AudioImportResult> {
    let wav = fs::read(&source_path)?;
    let (bytes, report) = audio::from_wav(&wav)?;

    let meta = vault::peek(&bytes)?;
    let digest = match keyfile_path.as_deref() {
        Some(p) => keyfile_digest(p, meta.keyfile_mode)?,
        None if meta.keyfile_mode.requires_file() => {
            return Err(err("a fita exige o keyfile de audio correspondente"))
        }
        None => None,
    };

    let vault = UnlockedVault::open(&bytes, &factors(&password, digest))?;
    let entries = vault.body.entries.len();

    let path = vault_path(&app)?;
    write_atomic(&path, &bytes)?;
    state.set_vault(vault, path);
    state.record_success();

    Ok(AudioImportResult { report, entries })
}

/// Exporta uma credencial avulsa num WAV curto, protegido por senha propria.
///
/// A senha e separada da senha mestra de proposito: o arquivo vai circular
/// (mandar para outra maquina, guardar num pendrive) e nao deve carregar o
/// segredo que abre o cofre inteiro.
#[tauri::command]
pub fn audio_export_entry(
    state: State<'_, AppState>,
    id: String,
    dest_path: String,
    password: String,
    robustness: String,
) -> Cmd<AudioExportResult> {
    if generator::estimate_strength(&password).label == "weak" {
        return Err(err("escolha uma senha mais forte para proteger este audio"));
    }

    let entry = state
        .with_vault(|v| v.body.find(&id).cloned())?
        .ok_or_else(|| err("item nao encontrado"))?;

    // Reaproveita o formato do cofre para um cofre de um item so: mesma
    // criptografia, mesmo codigo testado, nenhum formato novo para revisar.
    let mut mini = UnlockedVault::create(
        &factors(&password, None),
        KeyfileMode::None,
        KdfParams::default(),
    )?;
    mini.body.entries.push(entry);
    let bytes = mini.serialize()?;

    let wav = audio::to_wav(&bytes, robustness_from(&robustness))?;
    fs::write(&dest_path, &wav)?;

    let pcm_len = wav.len().saturating_sub(44) / 2;
    Ok(AudioExportResult {
        path: dest_path,
        bytes: wav.len(),
        duration_secs: pcm_len as f32 / audio::wav::SAMPLE_RATE as f32,
    })
}

#[derive(Serialize)]
pub struct EntryImportResult {
    pub report: TransportReport,
    pub title: String,
    pub id: String,
}

#[tauri::command]
pub fn audio_import_entry(
    app: AppHandle,
    state: State<'_, AppState>,
    source_path: String,
    password: String,
) -> Cmd<EntryImportResult> {
    let wav = fs::read(&source_path)?;
    let (bytes, report) = audio::from_wav(&wav)?;

    let mini = UnlockedVault::open(&bytes, &factors(&password, None))?;
    let mut entry = mini
        .body
        .entries
        .first()
        .cloned()
        .ok_or_else(|| err("o audio nao contem nenhum item"))?;

    // Id novo: importar duas vezes tem que gerar dois itens, nao sobrescrever
    // silenciosamente um item existente que por acaso tenha o mesmo id.
    entry.id = vault::model::new_id();
    let title = entry.title.clone();
    let id = entry.id.clone();

    state.with_vault(|v| v.body.entries.push(entry))?;
    persist(&state, &app)?;

    Ok(EntryImportResult { report, title, id })
}

/// Gera um keyfile de audio novo e devolve o payload para o cofre passar a
/// exigi-lo.
#[derive(Serialize)]
pub struct KeyfileResult {
    pub path: String,
    pub duration_secs: f32,
}

#[tauri::command]
pub fn keyfile_generate(dest_path: String) -> Cmd<KeyfileResult> {
    let payload = keyfile::new_payload()?;
    // Sempre "airborne": um keyfile e para durar anos e passar por copias,
    // conversoes e backups. A paridade extra custa menos de um segundo de som.
    let wav = audio::to_wav(&payload, Robustness::Airborne)?;
    fs::write(&dest_path, &wav)?;

    let pcm_len = wav.len().saturating_sub(44) / 2;
    Ok(KeyfileResult {
        path: dest_path,
        duration_secs: pcm_len as f32 / audio::wav::SAMPLE_RATE as f32,
    })
}

// --- esteganografia --------------------------------------------------------

fn stego_key(password: &str) -> [u8; 32] {
    // BLAKE3 rapido em vez de Argon2id: esta chave so decide *onde* os bits
    // ficam. O que esta escondido e o arquivo do cofre, que continua protegido
    // pelo Argon2id de 256 MiB. Quem adivinhar esta senha encontra ciphertext.
    blake3::derive_key("passec.stego.key.v1", password.as_bytes())
}

#[derive(Serialize)]
pub struct StegoResult {
    pub path: String,
    pub payload_bytes: usize,
    pub capacity_bytes: usize,
}

#[tauri::command]
pub fn stego_hide(
    state: State<'_, AppState>,
    carrier_path: String,
    dest_path: String,
    password: String,
) -> Cmd<StegoResult> {
    let carrier_bytes = fs::read(&carrier_path)?;
    let pcm = audio::wav::decode(&carrier_bytes)?;

    let payload = state.with_vault(|v| v.serialize())??;
    let capacity = audio::stego::capacity_bytes(pcm.samples.len());

    let escondido = audio::stego::embed(&pcm.samples, &payload, &stego_key(&password))?;
    // Preserva a taxa original: reescrever a 48 kHz mudaria o tom da musica.
    let wav = audio::wav::encode_with_rate(&escondido, pcm.sample_rate)?;
    fs::write(&dest_path, &wav)?;

    Ok(StegoResult {
        path: dest_path,
        payload_bytes: payload.len(),
        capacity_bytes: capacity,
    })
}

#[tauri::command]
pub fn stego_reveal(
    app: AppHandle,
    state: State<'_, AppState>,
    source_path: String,
    stego_password: String,
    master_password: String,
) -> Cmd<AudioImportResult> {
    let bytes = fs::read(&source_path)?;
    let pcm = audio::wav::decode(&bytes)?;
    let payload = audio::stego::extract(&pcm.samples, &stego_key(&stego_password))?;

    let meta = vault::peek(&payload)?;
    if meta.keyfile_mode.requires_file() {
        return Err(err(
            "o cofre escondido exige keyfile; restaure-o pelo import de fita",
        ));
    }

    let vault = UnlockedVault::open(&payload, &factors(&master_password, None))?;
    let entries = vault.body.entries.len();

    let path = vault_path(&app)?;
    write_atomic(&path, &payload)?;
    state.set_vault(vault, path);
    state.record_success();

    Ok(AudioImportResult {
        report: TransportReport {
            blocks_total: 0,
            blocks_corrupt: 0,
            blocks_recovered: 0,
            phase_error_deg: 0.0,
            pristine: true,
        },
        entries,
    })
}

/// Capacidade de um carregador, para a interface avisar antes de tentar.
#[derive(Serialize)]
pub struct CarrierInfo {
    pub capacity_bytes: usize,
    pub duration_secs: f32,
    pub needed_bytes: usize,
    pub fits: bool,
}

#[tauri::command]
pub fn stego_inspect_carrier(
    state: State<'_, AppState>,
    carrier_path: String,
) -> Cmd<CarrierInfo> {
    let bytes = fs::read(&carrier_path)?;
    let pcm = audio::wav::decode(&bytes)?;
    let capacity = audio::stego::capacity_bytes(pcm.samples.len());
    let needed = state.with_vault(|v| v.serialize())??.len();

    Ok(CarrierInfo {
        capacity_bytes: capacity,
        duration_secs: pcm.samples.len() as f32 / pcm.sample_rate.max(1) as f32,
        needed_bytes: needed,
        fits: needed <= capacity,
    })
}

/// Estimativa de duracao antes de gerar, para a interface avisar que vai sair
/// um audio de tres minutos.
#[tauri::command]
pub fn audio_estimate(state: State<'_, AppState>, robustness: String) -> Cmd<f32> {
    let bytes = state.with_vault(|v| v.serialize())??;
    Ok(audio::estimate_duration_secs(
        bytes.len(),
        robustness_from(&robustness),
    ))
}

// --- sincronizacao ---------------------------------------------------------

#[derive(Serialize)]
pub struct SyncStatus {
    pub configured: bool,
    pub owner: String,
    pub repo: String,
    pub path: String,
    pub last_sync: i64,
    /// Itens que existem na nuvem mas nao neste computador.
    pub archived_here: usize,
}

#[tauri::command]
pub fn sync_status(state: State<'_, AppState>) -> Cmd<SyncStatus> {
    let (cfg, ocultos) =
        state.with_vault(|v| (v.body.sync.clone(), v.body.archived_here.len()))?;

    Ok(match cfg {
        Some(c) => SyncStatus {
            configured: true,
            owner: c.owner.clone(),
            repo: c.repo.clone(),
            path: c.path.clone(),
            last_sync: c.last_sync,
            archived_here: ocultos,
        },
        None => SyncStatus {
            configured: false,
            owner: String::new(),
            repo: String::new(),
            path: String::new(),
            last_sync: 0,
            archived_here: ocultos,
        },
    })
}

#[derive(Serialize)]
pub struct SyncConfigureResult {
    /// `false` significa repositorio publico — a interface avisa em destaque.
    pub private: bool,
    pub outcome: sync::SyncOutcome,
}

/// Liga a sincronizacao neste cofre e faz o primeiro ciclo.
#[tauri::command]
pub fn sync_configure(
    app: AppHandle,
    state: State<'_, AppState>,
    owner: String,
    repo: String,
    path: String,
    token: String,
) -> Cmd<SyncConfigureResult> {
    let alvo = sync::Repo {
        owner: owner.trim().to_string(),
        repo: repo.trim().to_string(),
        path: {
            let p = path.trim();
            if p.is_empty() { "passec.vault".to_string() } else { p.to_string() }
        },
        token: token.trim().to_string(),
    };

    // Confere acesso antes de gravar qualquer coisa: e melhor falhar aqui, com
    // o formulario ainda aberto, do que gravar uma configuracao que nao funciona.
    let private = sync::github::check_access(&alvo)?;

    state.with_vault(|v| {
        v.body.sync = Some(crate::vault::model::SyncConfig {
            owner: alvo.owner.clone(),
            repo: alvo.repo.clone(),
            path: alvo.path.clone(),
            token: alvo.token.clone(),
            last_sha: String::new(),
            last_sync: 0,
        });
    })?;

    let outcome = state.with_vault(sync::sync)??;
    persist(&state, &app)?;

    Ok(SyncConfigureResult { private, outcome })
}

#[tauri::command]
pub fn sync_now(app: AppHandle, state: State<'_, AppState>) -> Cmd<sync::SyncOutcome> {
    let outcome = state.with_vault(sync::sync)??;
    persist(&state, &app)?;
    Ok(outcome)
}

/// Sobe o cofre local por cima do remoto, sem fundir.
#[tauri::command]
pub fn sync_force_push(app: AppHandle, state: State<'_, AppState>) -> Cmd<()> {
    state.with_vault(sync::force_push)??;
    persist(&state, &app)
}

#[tauri::command]
pub fn sync_disable(app: AppHandle, state: State<'_, AppState>) -> Cmd<()> {
    state.with_vault(|v| v.body.sync = None)?;
    persist(&state, &app)
}

#[derive(Serialize)]
pub struct AdoptResult {
    pub entries: usize,
    pub meta: VaultMeta,
}

/// Traz um cofre da nuvem para este computador.
///
/// E o caminho de um PC novo: nao existe cofre local, e criar um com a mesma
/// senha **nao** produziria o mesmo cofre — salt e VaultKey sao sorteados na
/// criacao. Aqui o arquivo remoto e adotado como esta, e so entao a senha
/// mestra o abre.
/// Parametros da adocao, agrupados.
///
/// A senha mestra passa por aqui, entao o struct se zera ao sair de escopo em
/// vez de deixar a copia na pilha para o alocador reciclar.
#[derive(serde::Deserialize, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
pub struct AdoptRequest {
    #[zeroize(skip)]
    pub owner: String,
    #[zeroize(skip)]
    pub repo: String,
    #[zeroize(skip)]
    pub path: String,
    pub token: String,
    pub password: String,
    #[zeroize(skip)]
    pub overwrite_local: bool,
}

#[tauri::command]
pub fn sync_adopt(
    app: AppHandle,
    state: State<'_, AppState>,
    req: AdoptRequest,
) -> Cmd<AdoptResult> {
    let destino = vault_path(&app)?;
    if destino.exists() && !req.overwrite_local {
        return Err(err(
            "ja existe um cofre neste computador; confirme a substituicao para continuar",
        ));
    }

    // Lido por referencia: `AdoptRequest` implementa `Drop` para zerar a senha,
    // e um tipo com `Drop` nao pode ser desmontado por movimento.
    let alvo = sync::Repo {
        owner: req.owner.trim().to_string(),
        repo: req.repo.trim().to_string(),
        path: {
            let p = req.path.trim();
            if p.is_empty() {
                "passec.vault".to_string()
            } else {
                p.to_string()
            }
        },
        token: req.token.trim().to_string(),
    };

    let bytes = sync::fetch_remote(&alvo)?;

    let meta_remota = vault::peek(&bytes)?;
    if meta_remota.keyfile_mode.requires_file() {
        return Err(err(
            "o cofre remoto exige keyfile de audio; traga o arquivo e use a tela de bloqueio",
        ));
    }

    // Abre antes de gravar: sem a senha certa, nada e escrito no disco local.
    let mut aberto = UnlockedVault::open(&bytes, &factors(&req.password, None))?;

    aberto.body.sync = Some(crate::vault::model::SyncConfig {
        owner: alvo.owner,
        repo: alvo.repo,
        path: alvo.path,
        token: alvo.token,
        last_sha: String::new(),
        last_sync: vault::model::now_millis(),
    });

    let entries = aberto.body.entries.len();
    let meta = aberto.meta();

    let regravado = aberto.serialize()?;
    write_atomic(&destino, &regravado)?;

    state.set_vault(aberto, destino);
    state.record_success();

    Ok(AdoptResult { entries, meta })
}

// --- itens sob demanda -----------------------------------------------------

#[derive(Serialize)]
pub struct CloudItem {
    pub id: String,
    pub kind: vault::EntryKind,
    pub title: String,
    pub username: String,
    pub updated_at: i64,
    /// `true` quando o item esta no disco desta maquina.
    pub local: bool,
}

/// Lista tudo que existe no cofre — o que esta aqui e o que so esta na nuvem.
///
/// Para saber os titulos dos itens remotos e preciso decifrar o corpo remoto,
/// que passa pela RAM inteiro. A distincao que este recurso oferece e sobre o
/// **disco**: um item oculto nao fica gravado nesta maquina, entao quem levar o
/// notebook nao o encontra. Nao e uma barreira contra quem esta com a sessao
/// aberta na sua frente.
#[tauri::command]
pub fn cloud_list(state: State<'_, AppState>) -> Cmd<Vec<CloudItem>> {
    let cfg = state
        .with_vault(|v| v.body.sync.clone())?
        .ok_or_else(|| err("a sincronizacao nao esta configurada"))?;

    let bytes = sync::fetch_remote(&sync::repo_from(&cfg))?;
    let remotos = state.with_vault(|v| v.open_sibling_body(&bytes))??;

    let mut itens = state.with_vault(|v| {
        v.body
            .entries
            .iter()
            .map(|e| CloudItem {
                id: e.id.clone(),
                kind: e.kind,
                title: e.title.clone(),
                username: e.username.clone(),
                updated_at: e.updated_at,
                local: true,
            })
            .collect::<Vec<_>>()
    })?;

    let locais: Vec<String> = itens.iter().map(|i| i.id.clone()).collect();
    for e in &remotos.entries {
        if !locais.contains(&e.id) {
            itens.push(CloudItem {
                id: e.id.clone(),
                kind: e.kind,
                title: e.title.clone(),
                username: e.username.clone(),
                updated_at: e.updated_at,
                local: false,
            });
        }
    }

    itens.sort_by_key(|i| i.title.to_lowercase());
    Ok(itens)
}

/// Tira o item deste computador, mantendo-o na nuvem.
///
/// A confirmacao de que ele existe no remoto e feita **antes** de remover, e
/// custa uma ida a rede de proposito: sem ela, ocultar um item que ainda nao
/// subiu seria apaga-lo para sempre.
#[tauri::command]
pub fn entry_archive(app: AppHandle, state: State<'_, AppState>, id: String) -> Cmd<()> {
    let existe_aqui = state.with_vault(|v| v.body.find(&id).is_some())?;
    if !existe_aqui {
        return Err(err("item nao encontrado nesta maquina"));
    }

    let cfg = state
        .with_vault(|v| v.body.sync.clone())?
        .ok_or_else(|| err("configure a sincronizacao antes de ocultar itens"))?;

    let bytes = sync::fetch_remote(&sync::repo_from(&cfg))?;
    let remotos = state.with_vault(|v| v.open_sibling_body(&bytes))??;

    if !remotos.entries.iter().any(|e| e.id == id) {
        return Err(err(
            "este item ainda nao esta na nuvem; sincronize antes de oculta-lo",
        ));
    }

    state.with_vault(|v| v.body.unload(&id))?;
    persist(&state, &app)
}

/// Traz de volta para este computador um item que estava so na nuvem.
#[tauri::command]
pub fn entry_restore(app: AppHandle, state: State<'_, AppState>, id: String) -> Cmd<String> {
    let cfg = state
        .with_vault(|v| v.body.sync.clone())?
        .ok_or_else(|| err("a sincronizacao nao esta configurada"))?;

    let bytes = sync::fetch_remote(&sync::repo_from(&cfg))?;
    let remotos = state.with_vault(|v| v.open_sibling_body(&bytes))??;

    let item = remotos
        .entries
        .iter()
        .find(|e| e.id == id)
        .cloned()
        .ok_or_else(|| err("item nao encontrado na nuvem"))?;

    let titulo = item.title.clone();
    state.with_vault(|v| {
        v.body.unarchive(&id);
        if v.body.find(&id).is_none() {
            v.body.entries.push(item);
        }
    })?;
    persist(&state, &app)?;
    Ok(titulo)
}

// --- modo em guarda --------------------------------------------------------

#[derive(Serialize)]
pub struct GuardStatus {
    pub state: crate::guard::GuardState,
    /// Segundos ate o modo virar bloqueio de verdade.
    pub seconds_until_lock: Option<u64>,
    pub attempts: u32,
    pub max_attempts: u32,
    /// Ha combinacao de teclas configurada neste cofre.
    pub has_pattern: bool,
}

#[tauri::command]
pub fn guard_status(state: State<'_, AppState>) -> GuardStatus {
    // Le o padrao sem passar por `with_vault`: em guarda ele recusaria, e a
    // interface precisa justamente saber se pode pedir a combinacao.
    let has_pattern = state.has_guard_pattern();

    GuardStatus {
        state: state.guard_state(),
        seconds_until_lock: state.guard_seconds_until_lock(),
        attempts: state.guard_attempts(),
        max_attempts: crate::guard::MAX_PATTERN_ATTEMPTS,
        has_pattern,
    }
}

#[tauri::command]
pub fn guard_enter(state: State<'_, AppState>) -> Cmd<()> {
    if state.enter_guard() {
        Ok(())
    } else {
        Err(err("nao ha cofre aberto para colocar em guarda"))
    }
}

/// Tenta sair do modo com a combinacao de teclas.
///
/// Devolve `false` quando a combinacao esta errada. Erros demais trancam a
/// sessao de verdade — e nesse caso a proxima chamada ja encontra o cofre
/// fechado.
#[tauri::command]
pub fn guard_leave(state: State<'_, AppState>, pattern: String) -> Cmd<bool> {
    Ok(state.try_leave_guard(&pattern)?)
}

/// Define a combinacao de teclas.
///
/// So faz sentido com o cofre aberto pela senha mestra — que e a unica forma
/// de chegar aqui, ja que todo comando exige a sessao destrancada.
#[tauri::command]
pub fn pattern_set(app: AppHandle, state: State<'_, AppState>, pattern: String) -> Cmd<()> {
    crate::guard::validate_len(&pattern)?;

    state.with_vault(|v| {
        let chave = *v.vault_key_copy().expose();
        let digest = crate::guard::digest(&chave, &pattern);
        v.body.guard_pattern = Some(crate::util::to_hex(&digest));
    })?;

    persist(&state, &app)
}

#[tauri::command]
pub fn pattern_clear(app: AppHandle, state: State<'_, AppState>) -> Cmd<()> {
    state.with_vault(|v| v.body.guard_pattern = None)?;
    persist(&state, &app)
}

// --- utilidades ------------------------------------------------------------

fn unix_now() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Vigia de inatividade.
///
/// A verificacao preguicosa dentro de `with_vault` so dispara quando a
/// interface chama algo; se o usuario simplesmente sai da frente do
/// computador, nada chamaria e o cofre ficaria aberto na RAM. Esta thread
/// fecha essa brecha e avisa a interface para voltar a tela de bloqueio.
pub fn spawn_autolock_watcher(app: AppHandle) {
    std::thread::spawn(move || loop {
        std::thread::sleep(std::time::Duration::from_secs(5));
        let state = app.state::<AppState>();
        if state.lock_if_expired() {
            let _ = app.emit("vault-locked", "inatividade");
        }
    });
}

/// Registro dos comandos expostos ao frontend.
pub fn handlers() -> impl Fn(tauri::ipc::Invoke<tauri::Wry>) -> bool + Send + Sync + 'static {
    tauri::generate_handler![
        vault_status,
        vault_create,
        vault_unlock,
        vault_unlock_hello,
        vault_lock,
        master_change,
        session_info,
        session_touch,
        session_set_autolock,
        entries_list,
        entry_get,
        entry_save,
        entry_delete,
        entry_totp_code,
        password_generate,
        password_strength,
        totp_setup_begin,
        totp_enable,
        totp_disable,
        hello_status,
        hello_enroll,
        hello_disable,
        audio_export_vault,
        audio_import_vault,
        audio_export_entry,
        audio_import_entry,
        audio_estimate,
        keyfile_generate,
        stego_hide,
        stego_reveal,
        stego_inspect_carrier,
        sync_status,
        sync_configure,
        sync_now,
        sync_force_push,
        sync_disable,
        sync_adopt,
        guard_status,
        guard_enter,
        guard_leave,
        pattern_set,
        pattern_clear,
        cloud_list,
        entry_archive,
        entry_restore,
    ]
}
