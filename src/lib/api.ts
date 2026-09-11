/**
 * Ponte tipada com o nucleo em Rust.
 *
 * Tudo que cruza o IPC passa por aqui, e por um motivo: o `invoke` cru aceita
 * qualquer string como nome de comando e qualquer objeto como argumento, entao
 * um erro de digitacao so apareceria em tempo de execucao. Com estas
 * assinaturas, o compilador pega.
 *
 * Convencao de nomes: argumentos vao em camelCase (o Tauri converte para o
 * snake_case do Rust), mas os valores de **retorno** chegam exatamente como o
 * serde os serializou — ou seja, em snake_case. Os tipos abaixo refletem isso.
 */

import { invoke } from "@tauri-apps/api/core";

export type KeyfileMode = "none" | "generated" | "rawfile";
export type EntryKind = "login" | "note" | "card" | "identity" | "key" | "wifi";
export type Robustness = "digital" | "airborne";
export type StrengthLabel = "weak" | "fair" | "good" | "strong";

export interface VaultMeta {
  keyfile_mode: KeyfileMode;
  totp_enabled: boolean;
  hello_enabled: boolean;
  created_at: number;
  updated_at: number;
}

export interface VaultStatus {
  exists: boolean;
  unlocked: boolean;
  meta: VaultMeta | null;
  hello_available: boolean;
}

export interface SessionInfo {
  unlocked: boolean;
  seconds_until_lock: number | null;
  autolock_secs: number;
}

export interface EntrySummary {
  id: string;
  kind: EntryKind;
  title: string;
  username: string;
  url: string;
  tags: string[];
  favorite: boolean;
  has_totp: boolean;
  updated_at: number;
}

export interface CustomField {
  label: string;
  value: string;
  secret: boolean;
}

export interface VaultEntry {
  id: string;
  kind: EntryKind;
  title: string;
  username: string;
  password: string;
  url: string;
  notes: string;
  tags: string[];
  totp_secret: string | null;
  custom: CustomField[];
  favorite: boolean;
  created_at: number;
  updated_at: number;
}

export interface Strength {
  bits: number;
  label: StrengthLabel;
  warnings: string[];
}

export interface TransportReport {
  blocks_total: number;
  blocks_corrupt: number;
  blocks_recovered: number;
  phase_error_deg: number;
  pristine: boolean;
}

export interface AudioExportResult {
  path: string;
  bytes: number;
  duration_secs: number;
}

export interface AudioImportResult {
  report: TransportReport;
  entries: number;
}

export interface EntryImportResult {
  report: TransportReport;
  title: string;
  id: string;
}

export interface CarrierInfo {
  capacity_bytes: number;
  duration_secs: number;
  needed_bytes: number;
  fits: boolean;
}

export interface TotpSetup {
  secret: string;
  uri: string;
  qr_svg: string;
}

export interface PasswordOptions {
  length: number;
  lowercase: boolean;
  uppercase: boolean;
  digits: boolean;
  symbols: boolean;
  exclude_ambiguous: boolean;
}

export interface SyncStatus {
  configured: boolean;
  owner: string;
  repo: string;
  path: string;
  last_sync: number;
  /** Itens que estao na nuvem mas nao neste computador. */
  archived_here: number;
}

export interface MergeReport {
  added: number;
  updated: number;
  removed: number;
  kept_local: number;
  total: number;
}

export interface SyncOutcome {
  report: MergeReport;
  had_remote: boolean;
  synced_at: number;
  archived: number;
}

export type GuardState = "open" | "onguard";

export interface GuardStatus {
  state: GuardState;
  seconds_until_lock: number | null;
  attempts: number;
  max_attempts: number;
  has_pattern: boolean;
}

export interface CloudItem {
  id: string;
  kind: EntryKind;
  title: string;
  username: string;
  updated_at: number;
  /** `true` quando o item esta no disco desta maquina. */
  local: boolean;
}

export interface SyncConfigureResult {
  /** `false` = repositorio publico; a interface avisa em destaque. */
  private: boolean;
  outcome: SyncOutcome;
}

export interface AdoptResult {
  entries: number;
  meta: VaultMeta;
}

/**
 * Erro vindo do Rust.
 *
 * O nucleo serializa erros como string simples. Normalizamos para `Error` aqui
 * para que o resto do codigo use um unico formato em `try/catch`.
 */
export class VaultApiError extends Error {}

async function call<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  try {
    return await invoke<T>(cmd, args);
  } catch (e) {
    throw new VaultApiError(typeof e === "string" ? e : String(e));
  }
}

/* --------------------------------------------------------------- cofre --- */

export const vaultStatus = () => call<VaultStatus>("vault_status");

export const vaultCreate = (
  password: string,
  keyfileMode: KeyfileMode,
  keyfilePath: string | null,
) => call<VaultMeta>("vault_create", { password, keyfileMode, keyfilePath });

export const vaultUnlock = (
  password: string,
  keyfilePath: string | null,
  totpCode: string | null,
) => call<VaultMeta>("vault_unlock", { password, keyfilePath, totpCode });

export const vaultUnlockHello = () => call<VaultMeta>("vault_unlock_hello");
export const vaultLock = () => call<boolean>("vault_lock");

export const masterChange = (
  newPassword: string,
  keyfileMode: KeyfileMode,
  keyfilePath: string | null,
) => call<void>("master_change", { newPassword, keyfileMode, keyfilePath });

/* -------------------------------------------------------------- sessao --- */

export const sessionInfo = () => call<SessionInfo>("session_info");
export const sessionTouch = () => call<void>("session_touch");
export const sessionSetAutolock = (secs: number) => call<number>("session_set_autolock", { secs });

/* ------------------------------------------------------------- entradas -- */

export const entriesList = (query: string | null) => call<EntrySummary[]>("entries_list", { query });
export const entryGet = (id: string) => call<VaultEntry>("entry_get", { id });
export const entrySave = (entry: VaultEntry) => call<string>("entry_save", { entry });
export const entryDelete = (id: string) => call<void>("entry_delete", { id });
export const entryTotpCode = (id: string) =>
  call<{ code: string; seconds_remaining: number }>("entry_totp_code", { id });

/* -------------------------------------------------------------- senhas --- */

export const passwordGenerate = (options: PasswordOptions) =>
  call<{ password: string; entropy_bits: number }>("password_generate", { options });

export const passwordStrength = (password: string) => call<Strength>("password_strength", { password });

/* ---------------------------------------------------------------- 2FA ---- */

export const totpSetupBegin = () => call<TotpSetup>("totp_setup_begin");
export const totpEnable = (secret: string, code: string) => call<void>("totp_enable", { secret, code });
export const totpDisable = () => call<void>("totp_disable");

export const helloStatus = () => call<boolean>("hello_status");
export const helloEnroll = () => call<void>("hello_enroll");
export const helloDisable = () => call<void>("hello_disable");

/* --------------------------------------------------------------- audio --- */

export const audioExportVault = (destPath: string, robustness: Robustness) =>
  call<AudioExportResult>("audio_export_vault", { destPath, robustness });

export const audioImportVault = (sourcePath: string, password: string, keyfilePath: string | null) =>
  call<AudioImportResult>("audio_import_vault", { sourcePath, password, keyfilePath });

export const audioExportEntry = (
  id: string,
  destPath: string,
  password: string,
  robustness: Robustness,
) => call<AudioExportResult>("audio_export_entry", { id, destPath, password, robustness });

export const audioImportEntry = (sourcePath: string, password: string) =>
  call<EntryImportResult>("audio_import_entry", { sourcePath, password });

export const audioEstimate = (robustness: Robustness) => call<number>("audio_estimate", { robustness });
export const keyfileGenerate = (destPath: string) =>
  call<{ path: string; duration_secs: number }>("keyfile_generate", { destPath });

/* ------------------------------------------------------ esteganografia --- */

export const stegoHide = (carrierPath: string, destPath: string, password: string) =>
  call<{ path: string; payload_bytes: number; capacity_bytes: number }>("stego_hide", {
    carrierPath,
    destPath,
    password,
  });

export const stegoReveal = (sourcePath: string, stegoPassword: string, masterPassword: string) =>
  call<AudioImportResult>("stego_reveal", { sourcePath, stegoPassword, masterPassword });

export const stegoInspectCarrier = (carrierPath: string) =>
  call<CarrierInfo>("stego_inspect_carrier", { carrierPath });

/* ------------------------------------------------------- sincronizacao --- */

export const syncStatus = () => call<SyncStatus>("sync_status");

export const syncConfigure = (owner: string, repo: string, path: string, token: string) =>
  call<SyncConfigureResult>("sync_configure", { owner, repo, path, token });

export const syncNow = () => call<SyncOutcome>("sync_now");
export const syncForcePush = () => call<void>("sync_force_push");
export const syncDisable = () => call<void>("sync_disable");

/**
 * Traz um cofre da nuvem para este computador.
 *
 * Note que isto NAO e "criar um cofre com a mesma senha": cada criacao sorteia
 * salt e chave proprios, entao dois cofres criados separadamente nunca se
 * entendem. O computador novo precisa adotar o arquivo remoto.
 */
export const syncAdopt = (
  owner: string,
  repo: string,
  path: string,
  token: string,
  password: string,
  overwriteLocal: boolean,
) =>
  call<AdoptResult>("sync_adopt", {
    req: { owner, repo, path, token, password, overwriteLocal },
  });

/* ------------------------------------------------------ modo em guarda --- */

export const guardStatus = () => call<GuardStatus>("guard_status");
export const guardEnter = () => call<void>("guard_enter");

/** Devolve `false` quando a combinacao esta errada. */
export const guardLeave = (pattern: string) => call<boolean>("guard_leave", { pattern });

export const patternSet = (pattern: string) => call<void>("pattern_set", { pattern });
export const patternClear = () => call<void>("pattern_clear");

/* ----------------------------------------------------- itens sob demanda - */

export const cloudList = () => call<CloudItem[]>("cloud_list");

/** Tira o item deste computador mantendo-o na nuvem. */
export const entryArchive = (id: string) => call<void>("entry_archive", { id });

/** Traz de volta um item que estava so na nuvem. Devolve o titulo. */
export const entryRestore = (id: string) => call<string>("entry_restore", { id });
