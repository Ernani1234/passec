/**
 * Controlador da interface do PASSEC.
 *
 * A interface guarda o minimo possivel: a lista mostra resumos sem senha, e o
 * conteudo secreto de um item so e buscado quando o usuario o abre. Ao trancar,
 * tudo que foi carregado e apagado do DOM — deixar um campo preenchido para
 * "quando voltar" manteria a senha viva na memoria da webview depois de o cofre
 * ja estar fechado no Rust.
 */

import { getCurrentWindow } from "@tauri-apps/api/window";
import { listen } from "@tauri-apps/api/event";
import { open as openDialog, save as saveDialog } from "@tauri-apps/plugin-dialog";

import * as api from "./lib/api";
import type { EntryKind, KeyfileMode, Robustness, VaultEntry, VaultMeta } from "./lib/api";
import {
  $,
  askPassword,
  copySecret,
  humanBytes,
  humanDuration,
  humanSecs,
  show,
  setText,
  status,
  statusBar,
  toast,
  typeLines,
  wireModal,
} from "./lib/ui";

/* ======================================================== estado local ==== */

let meta: VaultMeta | null = null;
let helloAvailable = false;
/** `true` quando a tela de bloqueio esta em modo "criar cofre". */
let creating = false;
/** Caminho do keyfile escolhido na sessao atual da tela de bloqueio. */
let keyfilePath: string | null = null;
let selectedId: string | null = null;
let totpTimer: number | undefined;
/** A sincronizacao esta ligada — decide se "tirar deste PC" faz sentido. */
let syncOn = false;

const WAV_FILTER = [{ name: "Audio WAV", extensions: ["wav"] }];

/* ============================================================== utils ===== */

function errMsg(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

/** Roda uma acao mostrando progresso e capturando o erro num aviso. */
async function guard<T>(label: string, fn: () => Promise<T>): Promise<T | undefined> {
  statusBar(label);
  try {
    const out = await fn();
    statusBar("");
    return out;
  } catch (e) {
    statusBar("");
    toast(errMsg(e), "err", 7000);
    return undefined;
  }
}

function screenTo(id: "screen-boot" | "screen-lock" | "screen-app"): void {
  for (const s of document.querySelectorAll<HTMLElement>(".screen")) {
    s.classList.toggle("active", s.id === id);
  }
}

/* =============================================================== boot ===== */

async function boot(): Promise<void> {
  const log = $("boot-log");
  const st = await api.vaultStatus().catch(() => null);

  await typeLines(log, [
    "<b>PASSEC</b> // TERMINAL DE CREDENCIAIS",
    "----------------------------------------------",
    "verificando subsistemas...",
    "  KDF ARGON2ID .................. <span class='ok'>OK</span>",
    "  AEAD XCHACHA20-POLY1305 ....... <span class='ok'>OK</span>",
    "  MODEM OFDM/DQPSK .............. <span class='ok'>OK</span>",
    "  FEC REED-SOLOMON .............. <span class='ok'>OK</span>",
    st?.hello_available
      ? "  WINDOWS HELLO ................. <span class='ok'>DISPONIVEL</span>"
      : "  WINDOWS HELLO ................. <span class='warn'>INDISPONIVEL</span>",
    st?.exists
      ? "  COFRE LOCAL ................... <span class='ok'>ENCONTRADO</span>"
      : "  COFRE LOCAL ................... <span class='warn'>NENHUM</span>",
    "----------------------------------------------",
    st?.exists ? "aguardando autenticacao." : "nenhum cofre — iniciando cadastro.",
  ]);

  await new Promise((r) => setTimeout(r, 450));
  await refreshLock();
  screenTo("screen-lock");
  $<HTMLInputElement>("lock-password").focus();
}

/* =========================================================== titlebar ===== */

function wireTitlebar(): void {
  const win = getCurrentWindow();
  $("win-min").addEventListener("click", () => void win.minimize());
  $("win-max").addEventListener("click", () => void win.toggleMaximize());
  $("win-close").addEventListener("click", () => void win.close());
}

/* ======================================================== tela de lock ==== */

const KEYFILE_HINTS: Record<KeyfileMode, string> = {
  none: "So a senha mestra protege o cofre.",
  generated:
    "O PASSEC gera um WAV com 64 bytes de entropia modulada. Ele entra no Argon2id junto com a senha — e sobrevive a conversao para MP3, porque o que conta e o payload, nao as amostras.",
  rawfile:
    "Qualquer audio seu vira a chave, mas pelo PCM exato: se o arquivo for reeditado, reconvertido ou perdido, o cofre nao abre mais. Tenha copia do arquivo original.",
};

async function refreshLock(): Promise<void> {
  const st = await api.vaultStatus();
  meta = st.meta;
  helloAvailable = st.hello_available;
  creating = !st.exists;

  setText("lock-title", creating ? "CADASTRO INICIAL" : "AUTENTICACAO NECESSARIA");
  setText("lock-mode-badge", creating ? "NOVO" : "TRANCADO");
  setText(
    "lock-intro",
    creating
      ? "Nenhum cofre nesta maquina. A senha mestra que voce escolher agora e a unica coisa entre um atacante e tudo que voce guardar — e nao existe recuperacao."
      : "",
  );

  show($("lock-confirm-row"), creating);
  show($("lock-setup-extra"), creating);
  show($("lock-totp-row"), !creating && !!meta?.totp_enabled);
  show($("lock-keyfile-row"), creating ? false : !!meta && meta.keyfile_mode !== "none");
  show($("lock-hello"), !creating && !!meta?.hello_enabled && helloAvailable);

  $("lock-submit").textContent = creating ? "CRIAR COFRE" : "DESTRANCAR";
  setText("lock-keyfile-hint", KEYFILE_HINTS.none);
  keyfilePath = null;
  $<HTMLInputElement>("lock-keyfile").value = "";
  show($("lock-cloud-panel"), false);
  status("");
}

function wireLock(): void {
  const pass = $<HTMLInputElement>("lock-password");
  const pass2 = $<HTMLInputElement>("lock-password2");
  const modeSel = $<HTMLSelectElement>("lock-keyfile-mode");

  // Medidor de forca, so no cadastro.
  let strengthTimer: number | undefined;
  pass.addEventListener("input", () => {
    if (!creating) return;
    clearTimeout(strengthTimer);
    strengthTimer = window.setTimeout(async () => {
      const s = await api.passwordStrength(pass.value).catch(() => null);
      if (!s) return;
      const pct = Math.min(100, (s.bits / 128) * 100);
      const bar = $("lock-strength").querySelector("i") as HTMLElement;
      bar.style.width = `${pct}%`;
      bar.className = s.label === "weak" ? "weak" : s.label === "fair" ? "fair" : "";
      const label = $("lock-strength").querySelector(".meter-label") as HTMLElement;
      label.textContent = `${Math.round(s.bits)} bits`;
      $("lock-warnings").innerHTML = s.warnings.map((w) => `<div>${w}</div>`).join("");
    }, 180);
  });

  modeSel.addEventListener("change", () => {
    const mode = modeSel.value as KeyfileMode;
    setText("lock-keyfile-hint", KEYFILE_HINTS[mode]);
    show($("lock-keyfile-row"), mode !== "none");
    keyfilePath = null;
    $<HTMLInputElement>("lock-keyfile").value = "";
  });

  $("lock-keyfile-pick").addEventListener("click", async () => {
    const mode = creating ? (modeSel.value as KeyfileMode) : (meta?.keyfile_mode ?? "none");

    // No cadastro com keyfile gerado, o arquivo ainda nao existe: criamos aqui.
    if (creating && mode === "generated") {
      const dest = await saveDialog({ title: "Onde salvar o keyfile", filters: WAV_FILTER, defaultPath: "passec-keyfile.wav" });
      if (!dest) return;
      const r = await guard("gerando keyfile...", () => api.keyfileGenerate(dest));
      if (!r) return;
      keyfilePath = r.path;
      $<HTMLInputElement>("lock-keyfile").value = r.path;
      toast(`keyfile gerado (${humanDuration(r.duration_secs)} de audio)`);
      return;
    }

    const picked = await openDialog({ title: "Selecione o keyfile", filters: WAV_FILTER, multiple: false });
    if (typeof picked === "string") {
      keyfilePath = picked;
      $<HTMLInputElement>("lock-keyfile").value = picked;
    }
  });

  $("lock-hello").addEventListener("click", async () => {
    status("aguardando o gesto do Windows Hello...");
    const r = await guard("windows hello...", () => api.vaultUnlockHello());
    if (r) {
      meta = r;
      await enterApp();
    } else {
      status("");
    }
  });

  const submit = async () => {
    const senha = pass.value;
    if (!senha) {
      status("digite a senha mestra");
      return;
    }

    if (creating) {
      if (senha !== pass2.value) {
        status("as senhas nao conferem");
        return;
      }
      const mode = modeSel.value as KeyfileMode;
      if (mode !== "none" && !keyfilePath) {
        status("selecione ou gere o keyfile antes de continuar");
        return;
      }
      status("derivando chave (Argon2id, 256 MiB)...");
      const r = await guard("criando cofre...", () => api.vaultCreate(senha, mode, keyfilePath));
      if (!r) {
        status("");
        return;
      }
      meta = r;
      toast("cofre criado");
      await enterApp();
      return;
    }

    const needKeyfile = !!meta && meta.keyfile_mode !== "none";
    if (needKeyfile && !keyfilePath) {
      status("este cofre exige o keyfile de audio");
      return;
    }
    const code = meta?.totp_enabled ? $<HTMLInputElement>("lock-totp").value : null;

    status("derivando chave (Argon2id, 256 MiB)...");
    const r = await guard("destrancando...", () => api.vaultUnlock(senha, keyfilePath, code));
    if (!r) {
      status("");
      return;
    }
    meta = r;
    await enterApp();
  };

  $("lock-submit").addEventListener("click", () => void submit());
  for (const el of [pass, pass2, $<HTMLInputElement>("lock-totp")]) {
    el.addEventListener("keydown", (e) => {
      if (e.key === "Enter") void submit();
    });
  }
}

/** Apaga do DOM tudo que veio do cofre. */
function wipeUi(): void {
  for (const id of [
    "lock-password",
    "lock-password2",
    "lock-totp",
    "sec-newpass",
    "stego-pass",
    "adopt-token",
    "adopt-password",
    "sync-token",
  ]) {
    $<HTMLInputElement>(id).value = "";
  }
  $<HTMLUListElement>("entry-list").innerHTML = "";
  $<HTMLUListElement>("cloud-list").innerHTML = "";
  guardBuffer = [];
  patternBuffer = [];
  show($("guard-host"), false);
  clearForm();
  show($("entry-form"), false);
  show($("entry-empty"), true);
  selectedId = null;
  clearInterval(totpTimer);
  setText("gen-out", "—");
}

async function enterApp(): Promise<void> {
  screenTo("screen-app");
  await refreshList();
  await refreshSecurity();
  await refreshSync();
  await refreshTapeEstimate();
  statusBar("cofre aberto");
}

async function lockNow(reason = "trancado"): Promise<void> {
  await api.vaultLock().catch(() => undefined);
  wipeUi();
  await refreshLock();
  screenTo("screen-lock");
  statusBar(reason);
  $<HTMLInputElement>("lock-password").focus();
}

/* ================================================================ abas ==== */

function wireTabs(): void {
  for (const tab of document.querySelectorAll<HTMLButtonElement>(".tab")) {
    tab.addEventListener("click", () => {
      for (const t of document.querySelectorAll(".tab")) t.classList.remove("active");
      for (const p of document.querySelectorAll(".pane")) p.classList.remove("active");
      tab.classList.add("active");
      $(tab.dataset.pane!).classList.add("active");
      if (tab.dataset.pane === "pane-sec") void refreshSecurity();
      if (tab.dataset.pane === "pane-cloud") void refreshSync();
      if (tab.dataset.pane === "pane-tape") void refreshTapeEstimate();
    });
  }
}

/* ============================================================== cofre ===== */

const KIND_LABEL: Record<EntryKind, string> = {
  login: "LOGIN",
  note: "NOTA",
  card: "CARTAO",
  identity: "IDENT",
  key: "CHAVE",
  wifi: "WI-FI",
};

async function refreshList(): Promise<void> {
  const query = $<HTMLInputElement>("search").value.trim();
  const items = await api.entriesList(query || null).catch((e) => {
    // Perder a sessao aqui e o caso normal do auto-lock, nao um erro a exibir.
    if (errMsg(e).includes("trancado")) void lockNow("trancado por inatividade");
    return null;
  });
  if (!items) return;

  const list = $<HTMLUListElement>("entry-list");
  list.innerHTML = "";
  for (const it of items) {
    const li = document.createElement("li");
    li.dataset.id = it.id;
    li.classList.toggle("sel", it.id === selectedId);
    li.innerHTML = `
      <span class="entry-title">
        ${it.favorite ? '<span class="entry-fav">★</span>' : ""}
        <span>${escapeHtml(it.title)}</span>
        ${it.has_totp ? '<span class="entry-kind">2FA</span>' : ""}
      </span>
      <span class="entry-sub">
        <span class="entry-kind">${KIND_LABEL[it.kind]}</span>
        ${escapeHtml(it.username || it.url || "")}
      </span>`;
    li.addEventListener("click", () => void selectEntry(it.id));
    list.appendChild(li);
  }
  setText("entry-count", `${items.length} ${items.length === 1 ? "item" : "itens"}`);
}

function escapeHtml(s: string): string {
  const d = document.createElement("div");
  d.textContent = s;
  return d.innerHTML;
}

function clearForm(): void {
  for (const id of ["f-title", "f-username", "f-password", "f-url", "f-totp", "f-tags"]) {
    $<HTMLInputElement>(id).value = "";
  }
  $<HTMLTextAreaElement>("f-notes").value = "";
  $("f-fav").classList.remove("on");
  show($("f-totp-live"), false);
  clearInterval(totpTimer);
}

function fillForm(e: VaultEntry): void {
  $<HTMLSelectElement>("f-kind").value = e.kind;
  $<HTMLInputElement>("f-title").value = e.title;
  $<HTMLInputElement>("f-username").value = e.username;
  $<HTMLInputElement>("f-password").value = e.password;
  $<HTMLInputElement>("f-url").value = e.url;
  $<HTMLInputElement>("f-totp").value = e.totp_secret ?? "";
  $<HTMLInputElement>("f-tags").value = e.tags.join(", ");
  $<HTMLTextAreaElement>("f-notes").value = e.notes;
  $("f-fav").classList.toggle("on", e.favorite);
  startTotpTicker(e.id, !!e.totp_secret);
}

function startTotpTicker(id: string, hasTotp: boolean): void {
  clearInterval(totpTimer);
  show($("f-totp-live"), hasTotp);
  if (!hasTotp) return;

  const tick = async () => {
    const r = await api.entryTotpCode(id).catch(() => null);
    if (!r) {
      clearInterval(totpTimer);
      return;
    }
    setText("f-totp-code", r.code);
    ($("f-totp-ring") as HTMLElement).style.width = `${(r.seconds_remaining / 30) * 100}%`;
  };
  void tick();
  totpTimer = window.setInterval(tick, 1000);
}

async function selectEntry(id: string): Promise<void> {
  const e = await guard("abrindo item...", () => api.entryGet(id));
  if (!e) return;
  selectedId = id;
  show($("entry-empty"), false);
  show($("entry-form"), true);
  fillForm(e);
  for (const li of document.querySelectorAll<HTMLLIElement>("#entry-list li")) {
    li.classList.toggle("sel", li.dataset.id === id);
  }
}

function collectForm(): VaultEntry {
  const totp = $<HTMLInputElement>("f-totp").value.trim();
  return {
    id: selectedId ?? "",
    kind: $<HTMLSelectElement>("f-kind").value as EntryKind,
    title: $<HTMLInputElement>("f-title").value.trim(),
    username: $<HTMLInputElement>("f-username").value,
    password: $<HTMLInputElement>("f-password").value,
    url: $<HTMLInputElement>("f-url").value.trim(),
    notes: $<HTMLTextAreaElement>("f-notes").value,
    tags: $<HTMLInputElement>("f-tags")
      .value.split(",")
      .map((t) => t.trim())
      .filter(Boolean),
    totp_secret: totp || null,
    custom: [],
    favorite: $("f-fav").classList.contains("on"),
    created_at: 0,
    updated_at: 0,
  };
}

function wireVault(): void {
  let searchTimer: number | undefined;
  $<HTMLInputElement>("search").addEventListener("input", () => {
    clearTimeout(searchTimer);
    searchTimer = window.setTimeout(() => void refreshList(), 140);
  });

  $("entry-new").addEventListener("click", () => {
    selectedId = null;
    clearForm();
    show($("entry-empty"), false);
    show($("entry-form"), true);
    for (const li of document.querySelectorAll("#entry-list li")) li.classList.remove("sel");
    $<HTMLInputElement>("f-title").focus();
  });

  $("f-fav").addEventListener("click", () => $("f-fav").classList.toggle("on"));

  for (const [btn, input] of [
    ["f-reveal", "f-password"],
    ["f-totp-reveal", "f-totp"],
  ] as const) {
    $(btn).addEventListener("click", () => {
      const el = $<HTMLInputElement>(input);
      el.type = el.type === "password" ? "text" : "password";
    });
  }

  for (const btn of document.querySelectorAll<HTMLButtonElement>("[data-copy]")) {
    btn.addEventListener("click", () =>
      void copySecret($<HTMLInputElement>(btn.dataset.copy!).value, "valor"),
    );
  }
  for (const btn of document.querySelectorAll<HTMLButtonElement>("[data-copy-text]")) {
    btn.addEventListener("click", () =>
      void copySecret($(btn.dataset.copyText!).textContent ?? "", "codigo"),
    );
  }

  $("f-gen").addEventListener("click", async () => {
    const r = await guard("gerando...", () => api.passwordGenerate(readGenOptions()));
    if (r) {
      $<HTMLInputElement>("f-password").value = r.password;
      toast(`senha gerada — ${Math.round(r.entropy_bits)} bits`);
    }
  });

  $<HTMLFormElement>("entry-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const entry = collectForm();
    if (!entry.title) {
      toast("o item precisa de um titulo", "warn");
      return;
    }
    const id = await guard("gravando...", () => api.entrySave(entry));
    if (id === undefined) return;
    selectedId = id;
    await refreshList();
    startTotpTicker(id, !!entry.totp_secret);
    toast("gravado e cifrado em disco");
  });

  // Tirar deste computador: o item continua na nuvem.
  $("entry-hide").addEventListener("click", async () => {
    if (!selectedId) return;
    const titulo = $<HTMLInputElement>("f-title").value;
    const ok = await guard("tirando deste computador...", () => api.entryArchive(selectedId!));
    if (ok === undefined) return;

    selectedId = null;
    clearForm();
    show($("entry-form"), false);
    show($("entry-empty"), true);
    await refreshList();
    await refreshSync();
    toast(`"${titulo}" saiu daqui — continua na nuvem, veja na aba NUVEM`);
  });

  $("entry-delete").addEventListener("click", async () => {
    if (!selectedId) return;
    const titulo = $<HTMLInputElement>("f-title").value;

    // O texto precisa dizer o alcance real da acao. "Apagar definitivamente?"
    // nao deixava claro que a exclusao viaja para a nuvem e para os outros
    // computadores — e o botao ao lado faz justamente a versao local.
    const aviso = syncOn
      ? `APAGAR "${titulo}" DE TODOS OS COMPUTADORES?

` +
        `O item sai daqui, sai da nuvem e sai dos outros computadores na proxima sincronizacao.

` +
        `Se voce so quer liberar o disco desta maquina, cancele e use TIRAR DESTE PC.`
      : `Apagar "${titulo}" deste cofre?`;

    if (!confirm(aviso)) return;

    const ok = await guard("apagando...", () => api.entryDelete(selectedId!));
    if (ok === undefined) return;
    selectedId = null;
    clearForm();
    show($("entry-form"), false);
    show($("entry-empty"), true);
    await refreshList();
    toast(
      syncOn
        ? "item apagado — da para recuperar pelo historico do repositorio"
        : "item apagado",
    );
  });

  $("entry-export").addEventListener("click", async () => {
    if (!selectedId) {
      toast("grave o item antes de exporta-lo", "warn");
      return;
    }
    const senha = await askPassword(
      "EXPORTAR ITEM EM AUDIO",
      "Este WAV vai circular fora do cofre, entao recebe uma senha propria — nunca a senha mestra.",
      "SENHA DO ARQUIVO",
    );
    if (!senha) return;

    const titulo = $<HTMLInputElement>("f-title").value.replace(/[^\w.-]+/g, "_") || "item";
    const dest = await saveDialog({ title: "Salvar audio", filters: WAV_FILTER, defaultPath: `${titulo}.wav` });
    if (!dest) return;

    const r = await guard("modulando audio...", () =>
      api.audioExportEntry(selectedId!, dest, senha, "airborne"),
    );
    if (r) toast(`audio gravado — ${humanDuration(r.duration_secs)}, ${humanBytes(r.bytes)}`);
  });
}

/* ============================================================ gerador ===== */

function readGenOptions(): api.PasswordOptions {
  return {
    length: Number($<HTMLInputElement>("gen-len").value),
    lowercase: $<HTMLInputElement>("gen-lower").checked,
    uppercase: $<HTMLInputElement>("gen-upper").checked,
    digits: $<HTMLInputElement>("gen-digits").checked,
    symbols: $<HTMLInputElement>("gen-symbols").checked,
    exclude_ambiguous: $<HTMLInputElement>("gen-ambig").checked,
  };
}

function wireGenerator(): void {
  const len = $<HTMLInputElement>("gen-len");
  len.addEventListener("input", () => setText("gen-len-label", len.value));

  const run = async () => {
    const r = await guard("gerando...", () => api.passwordGenerate(readGenOptions()));
    if (!r) return;
    setText("gen-out", r.password);
    setText("gen-bits", `${Math.round(r.entropy_bits)} bits`);
    ($("gen-bar") as HTMLElement).style.width = `${Math.min(100, (r.entropy_bits / 200) * 100)}%`;
  };

  $("gen-run").addEventListener("click", () => void run());
  $("gen-copy").addEventListener("click", () => {
    const v = $("gen-out").textContent ?? "";
    void copySecret(v === "—" ? "" : v, "senha");
  });
  void run();
}

/* =============================================================== fita ===== */

async function refreshTapeEstimate(): Promise<void> {
  const rob = $<HTMLSelectElement>("tape-robust").value as Robustness;
  const secs = await api.audioEstimate(rob).catch(() => null);
  setText("tape-estimate", secs === null ? "—" : `audio estimado: ${humanSecs(secs)}`);
}

function renderReport(r: api.TransportReport, entries: number): void {
  const el = $("tape-report");
  el.hidden = false;
  const linha = r.pristine
    ? "<b>sinal limpo</b> — nenhum bloco precisou de reparo"
    : `<span class="warn">${r.blocks_corrupt} blocos corrompidos, ${r.blocks_recovered} reconstruidos pelo Reed-Solomon</span>`;
  el.innerHTML = `${linha}
blocos lidos: <b>${r.blocks_total}</b>
erro de fase: <b>${r.phase_error_deg.toFixed(1)}°</b>
itens no cofre: <b>${entries}</b>`;
}

function wireTape(): void {
  $("tape-robust").addEventListener("change", () => void refreshTapeEstimate());

  $("tape-export").addEventListener("click", async () => {
    const rob = $<HTMLSelectElement>("tape-robust").value as Robustness;
    const dest = await saveDialog({ title: "Gravar fita", filters: WAV_FILTER, defaultPath: "passec-fita.wav" });
    if (!dest) return;
    const r = await guard("modulando o cofre...", () => api.audioExportVault(dest, rob));
    if (r) {
      toast(`fita gravada — ${humanDuration(r.duration_secs)}, ${humanBytes(r.bytes)}`);
      statusBar(`fita: ${r.path}`);
    }
  });

  $("tape-import").addEventListener("click", async () => {
    const src = await openDialog({ title: "Selecione a fita", filters: WAV_FILTER, multiple: false });
    if (typeof src !== "string") return;

    const senha = await askPassword(
      "RESTAURAR DE FITA",
      "Isto substitui o cofre desta maquina. A senha mestra da fita precisa conferir antes de qualquer coisa ser escrita.",
      "SENHA MESTRA DA FITA",
    );
    if (!senha) return;

    const r = await guard("demodulando...", () => api.audioImportVault(src, senha, keyfilePath));
    if (r) {
      renderReport(r.report, r.entries);
      await refreshList();
      await refreshSecurity();
      toast(`cofre restaurado — ${r.entries} itens`);
    }
  });

  $("entry-import").addEventListener("click", async () => {
    const src = await openDialog({ title: "Audio do item", filters: WAV_FILTER, multiple: false });
    if (typeof src !== "string") return;
    const senha = await askPassword("IMPORTAR ITEM", "Senha que protege este arquivo de audio.", "SENHA DO ARQUIVO");
    if (!senha) return;

    const r = await guard("demodulando...", () => api.audioImportEntry(src, senha));
    if (r) {
      await refreshList();
      toast(`"${r.title}" importado`);
    }
  });
}

/* ============================================================ ocultar ===== */

function wireStego(): void {
  $("stego-pick").addEventListener("click", async () => {
    const picked = await openDialog({ title: "Audio carregador", filters: WAV_FILTER, multiple: false });
    if (typeof picked !== "string") return;
    $<HTMLInputElement>("stego-carrier").value = picked;

    const info = await guard("analisando audio...", () => api.stegoInspectCarrier(picked));
    if (!info) return;
    setText(
      "stego-capacity",
      info.fits
        ? `cabe: ${humanBytes(info.needed_bytes)} de cofre em ${humanBytes(info.capacity_bytes)} disponiveis (${humanDuration(info.duration_secs)} de audio)`
        : `NAO CABE: o cofre tem ${humanBytes(info.needed_bytes)} e este audio comporta ${humanBytes(info.capacity_bytes)} — use um arquivo mais longo`,
    );
  });

  $("stego-hide").addEventListener("click", async () => {
    const carrier = $<HTMLInputElement>("stego-carrier").value;
    const senha = $<HTMLInputElement>("stego-pass").value;
    if (!carrier) {
      toast("escolha o audio carregador", "warn");
      return;
    }
    if (!senha) {
      toast("defina a senha do esconderijo", "warn");
      return;
    }
    const dest = await saveDialog({ title: "Salvar audio com o cofre dentro", filters: WAV_FILTER, defaultPath: "musica.wav" });
    if (!dest) return;

    const r = await guard("escondendo...", () => api.stegoHide(carrier, dest, senha));
    if (r) toast(`escondido: ${humanBytes(r.payload_bytes)} em ${humanBytes(r.capacity_bytes)}`);
  });

  $("stego-reveal").addEventListener("click", async () => {
    const src = await openDialog({ title: "Audio com cofre escondido", filters: WAV_FILTER, multiple: false });
    if (typeof src !== "string") return;

    const sPass = await askPassword("REVELAR", "Senha usada ao esconder.", "SENHA DO ESCONDERIJO");
    if (!sPass) return;
    const mPass = await askPassword("REVELAR", "Senha mestra do cofre escondido.", "SENHA MESTRA");
    if (!mPass) return;

    const r = await guard("extraindo...", () => api.stegoReveal(src, sPass, mPass));
    if (r) {
      await refreshList();
      await refreshSecurity();
      toast(`cofre revelado — ${r.entries} itens`);
    }
  });
}


/* ============================================================== nuvem ===== */

async function refreshSync(): Promise<void> {
  const st = await api.syncStatus().catch(() => null);
  if (!st) return;

  const badge = $("sync-badge");
  badge.textContent = st.configured ? "LIGADA" : "DESLIGADA";
  badge.className = `badge ${st.configured ? "on" : "off"}`;

  syncOn = st.configured;
  show($("sync-form"), !st.configured);
  show($("sync-active"), st.configured);
  show($("cloud-items-panel"), st.configured);
  show($("entry-hide"), st.configured);
  show($("entry-danger-hint"), st.configured);

  if (st.configured) {
    $("sync-info").innerHTML = `
      <dt>REPOSITORIO</dt><dd>${escapeHtml(st.owner)}/${escapeHtml(st.repo)}</dd>
      <dt>ARQUIVO</dt><dd>${escapeHtml(st.path)}</dd>
      <dt>ULTIMA SINC.</dt><dd>${
        st.last_sync ? new Date(st.last_sync).toLocaleString("pt-BR") : "nunca"
      }</dd>
      <dt>OCULTOS AQUI</dt><dd>${st.archived_here}</dd>`;
  }
}

function renderSyncReport(o: api.SyncOutcome): void {
  const el = $("sync-report");
  el.hidden = false;
  const r = o.report;
  el.innerHTML = o.had_remote
    ? `<b>fundido com a versao remota</b>
vindos da nuvem: <b>${r.added}</b>    atualizados: <b>${r.updated}</b>
apagados: <b>${r.removed}</b>    mantidos daqui: <b>${r.kept_local}</b>
total no cofre: <b>${r.total}</b>`
    : `<b>primeira subida</b> — o repositorio ainda nao tinha cofre
itens enviados: <b>${r.total}</b>`;
}

function lerCamposSync(prefixo: string) {
  const v = (id: string) => $<HTMLInputElement>(`${prefixo}-${id}`).value.trim();
  return {
    owner: v("owner"),
    repo: v("repo"),
    path: v("path") || "passec.vault",
    token: v("token"),
  };
}

function wireCloud(): void {
  $("sync-connect").addEventListener("click", async () => {
    const c = lerCamposSync("sync");
    if (!c.owner || !c.repo || !c.token) {
      toast("preencha dono, repositorio e token", "warn");
      return;
    }

    const r = await guard("conectando ao GitHub...", () =>
      api.syncConfigure(c.owner, c.repo, c.path, c.token),
    );
    if (!r) return;

    // Um repositorio publico expoe o cofre a forca bruta offline por qualquer
    // pessoa. Nao bloqueamos — a decisao e do usuario — mas nao deixamos passar
    // em silencio.
    if (!r.private) {
      toast("ATENCAO: este repositorio e PUBLICO. Torne-o privado agora.", "err", 12000);
    }
    $<HTMLInputElement>("sync-token").value = "";
    renderSyncReport(r.outcome);
    await refreshSync();
    await refreshList();
    toast("sincronizacao ligada");
  });

  $("sync-run").addEventListener("click", async () => {
    const o = await guard("sincronizando...", () => api.syncNow());
    if (!o) return;
    renderSyncReport(o);
    await refreshSync();
    await refreshList();
    const r = o.report;
    toast(
      r.added + r.updated + r.removed === 0
        ? "ja estava em dia"
        : `sincronizado: +${r.added} novos, ${r.updated} atualizados, ${r.removed} apagados`,
    );
  });

  $("sync-push").addEventListener("click", async () => {
    if (
      !confirm(
        `Enviar esta versao por cima da que esta na nuvem?

O que existir so na nuvem sera perdido. Use isto apenas para resolver um impasse.`,
      )
    ) {
      return;
    }
    const ok = await guard("enviando...", () => api.syncForcePush());
    if (ok !== undefined) {
      await refreshSync();
      toast("versao local enviada");
    }
  });

  $("sync-off").addEventListener("click", async () => {
    if (!confirm("Desligar a sincronizacao? O arquivo no GitHub continua la.")) return;
    const ok = await guard("desligando...", () => api.syncDisable());
    if (ok !== undefined) {
      $("sync-report").hidden = true;
      await refreshSync();
      toast("sincronizacao desligada");
    }
  });
}

/** Traz um cofre da nuvem para este computador, a partir da tela de bloqueio. */
function wireAdopt(): void {
  const painel = $("lock-cloud-panel");

  $("lock-cloud").addEventListener("click", () => {
    show(painel, true);
    $<HTMLInputElement>("adopt-owner").focus();
  });
  $("adopt-cancel").addEventListener("click", () => show(painel, false));

  $("adopt-run").addEventListener("click", async () => {
    const c = lerCamposSync("adopt");
    const senha = $<HTMLInputElement>("adopt-password").value;

    if (!c.owner || !c.repo || !c.token) {
      toast("preencha dono, repositorio e token", "warn");
      return;
    }
    if (!senha) {
      toast("digite a senha mestra do cofre remoto", "warn");
      return;
    }

    // `creating` e falso quando ja existe um cofre neste computador — e adotar
    // vai substitui-lo.
    const temLocal = !creating;
    if (
      temLocal &&
      !confirm(
        `Ja existe um cofre neste computador.

Trazer o da nuvem vai substitui-lo. O que estiver so aqui sera perdido.`,
      )
    ) {
      return;
    }

    status("baixando e abrindo (Argon2id, 256 MiB)...");
    const r = await guard("trazendo da nuvem...", () =>
      api.syncAdopt(c.owner, c.repo, c.path, c.token, senha, temLocal),
    );
    if (!r) {
      status("");
      return;
    }

    for (const id of ["adopt-token", "adopt-password"]) {
      $<HTMLInputElement>(id).value = "";
    }
    show(painel, false);
    meta = r.meta;
    toast(`cofre trazido da nuvem — ${r.entries} itens`);
    await enterApp();
  });
}

/* ========================================================= seguranca ====== */

async function refreshSecurity(): Promise<void> {
  const st = await api.vaultStatus().catch(() => null);
  if (!st?.meta) return;
  meta = st.meta;
  helloAvailable = st.hello_available;

  const totpOn = meta.totp_enabled;
  const badge = $("sec-totp-badge");
  badge.textContent = totpOn ? "ATIVO" : "INATIVO";
  badge.className = `badge ${totpOn ? "on" : "off"}`;
  show($("sec-totp-off"), totpOn);
  $("sec-totp-begin").textContent = totpOn ? "RECONFIGURAR" : "CONFIGURAR";

  const helloOn = meta.hello_enabled;
  const hb = $("sec-hello-badge");
  hb.textContent = !helloAvailable ? "INDISPONIVEL" : helloOn ? "ATIVO" : "INATIVO";
  hb.className = `badge ${helloOn ? "on" : "off"}`;
  show($("sec-hello-off"), helloOn);
  ($("sec-hello-on") as HTMLButtonElement).disabled = !helloAvailable;

  const gs = await api.guardStatus().catch(() => null);
  if (gs) {
    const pb = $("pattern-badge");
    pb.textContent = gs.has_pattern ? "DEFINIDA" : "NENHUMA";
    pb.className = `badge ${gs.has_pattern ? "on" : "off"}`;
    show($("pattern-off"), gs.has_pattern);
  }

  const kb = $("sec-keyfile-badge");
  kb.textContent = meta.keyfile_mode === "none" ? "INATIVO" : meta.keyfile_mode.toUpperCase();
  kb.className = `badge ${meta.keyfile_mode === "none" ? "off" : "on"}`;

  const info = await api.sessionInfo().catch(() => null);
  $("sec-diag").innerHTML = `
    <dt>FORMATO</dt><dd>PASSECV1</dd>
    <dt>KDF</dt><dd>Argon2id 256 MiB / 3 passagens / 4 pistas</dd>
    <dt>CIFRA</dt><dd>XChaCha20-Poly1305 (nonce 192 bits)</dd>
    <dt>MODEM</dt><dd>OFDM 373 subportadoras / DQPSK</dd>
    <dt>CRIADO</dt><dd>${new Date(meta.created_at).toLocaleString("pt-BR")}</dd>
    <dt>ALTERADO</dt><dd>${new Date(meta.updated_at).toLocaleString("pt-BR")}</dd>
    <dt>AUTO-LOCK</dt><dd>${info ? humanSecs(info.autolock_secs) : "—"}</dd>`;
}

function wireSecurity(): void {
  const slider = $<HTMLInputElement>("sec-autolock");
  slider.addEventListener("input", () => setText("sec-autolock-label", humanSecs(Number(slider.value))));
  slider.addEventListener("change", async () => {
    const s = await api.sessionSetAutolock(Number(slider.value)).catch(() => null);
    if (s !== null) {
      slider.value = String(s);
      setText("sec-autolock-label", humanSecs(s));
      toast(`auto-lock em ${humanSecs(s)}`);
    }
  });

  $("sec-lock-now").addEventListener("click", () => void lockNow("trancado manualmente"));

  $("sec-change").addEventListener("click", async () => {
    const nova = $<HTMLInputElement>("sec-newpass").value;
    if (!nova) {
      toast("digite a nova senha", "warn");
      return;
    }
    const mode = meta?.keyfile_mode ?? "none";
    let path: string | null = null;
    if (mode !== "none") {
      const picked = await openDialog({ title: "Confirme o keyfile atual", filters: WAV_FILTER, multiple: false });
      if (typeof picked !== "string") return;
      path = picked;
    }
    const ok = await guard("re-embrulhando chave...", () => api.masterChange(nova, mode, path));
    if (ok !== undefined) {
      $<HTMLInputElement>("sec-newpass").value = "";
      toast("senha mestra trocada");
    }
  });

  $("sec-totp-begin").addEventListener("click", async () => {
    const s = await guard("gerando segredo...", () => api.totpSetupBegin());
    if (!s) return;
    show($("sec-totp-setup"), true);
    $("sec-qr").innerHTML = s.qr_svg;
    setText("sec-totp-secret", s.secret);
    $("sec-totp-confirm").dataset.secret = s.secret;
    $<HTMLInputElement>("sec-totp-code").focus();
  });

  $("sec-totp-confirm").addEventListener("click", async () => {
    const secret = $("sec-totp-confirm").dataset.secret ?? "";
    const code = $<HTMLInputElement>("sec-totp-code").value;
    const ok = await guard("conferindo codigo...", () => api.totpEnable(secret, code));
    if (ok === undefined) return;
    show($("sec-totp-setup"), false);
    $<HTMLInputElement>("sec-totp-code").value = "";
    await refreshSecurity();
    toast("TOTP ativado");
  });

  $("sec-totp-off").addEventListener("click", async () => {
    if (!confirm("Desativar o segundo fator TOTP?")) return;
    const ok = await guard("desativando...", () => api.totpDisable());
    if (ok !== undefined) {
      await refreshSecurity();
      toast("TOTP desativado");
    }
  });

  $("sec-hello-on").addEventListener("click", async () => {
    toast("confirme o gesto do Windows Hello duas vezes", "warn", 6000);
    const ok = await guard("cadastrando no TPM...", () => api.helloEnroll());
    if (ok !== undefined) {
      await refreshSecurity();
      toast("Windows Hello cadastrado");
    }
  });

  $("sec-hello-off").addEventListener("click", async () => {
    const ok = await guard("removendo...", () => api.helloDisable());
    if (ok !== undefined) {
      await refreshSecurity();
      toast("Windows Hello removido");
    }
  });

  $("sec-keyfile-gen").addEventListener("click", async () => {
    const dest = await saveDialog({ title: "Onde salvar o keyfile", filters: WAV_FILTER, defaultPath: "passec-keyfile.wav" });
    if (!dest) return;
    const r = await guard("gerando keyfile...", () => api.keyfileGenerate(dest));
    if (!r) return;
    toast(`keyfile gerado (${humanDuration(r.duration_secs)}) — ative-o trocando a senha mestra`, "warn", 7000);
  });
}

/* ======================================================== modo em guarda === */

/** Teclas digitadas na sobreposicao, ainda nao enviadas. */
let guardBuffer: string[] = [];
/** Teclas digitadas ao configurar a combinacao. */
let patternBuffer: string[] = [];

const MAX_PATTERN = 16;

function renderGuardDots(): void {
  // Um ponto por tecla: mostra progresso sem revelar quais teclas foram
  // digitadas nem o comprimento que o cofre espera.
  $("guard-dots").innerHTML = guardBuffer.map(() => "<i></i>").join("");
}

function guardVisible(on: boolean): void {
  show($("guard-host"), on);
  if (on) {
    guardBuffer = [];
    renderGuardDots();
    setText("guard-status", "");
  }
}

async function enterGuard(): Promise<void> {
  const ok = await guard("entrando em guarda...", () => api.guardEnter());
  if (ok === undefined) return;

  const st = await api.guardStatus().catch(() => null);
  setText(
    "guard-hint",
    st?.has_pattern
      ? "digite a combinacao e pressione ENTER"
      : "nenhuma combinacao definida — use TRANCAR DE VERDADE e entre com a senha mestra",
  );
  guardVisible(true);
  statusBar("em guarda");
}

async function tryLeaveGuard(): Promise<void> {
  if (guardBuffer.length === 0) return;

  const tentativa = guardBuffer.join("");
  let certo: boolean | undefined;
  try {
    certo = await api.guardLeave(tentativa);
  } catch (e) {
    // Sem combinacao configurada, ou a sessao ja foi trancada por excesso de
    // erros: os dois casos terminam na tela de senha mestra.
    setText("guard-status", errMsg(e));
    const st = await api.guardStatus().catch(() => null);
    if (!st || st.state === "open") {
      guardVisible(false);
      await lockNow("trancado");
    }
    return;
  }

  if (certo) {
    guardVisible(false);
    statusBar("de volta");
    await refreshList();
    return;
  }

  // Errou: sacode os pontos, limpa e mostra quanto resta antes de trancar.
  const host = $("guard-host");
  host.classList.add("wrong");
  setTimeout(() => host.classList.remove("wrong"), 340);

  guardBuffer = [];
  renderGuardDots();

  const st = await api.guardStatus().catch(() => null);
  if (!st || st.state === "open") {
    guardVisible(false);
    await lockNow("trancado apos tentativas demais");
    return;
  }
  const restantes = st.max_attempts - st.attempts;
  setText(
    "guard-status",
    restantes <= 1
      ? "combinacao errada — a proxima tentativa tranca o cofre"
      : `combinacao errada — ${restantes} tentativas antes de trancar`,
  );
}

function wireGuard(): void {
  $("guard-to-lock").addEventListener("click", () => {
    guardVisible(false);
    void lockNow("trancado manualmente");
  });

  // Captura global: enquanto a sobreposicao esta aberta, o teclado e dela.
  window.addEventListener(
    "keydown",
    (e) => {
      if ($("guard-host").hidden) return;
      e.preventDefault();
      e.stopPropagation();

      if (e.key === "Enter") {
        void tryLeaveGuard();
      } else if (e.key === "Backspace") {
        guardBuffer.pop();
        renderGuardDots();
      } else if (e.key === "Escape") {
        guardVisible(false);
        void lockNow("trancado manualmente");
      } else if (e.key.length === 1 && guardBuffer.length < MAX_PATTERN) {
        guardBuffer.push(e.key);
        renderGuardDots();
      }
    },
    // Fase de captura: pega a tecla antes de qualquer campo da pagina.
    true,
  );
}

/* ------------------------------------------------- definir a combinacao --- */

function renderPatternField(): void {
  $<HTMLInputElement>("pattern-input").value = "•".repeat(patternBuffer.length);
  setText("pattern-len", String(patternBuffer.length));
}

function wirePattern(): void {
  const campo = $<HTMLInputElement>("pattern-input");

  campo.addEventListener("keydown", (e) => {
    e.preventDefault();
    if (e.key === "Backspace") {
      patternBuffer.pop();
    } else if (e.key.length === 1 && patternBuffer.length < MAX_PATTERN) {
      patternBuffer.push(e.key);
    }
    renderPatternField();
  });

  $("pattern-reset").addEventListener("click", () => {
    patternBuffer = [];
    renderPatternField();
    campo.focus();
  });

  $("pattern-save").addEventListener("click", async () => {
    const ok = await guard("gravando combinacao...", () => api.patternSet(patternBuffer.join("")));
    if (ok === undefined) return;
    patternBuffer = [];
    renderPatternField();
    await refreshSecurity();
    toast("combinacao gravada");
  });

  $("pattern-off").addEventListener("click", async () => {
    if (!confirm("Remover a combinacao? Sair do modo em guarda passara a exigir a senha mestra.")) {
      return;
    }
    const ok = await guard("removendo...", () => api.patternClear());
    if (ok !== undefined) {
      await refreshSecurity();
      toast("combinacao removida");
    }
  });

  $("guard-now").addEventListener("click", () => void enterGuard());
}

/* ==================================================== itens sob demanda ==== */

async function refreshCloudItems(): Promise<void> {
  const itens = await guard("consultando a nuvem...", () => api.cloudList());
  if (!itens) return;

  const lista = $<HTMLUListElement>("cloud-list");
  lista.innerHTML = "";

  for (const it of itens) {
    const li = document.createElement("li");
    li.className = it.local ? "" : "remote";
    li.innerHTML =
      '<span class="cloud-where ' +
      (it.local ? "here" : "") +
      '">' +
      (it.local ? "AQUI" : "NUVEM") +
      "</span>" +
      '<span class="cloud-item-main">' +
      '<span class="cloud-item-title">' +
      escapeHtml(it.title) +
      "</span>" +
      '<span class="cloud-item-sub">' +
      KIND_LABEL[it.kind] +
      (it.username ? " · " + escapeHtml(it.username) : "") +
      "</span></span>";

    const botao = document.createElement("button");
    botao.className = "btn small";
    botao.textContent = it.local ? "OCULTAR" : "TRAZER";
    botao.addEventListener("click", async () => {
      if (it.local) {
        const ok = await guard("ocultando...", () => api.entryArchive(it.id));
        if (ok === undefined) return;
        toast(`"${it.title}" saiu deste computador — continua na nuvem`);
      } else {
        const titulo = await guard("trazendo...", () => api.entryRestore(it.id));
        if (titulo === undefined) return;
        toast(`"${titulo}" trazido para este computador`);
      }
      await refreshCloudItems();
      await refreshList();
      await refreshSync();
    });

    li.appendChild(botao);
    lista.appendChild(li);
  }

  const aqui = itens.filter((i) => i.local).length;
  setText("cloud-count", `${aqui} de ${itens.length} aqui`);
}

function wireCloudItems(): void {
  $("cloud-refresh").addEventListener("click", () => void refreshCloudItems());
}

/* ============================================================ status ====== */

function startStatusLoop(): void {
  setInterval(() => {
    const d = new Date();
    setText("st-clock", d.toLocaleTimeString("pt-BR", { hour12: false }));
  }, 1000);

  // Enquanto em guarda, acompanha o prazo ate o bloqueio de verdade — que o
  // backend aplica sozinho, mesmo sem ninguem tocar na interface.
  setInterval(async () => {
    if ($("guard-host").hidden) return;
    const gs = await api.guardStatus().catch(() => null);
    if (!gs || gs.state === "open") {
      guardVisible(false);
      await lockNow("trancado por inatividade");
      return;
    }
    setText(
      "guard-countdown",
      gs.seconds_until_lock === null ? "—" : humanSecs(gs.seconds_until_lock),
    );
  }, 1000);

  setInterval(async () => {
    const info = await api.sessionInfo().catch(() => null);
    if (!info) return;
    setText("st-vault", `COFRE: ${info.unlocked ? "ABERTO" : "TRANCADO"}`);
    setText(
      "st-lock",
      info.seconds_until_lock === null ? "AUTO-LOCK: —" : `AUTO-LOCK: ${humanSecs(info.seconds_until_lock)}`,
    );
  }, 1000);
}

/** Renova o relogio de inatividade quando o usuario realmente age. */
function wireActivity(): void {
  let pending = false;
  const touch = () => {
    if (pending) return;
    pending = true;
    // Agrupa rajadas de eventos numa unica chamada por segundo, senao cada
    // tecla digitada viraria uma ida ao backend.
    setTimeout(() => {
      pending = false;
      void api.sessionTouch().catch(() => undefined);
    }, 1000);
  };
  for (const ev of ["keydown", "mousedown", "wheel"]) {
    window.addEventListener(ev, touch, { passive: true });
  }

  window.addEventListener("keydown", (e) => {
    if (e.ctrlKey && e.key.toLowerCase() === "l") {
      e.preventDefault();
      void lockNow("trancado manualmente");
    }
    if (e.ctrlKey && e.key.toLowerCase() === "g") {
      e.preventDefault();
      void enterGuard();
    }
  });
}

/* ============================================================== inicio ==== */

async function main(): Promise<void> {
  wireModal();
  wireTitlebar();
  wireLock();
  wireTabs();
  wireVault();
  wireGenerator();
  wireTape();
  wireStego();
  wireCloud();
  wireAdopt();
  wireGuard();
  wirePattern();
  wireCloudItems();
  wireSecurity();
  wireActivity();
  startStatusLoop();

  // O backend tranca sozinho por inatividade e avisa; a interface precisa
  // acompanhar, senao continuaria mostrando uma tela de cofre aberto.
  await listen("vault-locked", () => void lockNow("trancado por inatividade"));

  await boot();
}

void main().catch((e) => {
  document.body.innerHTML = `<pre style="padding:24px;color:#ff5f52">falha ao iniciar: ${escapeHtml(errMsg(e))}</pre>`;
});
