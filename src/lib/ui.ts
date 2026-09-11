/** Utilidades de interface: DOM, avisos, modal e area de transferencia. */

/** `getElementById` com tipo, que estoura cedo se o id nao existir no HTML. */
export function $<T extends HTMLElement = HTMLElement>(id: string): T {
  const el = document.getElementById(id);
  if (!el) throw new Error(`elemento ausente no HTML: #${id}`);
  return el as T;
}

export function show(el: HTMLElement, visible: boolean): void {
  el.hidden = !visible;
}

export function setText(id: string, text: string): void {
  $(id).textContent = text;
}

/* --------------------------------------------------------------- avisos -- */

type ToastKind = "ok" | "err" | "warn";

export function toast(message: string, kind: ToastKind = "ok", ms = 4200): void {
  const host = $("toast-host");
  const el = document.createElement("div");
  el.className = `toast ${kind === "ok" ? "" : kind}`.trim();
  el.textContent = message;
  host.appendChild(el);
  setTimeout(() => el.remove(), ms);
}

export function status(message: string, ok = false): void {
  const el = $("lock-status");
  el.textContent = message;
  el.classList.toggle("ok", ok);
}

export function statusBar(message: string): void {
  setText("st-msg", message);
}

/* ---------------------------------------------------------------- modal -- */

let modalResolve: ((value: string | null) => void) | null = null;

/**
 * Pede uma senha pontual (exportar item, restaurar fita).
 *
 * Devolve `null` no cancelamento, para o chamador distinguir "desistiu" de
 * "digitou vazio" — as duas coisas precisam de tratamento diferente.
 */
export function askPassword(title: string, text: string, label = "SENHA"): Promise<string | null> {
  const host = $("modal-host");
  setText("modal-title", title);
  setText("modal-text", text);
  setText("modal-label", label);

  const input = $<HTMLInputElement>("modal-input");
  input.value = "";
  host.hidden = false;
  // `setTimeout` porque focar um elemento que acabou de sair de `hidden` no
  // mesmo tick e ignorado pelo navegador.
  setTimeout(() => input.focus(), 0);

  return new Promise((resolve) => {
    modalResolve = resolve;
  });
}

function closeModal(value: string | null): void {
  $("modal-host").hidden = true;
  const input = $<HTMLInputElement>("modal-input");
  const resolve = modalResolve;
  modalResolve = null;
  // Limpa o campo depois de ler: a senha nao deve ficar no DOM esperando a
  // proxima abertura do modal.
  input.value = "";
  resolve?.(value);
}

export function wireModal(): void {
  $("modal-ok").addEventListener("click", () => closeModal($<HTMLInputElement>("modal-input").value));
  $("modal-cancel").addEventListener("click", () => closeModal(null));
  $<HTMLInputElement>("modal-input").addEventListener("keydown", (e) => {
    if (e.key === "Enter") closeModal($<HTMLInputElement>("modal-input").value);
    if (e.key === "Escape") closeModal(null);
  });
}

/* ------------------------------------------------- area de transferencia -- */

/** Segundos ate a area de transferencia ser limpa sozinha. */
const CLIPBOARD_TTL = 25;

let clipboardTimer: number | undefined;
let lastCopied = "";

/**
 * Copia e agenda a limpeza.
 *
 * A area de transferencia e global: qualquer programa aberto consegue ler o
 * que esta la. Deixar uma senha parada nela ate a proxima copia e um vazamento
 * silencioso, entao apagamos sozinhos depois de alguns segundos.
 *
 * A limpeza so acontece se o conteudo ainda for o nosso — se o usuario copiou
 * outra coisa nesse meio tempo, apagar destruiria o trabalho dele.
 */
export async function copySecret(text: string, what = "valor"): Promise<void> {
  if (!text) {
    toast("nada para copiar", "warn");
    return;
  }
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    toast("o sistema recusou o acesso a area de transferencia", "err");
    return;
  }

  lastCopied = text;
  toast(`${what} copiado — sera apagado em ${CLIPBOARD_TTL}s`);

  clearTimeout(clipboardTimer);
  clipboardTimer = window.setTimeout(async () => {
    try {
      const atual = await navigator.clipboard.readText();
      if (atual === lastCopied) {
        await navigator.clipboard.writeText("");
        statusBar("area de transferencia limpa");
      }
    } catch {
      // Sem permissao de leitura: limpamos assim mesmo, porque deixar a senha
      // la e o risco maior.
      try {
        await navigator.clipboard.writeText("");
      } catch {
        /* nada mais a fazer */
      }
    }
    lastCopied = "";
  }, CLIPBOARD_TTL * 1000);
}

/* ------------------------------------------------------------ formatacao - */

export function humanBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

export function humanSecs(s: number): string {
  if (s < 60) return `${Math.round(s)}s`;
  const m = Math.floor(s / 60);
  const r = Math.round(s % 60);
  return r ? `${m}min ${r}s` : `${m}min`;
}

export function humanDuration(secs: number): string {
  const m = Math.floor(secs / 60);
  const s = Math.floor(secs % 60);
  return `${m}:${String(s).padStart(2, "0")}`;
}

/* --------------------------------------------------------- efeito boot --- */

/** Escreve linhas uma a uma, imitando um terminal subindo. */
export function typeLines(
  el: HTMLElement,
  lines: string[],
  perLine = 90,
): Promise<void> {
  return new Promise((resolve) => {
    let i = 0;
    const tick = () => {
      if (i >= lines.length) {
        resolve();
        return;
      }
      el.insertAdjacentHTML("beforeend", `${lines[i]}\n`);
      i += 1;
      setTimeout(tick, perLine);
    };
    tick();
  });
}
