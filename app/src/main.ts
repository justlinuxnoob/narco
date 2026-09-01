/**
 * Narco UI.
 *
 * This layer holds no keys and does no cryptography — all of it lives in Rust.
 * Its one security responsibility is to never persist anything: no
 * localStorage, no sessionStorage, no cookies, no IndexedDB. Messages live in
 * the DOM and nowhere else, and the DOM is cleared when the session ends.
 */

import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";

type UiEvent =
  | { kind: "status"; text: string; stage: string }
  | { kind: "ready" }
  | { kind: "message"; text: string }
  | { kind: "ended"; reason: string };

const $ = <T extends HTMLElement>(id: string) => {
  const el = document.getElementById(id);
  if (!el) throw new Error(`missing element #${id}`);
  return el as T;
};

const screens = {
  entry: $("entry"),
  connecting: $("connecting"),
  chat: $("chat"),
  ended: $("ended"),
};

function show(name: keyof typeof screens) {
  for (const [key, el] of Object.entries(screens)) {
    el.classList.toggle("hidden", key !== name);
  }
}

// --- secret fields --------------------------------------------------------

const secretsBox = $("secrets");
const entryError = $("entry-error");
const setError = (msg: string) => {
  entryError.textContent = msg;
};

const secretInputs = () =>
  Array.from(secretsBox.querySelectorAll<HTMLInputElement>("input"));

/** Renumber rows and hide the remove button when only one field is left. */
function relabel() {
  const rows = Array.from(secretsBox.children) as HTMLElement[];
  rows.forEach((row, i) => {
    row.querySelector(".n")!.textContent = String(i + 1);
    row.querySelector<HTMLButtonElement>(".remove")!.hidden = rows.length === 1;
    const input = row.querySelector<HTMLInputElement>("input")!;
    input.placeholder = i === 0 ? "shared code" : "another secret";
  });
}

/** Briefly relabel a button to confirm an action, then restore it. */
function flash(btn: HTMLButtonElement, text: string) {
  const original = btn.textContent;
  btn.textContent = text;
  btn.disabled = true;
  setTimeout(() => {
    btn.textContent = original;
    btn.disabled = false;
  }, 900);
}

function addSecret(focus = false) {
  const row = document.createElement("div");
  row.className = "secret";

  const n = document.createElement("span");
  n.className = "n";

  const input = document.createElement("input");
  input.type = "text";
  input.autocomplete = "off";
  input.spellcheck = false;
  input.addEventListener("keydown", (e) => {
    if (e.key === "Enter") start();
  });

  // Every secret gets its own generate, not just the first — a hand-typed
  // second secret is usually far weaker than a generated one.
  const gen = document.createElement("button");
  gen.type = "button";
  gen.className = "icon";
  gen.textContent = "gen";
  gen.title = "generate a random secret";
  gen.addEventListener("click", async () => {
    input.value = await invoke<string>("generate_code");
    setError("");
    flash(gen, "done");
  });

  const copy = document.createElement("button");
  copy.type = "button";
  copy.className = "icon";
  copy.textContent = "copy";
  copy.title = "copy to clipboard";
  copy.addEventListener("click", async () => {
    if (!input.value) return;
    try {
      await navigator.clipboard.writeText(input.value);
      flash(copy, "ok");
    } catch {
      // Clipboard can be unavailable; selecting still lets the user copy.
      input.select();
      flash(copy, "select");
    }
  });

  const remove = document.createElement("button");
  remove.type = "button";
  remove.className = "remove";
  remove.textContent = "×";
  remove.setAttribute("aria-label", "remove this secret");
  remove.addEventListener("click", () => {
    row.remove();
    relabel();
  });

  row.append(n, input, gen, copy, remove);
  secretsBox.append(row);
  relabel();
  if (focus) input.focus();
}

addSecret();
$("add").addEventListener("click", () => addSecret(true));

// --- connecting progress --------------------------------------------------

const STAGES = ["tor", "publish", "peer", "verify"] as const;
let elapsedTimer: number | undefined;
let startedAt = 0;

/** Mark stages before `stage` done, `stage` active, the rest pending. */
function setStage(stage: string) {
  const idx = STAGES.indexOf(stage as (typeof STAGES)[number]);
  if (idx < 0) return;
  for (const [i, name] of STAGES.entries()) {
    const li = document.querySelector<HTMLLIElement>(`li[data-stage="${name}"]`);
    if (!li) continue;
    li.classList.toggle("done", i < idx);
    li.classList.toggle("active", i === idx);
  }
}

function startElapsed() {
  startedAt = Date.now();
  stopElapsed();
  // A visibly moving clock is the difference between "working" and "frozen".
  elapsedTimer = window.setInterval(() => {
    const s = Math.floor((Date.now() - startedAt) / 1000);
    $("elapsed").textContent = `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`;
    if (s > 360) {
      $("patience").innerHTML =
        "Taking longer than usual. It can still succeed — but check that the " +
        "other person has the app open with <strong>exactly</strong> the same " +
        "secrets, in the same order.";
    }
  }, 1000);
}

function stopElapsed() {
  if (elapsedTimer !== undefined) clearInterval(elapsedTimer);
  elapsedTimer = undefined;
}

// --- entry ----------------------------------------------------------------

async function start() {
  const secrets = secretInputs()
    .map((i) => i.value.trim())
    .filter((s) => s.length > 0);

  if (secrets.length === 0) {
    setError("Enter a shared code, or press gen to make one.");
    return;
  }

  // Check locally first: an instant, specific error beats waiting minutes to
  // discover the code was malformed.
  try {
    await invoke("check_code", { code: secrets[0] });
  } catch (e) {
    setError(String(e));
    return;
  }

  setError("");
  $("status").textContent = "Starting…";
  setStage("tor");
  show("connecting");
  startElapsed();

  const idleSecs = Number($<HTMLSelectElement>("idle").value);
  try {
    await invoke("connect", { secrets, idleSecs });
  } catch (e) {
    endWith(String(e));
  }
}

$("start").addEventListener("click", start);

$("cancel").addEventListener("click", async () => {
  await invoke("end_session");
  endWith("You cancelled.");
});

// --- chat -----------------------------------------------------------------

const messages = $<HTMLOListElement>("messages");
const input = $<HTMLInputElement>("input");
/** Timers for disappearing messages, so they can be cancelled on wipe. */
const burnTimers: number[] = [];

const burnSeconds = () => Number($<HTMLSelectElement>("burn").value);

function addMessage(text: string, who: "me" | "them" | "note") {
  const li = document.createElement("li");
  li.className = who;
  // textContent, never innerHTML: a peer-supplied string must never be parsed
  // as markup.
  li.textContent = text;
  messages.append(li);
  messages.scrollTop = messages.scrollHeight;

  const secs = burnSeconds();
  if (secs > 0 && who !== "note") {
    burnTimers.push(
      window.setTimeout(() => {
        li.remove();
      }, secs * 1000),
    );
  }
}

$<HTMLFormElement>("composer").addEventListener("submit", async (e) => {
  e.preventDefault();
  const text = input.value;
  if (!text.trim()) return;
  input.value = "";
  try {
    await invoke("send", { text });
    addMessage(text, "me");
  } catch (err) {
    addMessage(String(err), "note");
  }
});

$("end").addEventListener("click", () => invoke("end_session"));

// --- ended ----------------------------------------------------------------

function endWith(reason: string) {
  stopElapsed();
  for (const t of burnTimers.splice(0)) clearTimeout(t);
  // Destroy every trace of the conversation in the UI. Rust has already
  // zeroized the keys.
  messages.replaceChildren();
  input.value = "";
  $("ended-reason").textContent = reason;
  show("ended");
}

$("again").addEventListener("click", () => {
  secretsBox.replaceChildren();
  addSecret(true);
  setError("");
  show("entry");
});

// --- events from Rust -----------------------------------------------------

listen<UiEvent>("narco", ({ payload }) => {
  switch (payload.kind) {
    case "status":
      $("status").textContent = payload.text;
      setStage(payload.stage);
      break;
    case "ready": {
      stopElapsed();
      setStage("verify");
      show("chat");
      const secs = burnSeconds();
      $("chat-mode").textContent =
        secs > 0 ? `encrypted · vanishing ${secs}s` : "encrypted";
      addMessage("Encrypted. Messages are gone when this ends.", "note");
      input.focus();
      break;
    }
    case "message":
      addMessage(payload.text, "them");
      break;
    case "ended":
      endWith(payload.reason);
      break;
  }
});
