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
  | { kind: "status"; text: string }
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

function secretInputs(): HTMLInputElement[] {
  return Array.from(secretsBox.querySelectorAll<HTMLInputElement>("input"));
}

/** Renumber and show remove buttons only when there is more than one field. */
function relabel() {
  const rows = Array.from(secretsBox.children) as HTMLElement[];
  rows.forEach((row, i) => {
    row.querySelector(".n")!.textContent = String(i + 1);
    const remove = row.querySelector<HTMLButtonElement>(".remove")!;
    remove.hidden = rows.length === 1;
  });
  const first = secretInputs()[0];
  if (first) first.placeholder = "shared code";
}

function addSecret(value = "", focus = false) {
  const row = document.createElement("div");
  row.className = "secret";

  const n = document.createElement("span");
  n.className = "n";

  const input = document.createElement("input");
  input.type = "text";
  input.autocomplete = "off";
  input.spellcheck = false;
  input.placeholder = "another secret";
  input.value = value;
  input.addEventListener("keydown", (e) => {
    if (e.key === "Enter") start();
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

  row.append(n, input, remove);
  secretsBox.append(row);
  relabel();
  if (focus) input.focus();
}

addSecret();

$("add").addEventListener("click", () => addSecret("", true));

$("generate").addEventListener("click", async () => {
  const code = await invoke<string>("generate_code");
  const first = secretInputs()[0];
  first.value = code;
  first.focus();
  first.select();
  setError("");
});

// --- entry ----------------------------------------------------------------

const entryError = $("entry-error");
const setError = (msg: string) => {
  entryError.textContent = msg;
};

async function start() {
  const secrets = secretInputs()
    .map((i) => i.value.trim())
    .filter((s) => s.length > 0);

  if (secrets.length === 0) {
    setError("Enter a shared code.");
    return;
  }

  // Check the code locally first so the user gets an instant, specific error
  // instead of waiting minutes to find out it was malformed.
  try {
    await invoke("check_code", { code: secrets[0] });
  } catch (e) {
    setError(String(e));
    return;
  }

  setError("");
  setStatus("Starting…");
  show("connecting");

  try {
    await invoke("connect", { secrets });
  } catch (e) {
    endWith(String(e));
  }
}

$("start").addEventListener("click", start);

// --- connecting -----------------------------------------------------------

const setStatus = (text: string) => {
  $("status").textContent = text;
};

$("cancel").addEventListener("click", async () => {
  await invoke("end_session");
  endWith("You cancelled.");
});

// --- chat -----------------------------------------------------------------

const messages = $<HTMLOListElement>("messages");
const input = $<HTMLInputElement>("input");

function addMessage(text: string, who: "me" | "them" | "note") {
  const li = document.createElement("li");
  li.className = who;
  // textContent, never innerHTML: a peer-supplied string must never be parsed
  // as markup.
  li.textContent = text;
  messages.append(li);
  messages.scrollTop = messages.scrollHeight;
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
  // Destroy every trace of the conversation in the UI. The Rust side has
  // already zeroized the keys.
  messages.replaceChildren();
  input.value = "";
  $("ended-reason").textContent = reason;
  show("ended");
}

$("again").addEventListener("click", () => {
  secretsBox.replaceChildren();
  addSecret("", true);
  setError("");
  show("entry");
});

// --- events from Rust -----------------------------------------------------

listen<UiEvent>("narco", ({ payload }) => {
  switch (payload.kind) {
    case "status":
      setStatus(payload.text);
      break;
    case "ready":
      show("chat");
      addMessage("Encrypted. Messages are gone when this ends.", "note");
      input.focus();
      break;
    case "message":
      addMessage(payload.text, "them");
      break;
    case "ended":
      endWith(payload.reason);
      break;
  }
});
