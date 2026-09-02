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
  | { kind: "message"; from: string; text: string }
  | { kind: "ended"; reason: string }
  | { kind: "idleWarning"; secondsLeft: number; active: boolean }
  | { kind: "reconnecting" }
  | { kind: "reconnected" }
  | { kind: "torProgress"; text: string; ready: boolean; failed: boolean };

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
    // Enter runs whichever side the user already chose.
    if (e.key === "Enter" && mode) start(mode === "host");
  });

  // Track where each value came from. A generated code carries 130 bits; a
  // typed one is usually nearer 30, and the room's onion address is derived
  // from it — so a guessable code is a joinable room, guessed offline against
  // the Tor directory without ever touching either of us.
  input.addEventListener("input", () => {
    delete input.dataset.generated;
    updateTypedWarning();
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
    input.dataset.generated = "1";
    setError("");
    updateTypedWarning();
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
    updateTypedWarning();
  });

  row.append(n, input, gen, copy, remove);
  secretsBox.append(row);
  relabel();
  updateTypedWarning();
  if (focus) input.focus();
}

/**
 * Warn when any secret was typed rather than generated — but only when
 * starting. The joiner types by definition: they are copying what they were
 * sent, and telling them off for it would be noise.
 */
function updateTypedWarning() {
  const typed = secretInputs().some(
    (i) => i.value.length > 0 && i.dataset.generated !== "1",
  );
  $("typed-warning").hidden = mode !== "host" || !typed;
  // Advice about sending secrets separately is noise until there is a second
  // one to send.
  $("multi-hint").hidden = secretInputs().length < 2;
}

// --- choosing a side ------------------------------------------------------

/** null until the user says whether they are starting or joining. */
let mode: "host" | "join" | null = null;

const LEAD = {
  host: "Send this code to the other person, then press start.",
  join: "Paste the code they sent you.",
};
async function choose(next: "host" | "join") {
  mode = next;
  $("choose").hidden = true;
  $("compose").hidden = false;
  $("compose-lead").textContent = LEAD[next];
  // Label it for this side, unless Tor is still coming up and the button is
  // busy saying so.
  setStartReady(!goBtn.disabled);
  setError("");

  secretsBox.replaceChildren();
  addSecret();
  const first = secretInputs()[0];
  if (next === "host") {
    // Generate up front. The strongest option should be the one you get by
    // doing nothing, not the one you get by noticing a button.
    first.value = await invoke<string>("generate_code");
    first.dataset.generated = "1";
    first.select();
  } else {
    first.focus();
  }
  updateTypedWarning();
}

$("choose-host").addEventListener("click", () => choose("host"));
$("choose-join").addEventListener("click", () => choose("join"));
$("back").addEventListener("click", () => {
  mode = null;
  $("compose").hidden = true;
  $("choose").hidden = false;
  secretsBox.replaceChildren();
  setError("");
});

$("add").addEventListener("click", () => addSecret(true));

// Join Tor immediately, without waiting for secrets — it needs none. This hides
// the slowest stage behind the time spent typing and sharing a code, and the
// client stays alive so a second chat skips it entirely.
const warmTor = () => {
  $("tor-retry").hidden = true;
  $("tor-state").textContent = "joining tor…";
  $("tor-state").classList.remove("ready", "failed");
  setStartReady(false);
  invoke("warm_tor").catch(() => {});
};
$("tor-retry").addEventListener("click", warmTor);
// The initial warmTor() is deferred until the event listener is attached (see
// the bottom of this file) so the first Tor events are never dropped.

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
    if (s > 150) {
      $("patience").textContent =
        "Taking longer than usual. Check they have the app open with exactly " +
        "the same secrets, in the same order.";
    }
  }, 1000);
}

function stopElapsed() {
  if (elapsedTimer !== undefined) clearInterval(elapsedTimer);
  elapsedTimer = undefined;
}

// --- entry ----------------------------------------------------------------

async function start(host: boolean) {
  const secrets = secretInputs()
    .map((i) => i.value.trim())
    .filter((s) => s.length > 0);

  if (secrets.length === 0) {
    setError("Enter a shared code, or press gen to make one.");
    return;
  }

  // Check locally first: an instant, specific error beats waiting minutes to
  // discover the code was malformed. Every secret, not just the first — each
  // one feeds the derivation, so a bad third secret fails just as hard, and it
  // used to fail silently minutes later as "nobody showed up".
  for (const [i, secret] of secrets.entries()) {
    try {
      await invoke("check_code", { code: secret });
    } catch (e) {
      setError(secrets.length > 1 ? `Secret ${i + 1}: ${e}` : String(e));
      return;
    }
  }

  setError("");
  $("status").textContent = "Starting…";
  setStage("tor");

  // The host shares the code, so keep it visible on the connecting screen.
  // Show ALL secrets: the address derives from every one, so the joiner must
  // enter them all, in order. (This previously showed only the first, so a
  // multi-secret host published at an address the joiner could never derive —
  // which looked like "2+ secrets don't connect".)
  const share = $("share");
  if (host) {
    $("share-code").textContent =
      secrets.length === 1
        ? secrets[0]
        : secrets.map((s, i) => `${i + 1}. ${s}`).join("\n");
    share.hidden = false;
  } else {
    share.hidden = true;
  }

  show("connecting");
  startElapsed();

  const idleSecs = Number($<HTMLSelectElement>("idle").value);
  try {
    const nickname = $<HTMLInputElement>("nickname").value.trim().replace(/\0/g, "");
    await invoke("connect", { secrets, idleSecs, host, nickname });
  } catch (e) {
    endWith(String(e));
  }
}

// Starting is disabled until Tor is ready — pressing earlier would just wait
// on a connection that hasn't happened yet, which looks broken. Choosing a
// side stays available, so the code can be generated and sent meanwhile.
const goBtn = $<HTMLButtonElement>("go");
goBtn.disabled = true;
goBtn.addEventListener("click", () => start(mode === "host"));
$("share-copy").addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText($("share-code").textContent ?? "");
    flash($<HTMLButtonElement>("share-copy"), "ok");
  } catch {
    /* clipboard may be unavailable; the code is on screen to copy by hand */
  }
});

/** Reflect Tor readiness on the action button. */
function setStartReady(ready: boolean) {
  goBtn.disabled = !ready;
  if (!ready) {
    goBtn.textContent = "connecting to tor…";
  } else if (mode) {
    goBtn.textContent = mode === "host" ? "start & wait for them" : "join";
  }
}

$("cancel").addEventListener("click", async () => {
  // Say what is happening, then let the backend confirm it with an "ended"
  // event. Declaring it cancelled here was a lie: the session kept running,
  // kept the onion service published, and could still drop the user into a
  // chat they thought they had killed.
  $("status").textContent = "Cancelling…";
  await invoke("end_session");
});

// --- chat -----------------------------------------------------------------

const messages = $<HTMLOListElement>("messages");
const input = $<HTMLInputElement>("input");
/** Timers for disappearing messages, so they can be cancelled on wipe. */
const burnTimers: number[] = [];

/** Ticks the idle countdown while it is on screen. */
let idleCountdown: number | undefined;

const burnSeconds = () => Number($<HTMLSelectElement>("burn").value);

function addMessage(text: string, who: "me" | "them" | "note", from = "") {
  const li = document.createElement("li");
  li.className = who;
  // A name the sender chose, shown so a three-person room reads correctly. It
  // is not authenticated — everyone present already holds the secret — so it
  // distinguishes people rather than proving who they are.
  if (from) {
    const tag = document.createElement("span");
    tag.className = "who";
    // textContent, never innerHTML: this came from the peer.
    tag.textContent = from;
    li.append(tag);
  }
  const body = document.createElement("span");
  body.textContent = text;
  li.append(body);
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
  if (idleCountdown !== undefined) clearInterval(idleCountdown);
  idleCountdown = undefined;
  $("idle-warning").hidden = true;
  for (const t of burnTimers.splice(0)) clearTimeout(t);
  // Destroy every trace of the conversation in the UI. Rust has already
  // zeroized the keys.
  messages.replaceChildren();
  input.value = "";
  // The share box holds the host's secrets in full. It was never cleared, so
  // they stayed in the DOM for the life of the app — visible again the moment
  // anyone hit "start over".
  $("share-code").textContent = "";
  $("share").hidden = true;
  $("ended-reason").textContent = reason;
  show("ended");
}

$("again").addEventListener("click", () => {
  // Back to the choice, not to a half-filled form: the next conversation gets
  // its own code, and the previous one's must not linger on screen.
  mode = null;
  secretsBox.replaceChildren();
  $("compose").hidden = true;
  $("choose").hidden = false;
  setError("");
  show("entry");
});

// --- diagnostics ----------------------------------------------------------

/** Pull the in-app log buffer (app + Tor internals) into an element. */
async function loadLogs(into: HTMLElement) {
  try {
    into.textContent = await invoke<string>("get_logs");
  } catch (e) {
    into.textContent = `could not read logs: ${e}`;
  }
}

const diag = $<HTMLDetailsElement>("diag");
diag.addEventListener("toggle", () => {
  if (diag.open) loadLogs($("diag-log"));
});
$("diag-refresh").addEventListener("click", () => loadLogs($("diag-log")));
$("diag-copy").addEventListener("click", async () => {
  await loadLogs($("diag-log"));
  try {
    await navigator.clipboard.writeText($("diag-log").textContent ?? "");
    flash($<HTMLButtonElement>("diag-copy"), "copied");
  } catch {
    // Clipboard can be unavailable; the text is on screen to select by hand.
  }
});

// The ended screen is where failures land, so surface the logs there too.
$("ended-diag").addEventListener("click", async () => {
  const pre = $("ended-log");
  pre.hidden = !pre.hidden;
  if (!pre.hidden) await loadLogs(pre);
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
      addMessage(payload.text, "them", payload.from);
      break;
    case "idleWarning": {
      // Counts down rather than showing a fixed number, so it is obviously
      // live and obviously avoidable — anything you send calls it off.
      const el = $("idle-warning");
      if (idleCountdown !== undefined) clearInterval(idleCountdown);
      if (!payload.active) {
        el.hidden = true;
        break;
      }
      let left = payload.secondsLeft;
      const tick = () => {
        el.textContent = `No activity — this chat ends in ${left}s. Send anything to stay.`;
        if (left-- <= 0 && idleCountdown !== undefined) clearInterval(idleCountdown);
      };
      tick();
      el.hidden = false;
      idleCountdown = window.setInterval(tick, 1000);
      break;
    }
    // The conversation is not over, so the messages stay. Only the header
    // changes, and the composer waits until there is somewhere to send.
    case "reconnecting":
      $("chat-mode").textContent = "reconnecting…";
      $<HTMLInputElement>("input").disabled = true;
      addMessage("Connection lost. Getting it back…", "note");
      break;
    case "reconnected": {
      const secs = burnSeconds();
      $("chat-mode").textContent = secs > 0 ? `encrypted · vanishing ${secs}s` : "encrypted";
      $<HTMLInputElement>("input").disabled = false;
      addMessage("Back.", "note");
      input.focus();
      break;
    }
    case "ended":
      endWith(payload.reason);
      break;
    case "torProgress": {
      $("tor-state").textContent = payload.ready ? "tor ready" : payload.text;
      $("tor-state").classList.toggle("ready", payload.ready);
      $("tor-state").classList.toggle("failed", payload.failed);
      // Only allow starting once Tor is actually up.
      setStartReady(payload.ready);
      // A failed bootstrap must be recoverable without restarting the app.
      $("tor-retry").hidden = !payload.failed;
      if (payload.failed) {
        // If the user already pressed start, take them off the connecting
        // screen rather than leaving them watching a dead clock.
        if (!screens.connecting.classList.contains("hidden")) endWith(payload.text);
      } else if (payload.ready) {
        setStage("publish");
      }
      break;
    }
  }
}).then(() => {
  // Listener is attached; now it is safe to start Tor without racing it.
  warmTor();
});
