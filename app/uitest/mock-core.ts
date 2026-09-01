// Stand-in for @tauri-apps/api/core so the real UI can run in a browser.
(window as any).__CALLS__ = (window as any).__CALLS__ || [];
export async function invoke(cmd: string, args?: any): Promise<any> {
  (window as any).__CALLS__.push({ cmd, args });
  (window as any).__log?.(`invoke ${cmd} ${args ? JSON.stringify(args) : ""}`);
  if (cmd === "generate_code") return "PWXK7M2QRT9HFZDLMN4VB8SGJ3";
  if (cmd === "get_logs")
    return "[narco] narco 0.4.1 starting on windows\n[narco] tor: Joining the Tor network… 15% (ready=false failed=false)\ntor_dirmgr: unable to open cache database";
  if (cmd === "check_code") {
    const c = String(args?.code ?? "").trim();
    if (c.length < 10) throw "code must be at least 10 characters";
    if (new Set(c).size < 6) throw "code must use at least 6 different characters";
  }
  return null;
}
