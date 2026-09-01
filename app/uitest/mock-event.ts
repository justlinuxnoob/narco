// Stand-in for @tauri-apps/api/event.
export async function listen(_n: string, cb: (e: any) => void) {
  (window as any).__emit = (payload: any) => cb({ payload });
  return () => {};
}
