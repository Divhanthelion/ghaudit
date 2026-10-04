// Talks to the Rust side through the app's own commands. The page has no other access:
// no file system and no shell. File dialogs, file reads and links are handled in Rust,
// and the GitHub token never comes to the page.

const tauri = window.__TAURI__;

/** Run a command; rejects with an Error whose message is a sentence for the user. */
async function invoke(command, args) {
  if (!tauri) throw new Error("This page only works inside the ghaudit app.");
  try {
    return await tauri.core.invoke(command, args);
  } catch (e) {
    throw new Error(typeof e === "string" ? e : (e?.message ?? String(e)));
  }
}

/** Versions and the names of every rule. */
export const catalog = () => invoke("catalog");

/** Ask for a report file. Resolves to {name, report}, or null if cancelled. */
export const openReport = () => invoke("open_report");

/** Open a github.com or osv.dev link in the browser (anything else is refused). */
export const openLink = (url) => invoke("open_link", { url });

/**
 * What scans can use: { github: {source, login}, keychain: {available, saved},
 * github_cli, osv_scanner: {path, version} | null, git: {...} | null }.
 * Never the token itself.
 */
export const environment = () => invoke("environment");

/** Check a token with GitHub and keep it in the system keychain. Resolves to its login. */
export const saveToken = (token) => invoke("save_token", { token });

/** Remove the token saved in the system keychain. */
export const forgetToken = () => invoke("forget_token");

/** Ask for a folder to scan. Resolves to its path for display, or null if cancelled. */
export const pickFolder = () => invoke("pick_folder");

/**
 * Run a scan. `onProgress` receives ghaudit's progress events as they happen. Resolves
 * to {outcome: "finished", report} or {outcome: "cancelled"}.
 */
export function startScan(options, onProgress) {
  if (!tauri) return invoke("start_scan");
  const channel = new tauri.core.Channel();
  channel.onmessage = onProgress;
  return invoke("start_scan", { options, onProgress: channel });
}

/** Stop the running scan; startScan then resolves as cancelled. */
export const cancelScan = () => invoke("cancel_scan");

/**
 * Ask for an earlier report and compare the one on screen with it. Resolves to
 * {name, scanned, report} (the report without findings the earlier one had), or null.
 */
export const compareWith = () => invoke("compare_with");

/** Stop comparing with an earlier report. */
export const clearComparison = () => invoke("clear_comparison");

/**
 * Save the report on screen through the save dialog. format: "json", "sarif" or "text";
 * onlyNew leaves out findings the compared report had. Resolves to the file name, or null.
 */
export const exportReport = (format, onlyNew) => invoke("export_report", { format, onlyNew });
