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
