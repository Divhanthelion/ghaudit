// The scan setup page: what to scan, what to check, and GitHub access. Options are
// remembered on this computer (they hold nothing secret); the token never comes here.

import { h, replace, icon, toast, phone } from "./dom.js";
import * as backend from "./backend.js";
import * as nav from "./nav.js";
import { ANALYZER, SEVERITIES } from "./explain.js";

const STORE_KEY = "ghaudit.scan-options.v1";

/**
 * Defaults are thorough for repositories you own: git history (where deleted
 * credentials still live) and archived repositories (still readable, so their leaks
 * still count). Forks are left out: their code is mostly someone else's.
 */
export const DEFAULTS = Object.freeze({
  kind: "mine",
  repo: "",
  org: "",
  user: "",
  query: "",
  checks: Object.freeze({ sast: true, secrets: true, sca: true, workflows: true, agents: true, settings: true }),
  history: true,
  includeArchived: true,
  includeForks: false,
  minSeverity: "low",
  maxRepos: 100,
});

export const TARGETS = [
  { kind: "mine", label: "My repositories", icon: "user", multi: true },
  {
    kind: "repo",
    label: "One repository",
    icon: "repo",
    text: "Any repository on github.com you can read.",
    field: { key: "repo", label: "Repository", placeholder: "owner/name or https://github.com/owner/name" },
  },
  { kind: "folder", label: "A folder", icon: "folder", text: "A project on this computer." },
  {
    kind: "org",
    label: "An organization",
    icon: "org",
    text: "Every repository of a GitHub organization.",
    multi: true,
    field: { key: "org", label: "Organization", placeholder: "organization name" },
  },
  {
    kind: "user",
    label: "Someone's repositories",
    icon: "users",
    text: "The public repositories of any GitHub user.",
    multi: true,
    field: { key: "user", label: "GitHub user", placeholder: "username" },
  },
  {
    kind: "search",
    label: "GitHub search",
    icon: "search",
    text: "Repositories matching a search.",
    multi: true,
    field: { key: "query", label: "Search", placeholder: "topic:cli language:rust stars:>100" },
  },
];

const CHECKS = ["sast", "secrets", "sca", "workflows", "agents", "settings"];

/** Shown where a phone can't do what the desktop app does (the backend's wording). */
export const PHONE_NOTES = {
  sca: "Not available on phones: dependency checks need osv-scanner, a desktop program. Scan from a computer to check dependencies.",
  history: "Needs the full git history, which a phone can't download.",
};

/**
 * What this device can do, from environment(). An app without these fields is a
 * desktop app from before phones, which can do everything.
 */
export function capabilities(env) {
  const c = env?.capabilities ?? {};
  return {
    folders: c.folders ?? true,
    history: c.history ?? true,
    dependencies: c.dependencies ?? true,
    download: c.download ?? "git",
    pasteToken: c.paste_token ?? false,
  };
}

/** The scan targets this device offers. */
export function targetsFor(env) {
  const caps = capabilities(env);
  return TARGETS.filter((t) => t.kind !== "folder" || caps.folders);
}

/** How to install osv-scanner on this system. */
function installOsv(env) {
  const platform = env?.platform ?? (navigator.userAgent.includes("Windows") ? "windows" : navigator.userAgent.includes("Mac") ? "macos" : "linux");
  if (platform === "windows") return "winget install --id Google.OSVScanner";
  if (platform === "macos") return "brew install osv-scanner";
  return "go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest";
}

// ------------------------------------------------------------------ options

/**
 * The options a scan really runs with: checks this device can't do are off, whatever
 * was saved (the saved choice comes back on a computer).
 */
export function effectiveOptions(o, env) {
  const caps = capabilities(env);
  return {
    ...o,
    kind: o.kind === "folder" && !caps.folders ? "mine" : o.kind,
    checks: { ...o.checks, sca: o.checks.sca && caps.dependencies },
    history: o.history && caps.history,
  };
}

/** Saved options, checked field by field (anything odd falls back to the default). */
export function loadOptions() {
  let saved = null;
  try {
    saved = JSON.parse(localStorage.getItem(STORE_KEY) ?? "null");
  } catch {
    saved = null;
  }
  const o = structuredClone({ ...DEFAULTS, checks: { ...DEFAULTS.checks } });
  if (!saved || typeof saved !== "object") return o;
  if (TARGETS.some((t) => t.kind === saved.kind)) o.kind = saved.kind;
  for (const key of ["repo", "org", "user", "query"]) {
    if (typeof saved[key] === "string") o[key] = saved[key].slice(0, 300);
  }
  for (const key of ["history", "includeArchived", "includeForks"]) {
    if (typeof saved[key] === "boolean") o[key] = saved[key];
  }
  for (const key of CHECKS) {
    if (typeof saved.checks?.[key] === "boolean") o.checks[key] = saved.checks[key];
  }
  if (SEVERITIES.some((s) => s.id === saved.minSeverity && s.id !== "unknown")) o.minSeverity = saved.minSeverity;
  if (Number.isInteger(saved.maxRepos) && saved.maxRepos >= 1 && saved.maxRepos <= 1000) o.maxRepos = saved.maxRepos;
  return o;
}

export function saveOptions(o) {
  try {
    localStorage.setItem(STORE_KEY, JSON.stringify(o));
  } catch {
    // Not saved: the defaults come back next time.
  }
}

/** The options as the backend's `start_scan` takes them. */
export function scanRequest(o) {
  const target = {
    mine: { kind: "mine" },
    folder: { kind: "folder" },
    repo: { kind: "repo", repo: o.repo.trim() },
    org: { kind: "org", name: o.org.trim() },
    user: { kind: "user", name: o.user.trim() },
    search: { kind: "search", query: o.query.trim() },
  }[o.kind];
  return {
    target,
    ...o.checks,
    history: o.history && o.checks.secrets,
    includeArchived: o.includeArchived,
    includeForks: o.includeForks,
    minSeverity: o.minSeverity,
    maxRepos: o.maxRepos,
  };
}

/** A short name for what is being scanned, for the progress page. */
export function scanLabel(o, env, folder) {
  switch (o.kind) {
    case "mine":
      return env?.github?.login ? `${env.github.login}'s repositories` : "your repositories";
    case "repo":
      return o.repo.trim();
    case "folder":
      return folder ?? "a folder";
    case "org":
      return `organization ${o.org.trim()}`;
    case "user":
      return `${o.user.trim()}'s repositories`;
    default:
      return `search: ${o.query.trim()}`;
  }
}

/** Why a scan can't start yet, or null. */
function problem(options, env, folder) {
  const o = effectiveOptions(options, env);
  const target = TARGETS.find((t) => t.kind === o.kind);
  if (o.kind === "mine" && !env?.github?.login) return "Scanning your repositories needs GitHub access (see below).";
  if (o.kind === "folder" && !folder) return "Choose a folder to scan.";
  if (target.field && !o[target.field.key].trim()) return `Enter ${target.field.label.toLowerCase()} to scan.`;
  if (o.kind === "search" && !env?.github?.source) return "GitHub search needs GitHub access (see below).";
  // Without a token GitHub allows 60 requests an hour: a few repositories' worth.
  if (env?.mobile && target.multi && !env.github?.login) return "Scanning many repositories needs GitHub access (see below).";
  if (!CHECKS.some((c) => o.checks[c])) return "Turn on at least one check.";
  if (target.kind !== "folder" && capabilities(env).download === "git" && !env?.git) {
    return "Downloading repositories needs git, which isn't installed (see below).";
  }
  return null;
}

// ------------------------------------------------------------------ page

/**
 * ctx: {
 *   env: environment or null while loading, refreshEnvironment(),
 *   folder: chosen folder path or null, setFolder(path),
 *   start(request, label, options),
 * }
 */
export function renderSetup(ctx) {
  const o = loadOptions();
  const caps = capabilities(ctx.env);
  const mobile = Boolean(ctx.env?.mobile);
  if (!targetsFor(ctx.env).some((t) => t.kind === o.kind)) o.kind = "mine";
  const root = h("div", { class: "page setup" });

  function rerender() {
    saveOptions(o);
    replace(root, ...sections());
  }

  function sections() {
    const target = TARGETS.find((t) => t.kind === o.kind);
    return [
      h("div", { class: "section-head" }, h("h1", {}, "New scan"), h("p", {}, "ghaudit only reads: it never changes anything on GitHub.")),
      whatSection(target),
      checksSection(),
      target.multi ? repositoriesSection() : null,
      reportSection(),
      accessSection(),
      startSection(),
    ];
  }

  // -------------------------------------------------------------- what to scan

  function whatSection(target) {
    const login = ctx.env?.github?.login;
    const cards = targetsFor(ctx.env).map((t) =>
      h(
        "button",
        {
          type: "button",
          class: "target-card",
          role: "radio",
          "aria-checked": String(t.kind === o.kind),
          onclick: () => {
            o.kind = t.kind;
            rerender();
            // On a touch screen focus would open the keyboard over the other options.
            if (!mobile && !phone.matches) root.querySelector(".target-field input")?.focus();
          },
        },
        icon(t.icon),
        h("span", { class: "t-label" }, t.label),
        h(
          "span",
          { class: "t-text" },
          t.kind === "mine" ? (login ? `Everything ${login} owns, private ones too.` : "Needs GitHub access.") : t.text,
        ),
      ),
    );
    return h(
      "section",
      { class: "card form-card", "aria-labelledby": "what-head" },
      h("h2", { id: "what-head" }, "What to scan"),
      h("div", { class: "target-grid", role: "radiogroup", "aria-labelledby": "what-head" }, cards),
      target.field ? fieldRow(target.field) : null,
      target.kind === "folder" ? folderRow() : null,
    );
  }

  function fieldRow(field) {
    const input = h("input", {
      class: "input",
      type: "text",
      value: o[field.key],
      placeholder: field.placeholder,
      spellcheck: "false",
      autocomplete: "off",
      autocapitalize: "off",
      autocorrect: "off",
      enterkeyhint: "go",
      inputmode: field.key === "repo" ? "url" : null,
      "aria-label": field.label,
    });
    input.addEventListener("input", () => {
      o[field.key] = input.value;
      saveOptions(o);
      updateStart();
    });
    input.addEventListener("keydown", (e) => {
      if (e.key === "Enter") start();
    });
    return h("label", { class: "target-field" }, h("span", {}, field.label), input);
  }

  function folderRow() {
    return h(
      "div",
      { class: "target-field" },
      h("span", {}, "Folder"),
      h(
        "div",
        { class: "folder-pick" },
        h(
          "button",
          {
            type: "button",
            class: "btn",
            onclick: async () => {
              try {
                const chosen = await backend.pickFolder();
                if (chosen) {
                  ctx.setFolder(chosen);
                  rerender();
                }
              } catch (e) {
                toast(e.message, { error: true });
              }
            },
          },
          icon("folder"),
          ctx.folder ? "Choose another…" : "Choose a folder…",
        ),
        ctx.folder ? h("span", { class: "mono folder-path" }, ctx.folder) : h("span", { class: "muted" }, "No folder chosen"),
      ),
    );
  }

  // -------------------------------------------------------------- what to check

  /** extra: { sub, disabled, note, unavailable: why this device can't do it } */
  function toggle(label, text, checked, onchange, extra = {}) {
    const input = h("input", { type: "checkbox", checked, disabled: extra.disabled || Boolean(extra.unavailable) });
    input.addEventListener("change", () => onchange(input.checked));
    const cls = ["toggle-row", extra.sub ? "sub" : "", extra.disabled || extra.unavailable ? "disabled" : "", extra.unavailable ? "unavailable" : ""];
    return h(
      "label",
      { class: cls.filter(Boolean).join(" ") },
      input,
      h("span", { class: "toggle-text" }, h("b", {}, label), h("span", {}, text), extra.note ?? null),
      // Not faded with the rest of the row: it says why.
      extra.unavailable ? h("span", { class: "unavailable-note" }, icon("info"), extra.unavailable) : null,
    );
  }

  function checksSection() {
    const env = ctx.env;
    const rows = [];
    for (const id of CHECKS) {
      const a = ANALYZER[id];
      const unavailable = id === "sca" && !caps.dependencies ? PHONE_NOTES.sca : null;
      let note = null;
      if (id === "sca" && env && !env.osv_scanner && !unavailable) note = osvMissing();
      if (id === "sca" && env?.osv_scanner?.version) note = h("span", { class: "ok-note" }, icon("check"), env.osv_scanner.version);
      if (id === "settings" && env && !env.github.login) note = h("span", { class: "warn-note" }, "Needs GitHub access; without it this check is skipped.");
      rows.push(
        toggle(
          a.label,
          a.text,
          o.checks[id] && !unavailable,
          (on) => {
            o.checks[id] = on;
            rerender();
          },
          { note, unavailable },
        ),
      );
      if (id === "secrets") {
        rows.push(
          toggle(
            "Also search git history",
            "Finds credentials that were deleted but are still in old commits. Slower: every commit is downloaded.",
            o.history && o.checks.secrets && caps.history,
            (on) => {
              o.history = on;
              rerender();
            },
            { sub: true, disabled: !o.checks.secrets, unavailable: caps.history ? null : PHONE_NOTES.history },
          ),
        );
      }
    }
    return h("section", { class: "card form-card", "aria-labelledby": "checks-head" }, h("h2", { id: "checks-head" }, "What to check"), h("div", { class: "toggles" }, rows));
  }

  function osvMissing() {
    return h(
      "span",
      { class: "warn-note" },
      "osv-scanner isn't installed, so dependencies can't be checked. Install it with ",
      h("code", {}, installOsv(ctx.env)),
      ", then ",
      h("button", { type: "button", class: "link", onclick: () => ctx.refreshEnvironment() }, "check again"),
      ".",
    );
  }

  // -------------------------------------------------------------- repositories

  function repositoriesSection() {
    const max = h("input", {
      class: "input narrow",
      type: "number",
      min: 1,
      max: 1000,
      value: o.maxRepos,
      inputmode: "numeric",
      enterkeyhint: "done",
      "aria-label": "Most repositories to scan",
    });
    max.addEventListener("change", () => {
      const n = Math.round(Number(max.value));
      o.maxRepos = Number.isFinite(n) ? Math.min(1000, Math.max(1, n)) : DEFAULTS.maxRepos;
      max.value = o.maxRepos;
      saveOptions(o);
    });
    return h(
      "section",
      { class: "card form-card", "aria-labelledby": "repos-head" },
      h("h2", { id: "repos-head" }, "Which repositories"),
      h(
        "div",
        { class: "toggles" },
        toggle("Include archived repositories", "They are read-only, but anything leaked in them is still readable.", o.includeArchived, (on) => {
          o.includeArchived = on;
          saveOptions(o);
        }),
        toggle("Include forks", "Copies of other people's projects: most of their code isn't yours to fix.", o.includeForks, (on) => {
          o.includeForks = on;
          saveOptions(o);
        }),
      ),
      h("label", { class: "inline-field" }, h("span", {}, "Scan at most"), max, h("span", {}, "repositories")),
    );
  }

  // -------------------------------------------------------------- report

  function reportSection() {
    const select = h(
      "select",
      { class: "select", "aria-label": "Leave out findings below" },
      SEVERITIES.filter((s) => s.id !== "unknown").map((s) => h("option", { value: s.id, selected: s.id === o.minSeverity }, s.label)),
    );
    select.addEventListener("change", () => {
      o.minSeverity = select.value;
      saveOptions(o);
    });
    return h(
      "section",
      { class: "card form-card", "aria-labelledby": "report-head" },
      h("h2", { id: "report-head" }, "Report"),
      h(
        "label",
        { class: "inline-field" },
        h("span", {}, "Leave out findings below"),
        select,
        h("span", { class: "muted" }, "Low hides only informational findings, such as ones in tests and docs."),
      ),
    );
  }

  // -------------------------------------------------------------- GitHub access

  function accessSection() {
    const env = ctx.env;
    const body = [];
    if (!env) {
      body.push(h("p", { class: "muted" }, "Checking GitHub access…"));
    } else {
      const { source, login } = env.github;
      const how = {
        environment: "using the GITHUB_TOKEN environment variable",
        github_cli: "through the GitHub CLI",
        keychain: mobile ? "with the token saved on this phone" : "with the token saved in your system keychain",
      }[source];
      if (login) {
        body.push(h("p", { class: "status-line ok" }, icon("checkCircle"), `Signed in to GitHub as ${login}, ${how}.`));
      } else if (source) {
        body.push(
          h(
            "p",
            { class: "status-line warn" },
            icon("alert"),
            `GitHub didn't accept the token ${how}. It may have expired: `,
            source === "github_cli" ? h("span", {}, "run ", h("code", {}, "gh auth login"), " again.") : mobile ? "create a new one below." : "replace it.",
          ),
        );
      } else {
        body.push(
          h(
            "p",
            { class: "status-line warn" },
            icon("alert"),
            caps.folders
              ? "No GitHub access. Public repositories and folders can still be scanned, but not private repositories or settings, and GitHub allows only 60 requests an hour."
              : "No GitHub access. Public repositories can still be scanned, but not private repositories or settings, and GitHub allows only 60 requests an hour.",
          ),
        );
      }
      if (caps.pasteToken) {
        body.push(phoneToken(env));
      } else if (!login && !mobile) {
        body.push(
          h(
            "p",
            {},
            env.github_cli
              ? ["Sign in with the GitHub CLI: run ", h("code", {}, "gh auth login"), ", then "]
              : ["The easiest way is the GitHub CLI (", h("code", {}, "winget install --id GitHub.cli"), ", then ", h("code", {}, "gh auth login"), "). Then "],
            h("button", { type: "button", class: "link", onclick: () => ctx.refreshEnvironment() }, "check again"),
            ".",
          ),
        );
      }
      if (!caps.pasteToken) body.push(tokenForm(env));
    }
    if (env && !env.git && caps.download === "git") {
      body.push(
        h(
          "p",
          { class: "status-line warn" },
          icon("alert"),
          "git isn't installed, so repositories can't be downloaded (folders can still be scanned). Install it with ",
          h("code", {}, "winget install --id Git.Git"),
          ", then restart ghaudit.",
        ),
      );
    }
    return h("section", { class: "card form-card", "aria-labelledby": "access-head" }, h("h2", { id: "access-head" }, "GitHub access"), body);
  }

  function tokenForm(env) {
    if (!env.keychain.available) {
      return env.github.login ? null : h("p", { class: "muted" }, "Or set the GITHUB_TOKEN environment variable before starting ghaudit. (This computer has no system keychain to save a token in.)");
    }
    const saved = env.keychain.saved;
    const usedElsewhere = saved && env.github.source !== "keychain";
    const details = h(
      "details",
      { class: "token-form", open: !env.github.source ? true : null },
      h("summary", {}, saved ? "Saved token" : "Use a personal access token instead"),
    );
    const input = h("input", {
      class: "input",
      type: "password",
      autocomplete: "off",
      spellcheck: "false",
      placeholder: "ghp_… or github_pat_…",
      "aria-label": "GitHub personal access token",
    });
    const message = h("p", { class: "form-message", role: "status" });
    const save = h(
      "button",
      {
        type: "button",
        class: "btn",
        onclick: async () => {
          const value = input.value;
          if (!value.trim()) return;
          save.disabled = true;
          replace(message, "Checking the token with GitHub…");
          try {
            const login = await backend.saveToken(value);
            input.value = "";
            toast(`Token saved in your system keychain (${login}).`);
            ctx.refreshEnvironment();
          } catch (e) {
            replace(message, h("span", { class: "error-text" }, e.message));
          } finally {
            save.disabled = false;
          }
        },
      },
      "Check and save",
    );
    replace(
      details,
      details.firstChild,
      h(
        "p",
        { class: "muted" },
        "A token is kept in your system keychain, never in a file. ghaudit only reads. A classic token needs the repo scope to read private repositories (and read:org for organizations), but even then settings are fully checked only for repositories where the token's user is an admin. A saved token is used only when GITHUB_TOKEN isn't set and the GitHub CLI isn't signed in.",
      ),
      usedElsewhere ? h("p", { class: "muted" }, "A token is saved, but the sign-in above is being used instead.") : null,
      h("div", { class: "token-row" }, input, save),
      message,
      saved
        ? h(
            "button",
            {
              type: "button",
              class: "btn quiet danger",
              onclick: async () => {
                try {
                  await backend.forgetToken();
                  toast("The saved token was removed from your keychain.");
                  ctx.refreshEnvironment();
                } catch (e) {
                  toast(e.message, { error: true });
                }
              },
            },
            "Forget the saved token",
          )
        : null,
    );
    return details;
  }

  /**
   * Phones: no password field. GitHub's token page opens in the browser, filled in; the
   * backend takes the copied token from the clipboard, so it never reaches the page.
   */
  function phoneToken(env) {
    const saved = env.keychain.saved;
    const message = h("p", { class: "form-message", role: "status" });
    const fail = (e) => replace(message, h("span", { class: "error-text" }, e.message));
    const create = h(
      "button",
      {
        type: "button",
        class: "btn",
        onclick: () => {
          replace(message);
          backend.openTokenPage().catch(fail);
        },
      },
      icon("external"),
      "Create a token on GitHub",
    );
    const paste = h(
      "button",
      {
        type: "button",
        class: "btn primary",
        onclick: async () => {
          paste.disabled = true;
          replace(message, "Checking the token with GitHub…");
          try {
            const login = await backend.pasteToken();
            replace(message);
            toast(`Token saved on this phone (${login}).`);
            ctx.refreshEnvironment();
          } catch (e) {
            fail(e);
          } finally {
            paste.disabled = false;
          }
        },
      },
      icon("clipboard"),
      "Paste token",
    );
    const steps = [
      h(
        "ol",
        { class: "token-steps" },
        h("li", {}, "Tap ", h("b", {}, "Create a token on GitHub"), ". GitHub opens in your browser with a read-only token already filled in."),
        h("li", {}, "Under Repository access, choose ", h("b", {}, "All repositories"), ", then tap ", h("b", {}, "Generate token"), " and copy the token."),
        h("li", {}, "Come back here and tap ", h("b", {}, "Paste token"), ". ghaudit checks the token with GitHub, keeps it in this phone's secure storage and clears the clipboard."),
      ),
      h("div", { class: "token-actions" }, create, paste),
      message,
      h("p", { class: "muted" }, "The token can only read, and only the repositories of the account or organization you choose on GitHub. Settings are fully checked only for repositories where you are an admin."),
    ];
    if (!saved) return h("div", { class: "token-phone" }, steps);
    return h(
      "details",
      { class: "token-form", open: env.github.login ? null : true },
      h("summary", {}, "Replace the saved token"),
      steps,
      h(
        "button",
        {
          type: "button",
          class: "btn quiet danger",
          onclick: async () => {
            try {
              await backend.forgetToken();
              toast("The saved token was removed from this phone.");
              ctx.refreshEnvironment();
            } catch (e) {
              toast(e.message, { error: true });
            }
          },
        },
        "Forget the saved token",
      ),
    );
  }

  // -------------------------------------------------------------- start

  const startButton = h("button", { type: "button", class: "btn primary large", onclick: () => start() }, icon("play"), "Start scan");
  const startNote = h("p", { class: "start-note", role: "status" });

  function updateStart() {
    const why = problem(o, ctx.env, ctx.folder);
    startButton.disabled = Boolean(why) || !ctx.env;
    replace(startNote, why ?? "");
  }

  function startSection() {
    updateStart();
    return h("div", { class: "start-row" }, startButton, startNote);
  }

  function start() {
    if (problem(o, ctx.env, ctx.folder) || !ctx.env) return;
    const run = effectiveOptions(o, ctx.env);
    if (run.checks.sca && !ctx.env.osv_scanner) {
      confirmWithoutSca(run);
      return;
    }
    saveOptions(o);
    ctx.start(scanRequest(run), scanLabel(run, ctx.env, ctx.folder), run);
  }

  function confirmWithoutSca(run) {
    let dismiss = () => {};
    const dialog = h(
      "dialog",
      { class: "confirm", "aria-labelledby": "osv-title" },
      h("h2", { id: "osv-title" }, "Dependencies can't be checked"),
      h(
        "p",
        {},
        "osv-scanner isn't installed, so known vulnerabilities in packages would be missed. Install it with ",
        h("code", {}, installOsv(ctx.env)),
        ", or scan everything else now.",
      ),
      h(
        "div",
        { class: "confirm-actions" },
        h("button", { type: "button", class: "btn", onclick: () => dismiss() }, "Cancel"),
        h(
          "button",
          {
            type: "button",
            class: "btn primary",
            onclick: () => {
              dismiss();
              const without = { ...run, checks: { ...run.checks, sca: false } };
              ctx.start(scanRequest(without), scanLabel(run, ctx.env, ctx.folder), without);
            },
          },
          "Scan without dependency checks",
        ),
      ),
    );
    dismiss = nav.showDialog(dialog);
  }

  rerender();
  return root;
}
