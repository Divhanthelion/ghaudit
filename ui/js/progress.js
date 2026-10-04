// The scan progress page: a row per repository for multi-repository scans, a checklist
// of checks for one repository or folder, and Cancel. Fed by ghaudit's progress events
// (see src/progress.rs); every name and message in them is shown as text.

import { h, replace, icon, plural, formatDuration } from "./dom.js";
import { ANALYZER, analyzerLabel } from "./explain.js";

const ROW_STATE = {
  queued: { label: "Waiting", cls: "queued", icon: "clock" },
  running: { label: "Scanning", cls: "running", icon: "refresh" },
  done: { label: "Done", cls: "done", icon: "checkCircle" },
  failed: { label: "Failed", cls: "failed", icon: "xCircle" },
};

/**
 * label: what is being scanned; options: the setup options (which checks are on, the
 * repository limit); multi: whether repositories will be listed; onCancel().
 * Returns { element, handle(event), fail(message), cancelling() }.
 */
export function createProgressView({ label, options, multi, onCancel, onBack }) {
  const started = Date.now();
  const checkIds = ["sast", "secrets", "history", "sca", "workflows", "agents", "settings"];
  const enabled = new Set(
    checkIds.filter((id) => (id === "history" ? options.history && options.checks.secrets : options.checks[id])),
  );

  const run = {
    listed: null,
    order: [],
    repos: new Map(),
    done: 0,
    failed: 0,
    findings: 0,
    files: new Map(),
    analyzers: new Map(),
    error: null,
    cancelling: false,
  };

  const title = h("h1", {}, `Scanning ${label}`);
  const elapsed = h("span", { class: "elapsed" });
  const cancel = h(
    "button",
    {
      type: "button",
      class: "btn",
      onclick: () => {
        run.cancelling = true;
        cancel.disabled = true;
        replace(cancel, icon("stop"), "Stopping…");
        onCancel();
      },
    },
    icon("stop"),
    "Cancel",
  );
  const summary = h("p", { class: "progress-summary", role: "status", "aria-live": "polite" });
  const bar = h("div", { class: "progress-bar", role: "progressbar", "aria-label": "Scan progress" });
  const fill = h("div", { class: "progress-fill" });
  bar.append(fill);
  const body = h("div", { class: "progress-body" });

  const element = h(
    "div",
    { class: "page progress-page" },
    h("div", { class: "progress-head" }, h("div", {}, title, elapsed), cancel),
    h("div", { class: "card progress-card" }, summary, bar, body),
  );

  const key = (repository) => repository ?? "";

  // ---------------------------------------------------------------- events

  function handle(event) {
    switch (event.type) {
      case "repositories_listed":
        run.listed = event.listed;
        run.order = event.repositories;
        for (const [index, name] of event.repositories.entries()) {
          run.repos.set(name, { index, name, state: "queued", findings: 0, ms: 0, error: null, startedAt: 0 });
        }
        break;
      case "repository_started": {
        const r = run.repos.get(event.name);
        if (r) Object.assign(r, { state: "running", startedAt: Date.now() });
        break;
      }
      case "repository_finished": {
        const r = run.repos.get(event.name);
        if (r) {
          Object.assign(r, { state: event.error ? "failed" : "done", findings: event.findings, ms: event.duration_ms, error: event.error });
        }
        run.done = event.done;
        if (event.error) run.failed += 1;
        else run.findings += event.findings;
        break;
      }
      case "files_discovered":
        run.files.set(key(event.repository), event.files);
        break;
      case "analyzer_finished": {
        const k = key(event.repository);
        if (!run.analyzers.has(k)) run.analyzers.set(k, new Map());
        run.analyzers.get(k).set(event.status.analyzer, event.status);
        break;
      }
      default:
        break; // a newer ghaudit's event: nothing to show
    }
    schedule();
  }

  let frame = 0;
  function schedule() {
    if (!frame) frame = requestAnimationFrame(render);
  }

  // ---------------------------------------------------------------- render

  function render() {
    frame = 0;
    elapsed.textContent = ` · ${formatDuration(Date.now() - started)}`;
    if (run.error) return;
    if (multi) renderMulti();
    else renderSingle();
  }

  function setBar(done, total) {
    if (total === null) {
      bar.classList.add("indeterminate");
      bar.removeAttribute("aria-valuenow");
      fill.style.width = "";
      return;
    }
    bar.classList.remove("indeterminate");
    bar.setAttribute("aria-valuemin", "0");
    bar.setAttribute("aria-valuemax", String(total));
    bar.setAttribute("aria-valuenow", String(done));
    fill.style.width = `${total ? (done / total) * 100 : 100}%`;
  }

  function renderMulti() {
    if (run.listed === null) {
      replace(summary, "Asking GitHub for the list of repositories…");
      setBar(0, null);
      replace(body);
      return;
    }
    const total = run.order.length;
    const running = [...run.repos.values()].filter((r) => r.state === "running").length;
    const skipped = run.listed - total;
    replace(
      summary,
      h("b", {}, `${run.done.toLocaleString()} of ${plural(total, "repository", "repositories")} done`),
      running ? ` · ${running.toLocaleString()} scanning` : "",
      ` · ${plural(run.findings, "finding")} so far`,
      run.failed ? h("span", { class: "error-text" }, ` · ${run.failed.toLocaleString()} failed`) : "",
      skipped > 0 ? h("span", { class: "muted" }, ` · ${plural(skipped, "fork or archived repository", "forks or archived repositories")} left out`) : "",
      run.listed >= options.maxRepos ? h("span", { class: "muted" }, ` · stopped at the limit of ${options.maxRepos}`) : "",
    );
    setBar(run.done, total);
    if (!total) {
      replace(body, h("p", { class: "muted empty-note" }, "No repositories to scan."));
      return;
    }
    replace(
      body,
      h(
        "div",
        { class: "table-wrap progress-table" },
        h(
          "table",
          { class: "data" },
          h(
            "thead",
            {},
            h("tr", {}, h("th", {}, "Repository"), h("th", {}, "Status"), h("th", { class: "num" }, "Findings"), h("th", { class: "num" }, "Time")),
          ),
          h("tbody", {}, run.order.map((name) => repoRow(run.repos.get(name)))),
        ),
      ),
    );
  }

  function repoRow(r) {
    const s = ROW_STATE[r.state];
    const checks = run.analyzers.get(r.name);
    let status = h("span", { class: `state ${s.cls}` }, icon(s.icon), s.label);
    if (r.state === "running") {
      const n = checks ? checkIds.filter((id) => checks.has(id)).length : 0;
      status = h("span", { class: `state ${s.cls}` }, icon(s.icon, "spin"), run.files.has(r.name) ? `Checking (${n} of ${checkIds.length} checks done)` : "Downloading…");
    }
    const ms = r.state === "running" ? Date.now() - r.startedAt : r.ms;
    return h(
      "tr",
      { class: `repo-row ${s.cls}` },
      h("td", {}, h("span", { class: "f-repo" }, r.name), r.error ? h("div", { class: "error-text row-error" }, r.error) : null),
      h("td", {}, status),
      h("td", { class: "num" }, r.state === "done" ? r.findings.toLocaleString() : ""),
      h("td", { class: "num" }, r.state === "queued" ? "" : formatDuration(ms)),
    );
  }

  function renderSingle() {
    const statuses = [...run.analyzers.values()][0] ?? new Map();
    const files = [...run.files.values()][0];
    const finished = checkIds.filter((id) => statuses.has(id)).length;
    replace(
      summary,
      files === undefined
        ? options.kind === "folder"
          ? "Listing the folder's files…"
          : "Downloading the repository…"
        : h("b", {}, `Checking ${plural(files, "file")}`),
    );
    setBar(finished, files === undefined ? null : checkIds.length);
    replace(
      body,
      h(
        "ul",
        { class: "check-list" },
        checkIds.map((id) => {
          const st = statuses.get(id);
          let state;
          if (!enabled.has(id)) state = h("span", { class: "state skipped" }, icon("minusCircle"), "Off");
          else if (st?.state === "completed") state = h("span", { class: "state done" }, icon("checkCircle"), "Done");
          else if (st?.state === "failed") state = h("span", { class: "state failed" }, icon("xCircle"), "Failed");
          else if (st?.state === "skipped") state = h("span", { class: "state skipped" }, icon("minusCircle"), "Not run");
          else state = h("span", { class: "state running" }, icon("refresh", "spin"), files === undefined ? "Waiting" : "Working");
          const detail = enabled.has(id) && (st?.state === "failed" || st?.state === "skipped") ? st.detail : null;
          return h(
            "li",
            {},
            h("span", { class: "check-name" }, analyzerLabel(id), h("span", { class: "muted" }, ANALYZER[id]?.text ?? "")),
            h("span", { class: "check-state" }, state, detail ? h("span", { class: "muted check-detail" }, detail) : null),
          );
        }),
      ),
    );
  }

  // ---------------------------------------------------------------- public

  function fail(message) {
    run.error = message;
    clearInterval(timer);
    cancel.hidden = true;
    title.textContent = "The scan couldn't finish";
    replace(summary, h("span", { class: "error-text" }, message));
    bar.hidden = true;
    replace(body, h("button", { type: "button", class: "btn", onclick: onBack }, "Back to the scan options"));
  }

  function stop() {
    clearInterval(timer);
    if (frame) cancelAnimationFrame(frame);
  }

  const timer = setInterval(schedule, 1000);
  render();
  return { element, handle, fail, stop };
}
