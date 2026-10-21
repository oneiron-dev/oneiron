"use strict";
// Data attributes wire fixture behavior; bench locators use roles, names and ancestors.
(async () => {
  const fixture = document.body.dataset.fixture;
  const version = document.body.dataset.version;
  const api = `/${fixture}/${version}/api/`;
  const status = document.querySelector("[data-status]");
  let runId = "";
  let queue = Promise.resolve();
  const report = (message) => { status.textContent = message; };
  async function request(action, payload) {
    const response = await fetch(api + action, {
      method: payload === undefined ? "GET" : "POST",
      headers: {"Content-Type": "application/json", "X-CUA-Run": runId},
      ...(payload === undefined ? {} : {body: JSON.stringify(payload)})
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || `HTTP ${response.status}`);
    return result;
  }
  function save(action, payload) {
    report("Saving…");
    const job = queue.then(() => request(action, payload));
    queue = job.catch((error) => { report(`Stopped: ${error.message}`); });
    job.then(() => report("Saved"), () => {});
    return job;
  }
  try {
    const initial = await request("data");
    runId = initial.run_id;
    const view = initial.view;
    const params = new URLSearchParams(location.search);
    const recipient = params.get("recipient");
    const profile = document.querySelector("[data-profile]")?.dataset.profile;
    const noteDialog = document.querySelector("[data-note-dialog]");
    const consent = document.querySelector("[data-consent]");
    const shell = document.querySelector("main");
    const note = document.querySelector("[data-note]");
    const noteSend = document.querySelector("[data-note-send]");
    let noteProfile = view.opened_on;
    document.querySelectorAll("form").forEach((form) => {
      form.addEventListener("submit", (event) => event.preventDefault());
    });
    // An old tab cannot write through a later reset: each mutation carries its run id.
    function recompute() {
      for (let row = 2; row <= 7; row += 1) {
        const output = document.querySelector(`[data-formula="E${row}"]`);
        if (!output) continue;
        const c = document.querySelector(`[data-cell="C${row}"]`).value.trim();
        const d = document.querySelector(`[data-cell="D${row}"]`).value.trim();
        try {
          const integer = (value) => {
            if (!/^[+-]?\d+$/.test(value || "0")) throw new Error("not an integer");
            return BigInt(value || "0");
          };
          output.value = String(integer(c) * integer(d));
        } catch (_) { output.value = "#VALUE!"; }
      }
    }
    document.querySelectorAll("[data-field]").forEach((input) => {
      if (input.type === "radio") input.checked = input.value === view.fields[input.dataset.field];
      else input.value = view.fields[input.dataset.field];
      input.addEventListener("input", () => {
        if (input.type !== "radio" || input.checked) {
          save("field", {field: input.dataset.field, value: input.value}).catch(() => {});
        }
      });
    });
    const draftInputs = [...document.querySelectorAll("[data-draft]")];
    const linkPanel = document.querySelector("[data-link-panel]");
    const schedulePanel = document.querySelector("[data-schedule-panel]");
    function showLink() {
      const value = document.querySelector('[data-draft="link"]')?.value;
      const preview = document.querySelector("[data-link-preview]");
      if (preview && value) preview.setAttribute("href", value);
      else preview?.removeAttribute("href");
    }
    if (draftInputs.length) {
      if (!recipient || !view.drafts[recipient]) throw new Error("Open compose from a recipient row");
      const draft = view.drafts[recipient];
      draftInputs.forEach((input) => {
        input.value = draft[input.dataset.draft];
        input.addEventListener("input", () => {
          showLink();
          save("draft", {id: recipient, fields: {[input.dataset.draft]: input.value}}).catch(() => {});
        });
      });
      linkPanel.hidden = !draft.link;
      schedulePanel.hidden = !draft.scheduled_time;
      showLink();
    }
    document.querySelector("[data-open-link]")?.addEventListener("click", () => {
      save("press", {control: "insert-link", id: recipient}).then(() => {
        linkPanel.hidden = false;
        linkPanel.querySelector("input").focus();
      }, () => {});
    });
    document.querySelector("[data-open-schedule]")?.addEventListener("click", () => {
      save("press", {control: "schedule", id: recipient}).then(() => {
        schedulePanel.hidden = false;
        schedulePanel.querySelector("input").focus();
      }, () => {});
    });
    document.querySelector("[data-save-draft]")?.addEventListener("click", () => {
      const fields = Object.fromEntries(draftInputs.map((input) => [input.dataset.draft, input.value]));
      save("draft", {id: recipient, fields, finalize: true}).catch(() => {});
    });
    async function viewedProfile() {
      if (profile) await save("open_profile", {profile});
    }
    if (note) {
      note.value = noteProfile === profile ? view.note : "";
      noteSend.disabled = !note.value.trim();
      note.addEventListener("input", () => {
        const value = note.value;
        noteSend.disabled = !value.trim();
        save("note", {profile, note: value}).catch(() => {});
      });
    }
    document.querySelector("[data-connect]")?.addEventListener("click", () => {
      save("connect", {profile}).then(() => {
        if (noteProfile !== profile) note.value = "";
        noteProfile = profile;
        noteSend.disabled = !note.value.trim();
        noteDialog.showModal();
      }, () => {});
    });
    function closeNote() {
      save("close_note", {profile}).then(() => noteDialog.close(), () => {});
    }
    document.querySelector("[data-close-note]")?.addEventListener("click", closeNote);
    noteDialog?.addEventListener("cancel", (event) => { event.preventDefault(); closeNote(); });
    document.querySelector("[data-search]")?.form.addEventListener("submit", () => {
      const query = document.querySelector("[data-search]").value;
      save("search", {query}).then(() => {
        const tokens = query.toLowerCase().split(/\s+/).filter(Boolean);
        document.querySelectorAll("[data-search-result]").forEach((result) => {
          result.hidden = !tokens.every((token) => result.textContent.toLowerCase().includes(token));
        });
      }, () => {});
    });
    document.querySelectorAll("[data-cell]").forEach((input) => {
      input.value = view.cells[input.dataset.cell];
      input.addEventListener("input", () => {
        recompute();
        save("cell", {cell: input.dataset.cell, value: input.value}).catch(() => {});
      });
    });
    recompute();
    document.querySelector("[data-save-cells]")?.addEventListener("click", () => {
      save("save_cells", {}).catch(() => {});
    });
    document.querySelectorAll("[data-press]").forEach((button) => {
      button.addEventListener("click", (event) => {
        event.preventDefault();
        const payload = {control: button.dataset.press};
        if (fixture === "F3") payload.id = recipient;
        if (fixture === "F4") payload.profile = profile;
        save("press", payload).catch(() => {});
      });
    });
    if (consent && !initial.consent_dismissed) {
      shell.inert = true;
      consent.showModal();
      consent.addEventListener("cancel", (event) => event.preventDefault());
      document.querySelector("[data-dismiss-consent]").addEventListener("click", () => {
        save("consent", {}).then(async () => {
          consent.close();
          shell.inert = false;
          await viewedProfile();
        }, () => {}).catch(() => {});
      });
    } else {
      consent?.remove();
      await viewedProfile();
      if (noteDialog && view.dialog_open && noteProfile === profile) noteDialog.showModal();
    }
    report("Ready");
  } catch (error) { report(`Stopped: ${error.message}`); }
})();
