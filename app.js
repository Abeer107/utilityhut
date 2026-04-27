const STORAGE_KEY = "utilityhub-data-v1";
const VAULT_KEY = "utilityhub-vault-v1";
const ITERATIONS = 250000;

const state = {
  currentView: "passwords",
  vaultUnlocked: false,
  vaultEntries: [],
  data: loadAppData(),
};

const els = {
  viewTitle: document.getElementById("view-title"),
  syncStatus: document.getElementById("sync-status"),
  navButtons: [...document.querySelectorAll(".nav-button")],
  views: {
    passwords: document.getElementById("passwords-view"),
    projects: document.getElementById("projects-view"),
    notes: document.getElementById("notes-view"),
    tasks: document.getElementById("tasks-view"),
  },
  exportButton: document.getElementById("export-data"),
  vaultForm: document.getElementById("vault-form"),
  masterPassword: document.getElementById("master-password"),
  lockVault: document.getElementById("lock-vault"),
  generatePassword: document.getElementById("generate-password"),
  useGenerated: document.getElementById("use-generated"),
  generatedPassword: document.getElementById("generated-password"),
  passwordEntryForm: document.getElementById("password-entry-form"),
  passwordSearch: document.getElementById("password-search"),
  passwordList: document.getElementById("password-list"),
  projectForm: document.getElementById("project-form"),
  projectList: document.getElementById("project-list"),
  noteForm: document.getElementById("note-form"),
  noteSearch: document.getElementById("note-search"),
  noteList: document.getElementById("note-list"),
  taskForm: document.getElementById("task-form"),
  taskList: document.getElementById("task-list"),
  emptyStateTemplate: document.getElementById("empty-state-template"),
};

function loadAppData() {
  const raw = localStorage.getItem(STORAGE_KEY);
  if (!raw) {
    return { projects: [], notes: [], tasks: [] };
  }

  try {
    const parsed = JSON.parse(raw);
    return {
      projects: Array.isArray(parsed.projects) ? parsed.projects : [],
      notes: Array.isArray(parsed.notes) ? parsed.notes : [],
      tasks: Array.isArray(parsed.tasks) ? parsed.tasks : [],
    };
  } catch (error) {
    console.error("Failed to parse local data", error);
    return { projects: [], notes: [], tasks: [] };
  }
}

function saveAppData() {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(state.data));
  setStatus("Changes saved locally");
}

function setStatus(message) {
  els.syncStatus.textContent = message;
}

function uid() {
  return crypto.randomUUID();
}

function switchView(view) {
  state.currentView = view;
  els.navButtons.forEach((button) => {
    button.classList.toggle("active", button.dataset.view === view);
  });

  Object.entries(els.views).forEach(([name, element]) => {
    element.classList.toggle("active", name === view);
  });

  const activeButton = els.navButtons.find((button) => button.dataset.view === view);
  els.viewTitle.textContent = activeButton ? activeButton.textContent : "Workspace";
}

function cloneEmptyState() {
  return els.emptyStateTemplate.content.firstElementChild.cloneNode(true);
}

function formatDate(dateValue) {
  if (!dateValue) {
    return "No date";
  }

  const date = new Date(dateValue);
  if (Number.isNaN(date.getTime())) {
    return dateValue;
  }

  return new Intl.DateTimeFormat(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
  }).format(date);
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (character) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  }[character]));
}

function passwordStrengthBadge(password) {
  if (password.length >= 16) {
    return "success";
  }
  if (password.length >= 10) {
    return "warning";
  }
  return "";
}

function generatePasswordValue(length = 20) {
  const characters = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*-_+=?";
  const values = new Uint32Array(length);
  crypto.getRandomValues(values);
  return [...values].map((value) => characters[value % characters.length]).join("");
}

async function deriveKey(passphrase, salt) {
  const encoder = new TextEncoder();
  const baseKey = await crypto.subtle.importKey(
    "raw",
    encoder.encode(passphrase),
    "PBKDF2",
    false,
    ["deriveKey"]
  );

  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt,
      iterations: ITERATIONS,
      hash: "SHA-256",
    },
    baseKey,
    {
      name: "AES-GCM",
      length: 256,
    },
    false,
    ["encrypt", "decrypt"]
  );
}

function toBase64(arrayBuffer) {
  const bytes = new Uint8Array(arrayBuffer);
  let binary = "";
  bytes.forEach((byte) => {
    binary += String.fromCharCode(byte);
  });
  return btoa(binary);
}

function fromBase64(value) {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

async function encryptVault(entries, passphrase) {
  const encoder = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(passphrase, salt);
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    encoder.encode(JSON.stringify(entries))
  );

  return {
    salt: toBase64(salt),
    iv: toBase64(iv),
    ciphertext: toBase64(ciphertext),
  };
}

async function decryptVault(payload, passphrase) {
  const key = await deriveKey(passphrase, fromBase64(payload.salt));
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: fromBase64(payload.iv) },
    key,
    fromBase64(payload.ciphertext)
  );
  const decoder = new TextDecoder();
  return JSON.parse(decoder.decode(plaintext));
}

async function unlockVault(passphrase) {
  const raw = localStorage.getItem(VAULT_KEY);
  if (!raw) {
    state.vaultEntries = [];
    state.vaultUnlocked = true;
    setStatus("New vault ready");
    renderPasswords();
    return;
  }

  const payload = JSON.parse(raw);
  state.vaultEntries = await decryptVault(payload, passphrase);
  state.vaultUnlocked = true;
  setStatus("Vault unlocked");
  renderPasswords();
}

async function persistVault() {
  if (!state.vaultUnlocked) {
    return;
  }

  const passphrase = els.masterPassword.value;
  if (!passphrase) {
    setStatus("Enter your passphrase before saving vault changes");
    return;
  }

  const encrypted = await encryptVault(state.vaultEntries, passphrase);
  localStorage.setItem(VAULT_KEY, JSON.stringify(encrypted));
  setStatus("Vault encrypted and saved locally");
}

function lockVault() {
  state.vaultUnlocked = false;
  state.vaultEntries = [];
  els.masterPassword.value = "";
  renderPasswords();
  setStatus("Vault locked");
}

function renderPasswords() {
  els.passwordList.innerHTML = "";

  if (!state.vaultUnlocked) {
    const empty = cloneEmptyState();
    empty.querySelector("p").textContent = "Unlock the vault to view or add entries.";
    els.passwordList.append(empty);
    return;
  }

  const query = els.passwordSearch.value.trim().toLowerCase();
  const entries = state.vaultEntries.filter((entry) => {
    const searchable = `${entry.service} ${entry.username} ${entry.notes}`.toLowerCase();
    return searchable.includes(query);
  });

  if (!entries.length) {
    els.passwordList.append(cloneEmptyState());
    return;
  }

  entries.forEach((entry) => {
    const card = document.createElement("article");
    card.className = "card";
    card.innerHTML = `
      <div class="card-top">
        <div>
          <h4>${escapeHtml(entry.service)}</h4>
          <p>${escapeHtml(entry.username)}</p>
        </div>
        <span class="pill ${passwordStrengthBadge(entry.password)}">${entry.password.length} chars</span>
      </div>
      <p>${escapeHtml(entry.notes || "No notes")}</p>
      <div class="card-actions">
        <button type="button" data-copy="${entry.id}">Copy Password</button>
        <button type="button" data-reveal="${entry.id}">Reveal</button>
        <button type="button" data-delete-password="${entry.id}">Delete</button>
      </div>
    `;
    els.passwordList.append(card);
  });
}

function renderProjects() {
  els.projectList.innerHTML = "";

  if (!state.data.projects.length) {
    const empty = cloneEmptyState();
    empty.querySelector("p").textContent = "Start with a project so tasks and notes have context.";
    els.projectList.append(empty);
    return;
  }

  state.data.projects
    .slice()
    .sort((left, right) => right.createdAt.localeCompare(left.createdAt))
    .forEach((project) => {
      const card = document.createElement("article");
      const statusClass = project.status === "Done" ? "success" : project.status === "Blocked" ? "warning" : "";
      card.className = "card";
      card.innerHTML = `
        <div class="card-top">
          <div>
            <h4>${escapeHtml(project.name)}</h4>
            <p>${escapeHtml(project.summary || "No summary yet")}</p>
          </div>
          <span class="pill ${statusClass}">${escapeHtml(project.status)}</span>
        </div>
        <div class="card-meta">
          <span class="meta">Owner: ${escapeHtml(project.owner)}</span>
          <span class="meta">Due: ${escapeHtml(formatDate(project.dueDate))}</span>
        </div>
        <div class="card-actions">
          <button type="button" data-delete-project="${project.id}">Delete</button>
        </div>
      `;
      els.projectList.append(card);
    });
}

function renderNotes() {
  els.noteList.innerHTML = "";
  const query = els.noteSearch.value.trim().toLowerCase();
  const notes = state.data.notes.filter((note) => {
    const searchable = `${note.title} ${note.tags.join(" ")} ${note.body}`.toLowerCase();
    return searchable.includes(query);
  });

  if (!notes.length) {
    const empty = cloneEmptyState();
    empty.querySelector("p").textContent = query ? "No notes matched your search." : "Save a note and it will show up here.";
    els.noteList.append(empty);
    return;
  }

  notes
    .slice()
    .sort((left, right) => right.updatedAt.localeCompare(left.updatedAt))
    .forEach((note) => {
      const card = document.createElement("article");
      card.className = "card";
      card.innerHTML = `
        <div class="card-top">
          <div>
            <h4>${escapeHtml(note.title)}</h4>
            <p>${escapeHtml(note.body.slice(0, 180))}${note.body.length > 180 ? "..." : ""}</p>
          </div>
        </div>
        <div class="card-meta">
          <span class="meta">Updated: ${escapeHtml(formatDate(note.updatedAt))}</span>
          <div>${note.tags.map((tag) => `<span class="tag">${escapeHtml(tag)}</span>`).join(" ")}</div>
        </div>
        <div class="card-actions">
          <button type="button" data-delete-note="${note.id}">Delete</button>
        </div>
      `;
      els.noteList.append(card);
    });
}

function renderTasks() {
  els.taskList.innerHTML = "";

  const priorityRank = {
    High: 0,
    Medium: 1,
    Low: 2,
  };

  if (!state.data.tasks.length) {
    const empty = cloneEmptyState();
    empty.querySelector("p").textContent = "Capture a task and keep the queue moving.";
    els.taskList.append(empty);
    return;
  }

  state.data.tasks
    .slice()
    .sort((left, right) => Number(left.completed) - Number(right.completed) || priorityRank[left.priority] - priorityRank[right.priority])
    .forEach((task) => {
      const card = document.createElement("article");
      card.className = `card ${task.completed ? "completed" : ""}`;
      card.innerHTML = `
        <div class="task-row">
          <label class="task-row">
            <input type="checkbox" data-toggle-task="${task.id}" ${task.completed ? "checked" : ""}>
            <span class="task-title">${escapeHtml(task.title)}</span>
          </label>
          <span class="pill ${task.priority === "High" ? "warning" : task.completed ? "success" : ""}">${escapeHtml(task.priority)}</span>
        </div>
        <div class="card-meta">
          <span class="meta">Project: ${escapeHtml(task.project || "None")}</span>
          <span class="meta">Due: ${escapeHtml(formatDate(task.dueDate))}</span>
        </div>
        <div class="card-actions">
          <button type="button" data-delete-task="${task.id}">Delete</button>
        </div>
      `;
      els.taskList.append(card);
    });
}

function exportData() {
  const blob = new Blob(
    [
      JSON.stringify(
        {
          exportedAt: new Date().toISOString(),
          appData: state.data,
          encryptedVault: localStorage.getItem(VAULT_KEY) ? JSON.parse(localStorage.getItem(VAULT_KEY)) : null,
        },
        null,
        2
      ),
    ],
    { type: "application/json" }
  );

  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = `utilityhub-backup-${new Date().toISOString().slice(0, 10)}.json`;
  link.click();
  URL.revokeObjectURL(link.href);
  setStatus("Backup exported");
}

function bindEvents() {
  els.navButtons.forEach((button) => {
    button.addEventListener("click", () => switchView(button.dataset.view));
  });

  els.exportButton.addEventListener("click", exportData);

  els.vaultForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      await unlockVault(els.masterPassword.value);
    } catch (error) {
      console.error(error);
      setStatus("Could not unlock vault. Check the passphrase.");
    }
  });

  els.lockVault.addEventListener("click", lockVault);

  els.generatePassword.addEventListener("click", () => {
    els.generatedPassword.value = generatePasswordValue();
    setStatus("Generated a strong password");
  });

  els.useGenerated.addEventListener("click", () => {
    document.getElementById("entry-password").value = els.generatedPassword.value;
  });

  els.passwordEntryForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!state.vaultUnlocked) {
      setStatus("Unlock the vault before adding entries");
      return;
    }

    const formData = new FormData(els.passwordEntryForm);
    state.vaultEntries.unshift({
      id: uid(),
      service: String(formData.get("entry-service") || "").trim(),
      username: String(formData.get("entry-username") || "").trim(),
      password: String(formData.get("entry-password") || ""),
      notes: String(formData.get("entry-notes") || "").trim(),
    });
    els.passwordEntryForm.reset();
    await persistVault();
    renderPasswords();
  });

  els.passwordSearch.addEventListener("input", renderPasswords);

  els.passwordList.addEventListener("click", async (event) => {
    const target = event.target;
    if (!(target instanceof HTMLButtonElement)) {
      return;
    }

    const copyId = target.dataset.copy;
    const revealId = target.dataset.reveal;
    const deleteId = target.dataset.deletePassword;

    if (copyId) {
      const entry = state.vaultEntries.find((item) => item.id === copyId);
      if (entry) {
        await navigator.clipboard.writeText(entry.password);
        setStatus(`Copied password for ${entry.service}`);
      }
    }

    if (revealId) {
      const entry = state.vaultEntries.find((item) => item.id === revealId);
      if (entry) {
        alert(`${entry.service}\n${entry.username}\n\n${entry.password}`);
      }
    }

    if (deleteId) {
      state.vaultEntries = state.vaultEntries.filter((item) => item.id !== deleteId);
      await persistVault();
      renderPasswords();
    }
  });

  els.projectForm.addEventListener("submit", (event) => {
    event.preventDefault();
    state.data.projects.unshift({
      id: uid(),
      name: document.getElementById("project-name").value.trim(),
      owner: document.getElementById("project-owner").value.trim(),
      dueDate: document.getElementById("project-due-date").value,
      status: document.getElementById("project-status").value,
      summary: document.getElementById("project-summary").value.trim(),
      createdAt: new Date().toISOString(),
    });
    els.projectForm.reset();
    saveAppData();
    renderProjects();
  });

  els.projectList.addEventListener("click", (event) => {
    const target = event.target;
    if (!(target instanceof HTMLButtonElement) || !target.dataset.deleteProject) {
      return;
    }

    state.data.projects = state.data.projects.filter((project) => project.id !== target.dataset.deleteProject);
    saveAppData();
    renderProjects();
  });

  els.noteForm.addEventListener("submit", (event) => {
    event.preventDefault();
    const now = new Date().toISOString();
    state.data.notes.unshift({
      id: uid(),
      title: document.getElementById("note-title").value.trim(),
      tags: document.getElementById("note-tags").value.split(",").map((tag) => tag.trim()).filter(Boolean),
      body: document.getElementById("note-body").value.trim(),
      updatedAt: now,
    });
    els.noteForm.reset();
    saveAppData();
    renderNotes();
  });

  els.noteSearch.addEventListener("input", renderNotes);

  els.noteList.addEventListener("click", (event) => {
    const target = event.target;
    if (!(target instanceof HTMLButtonElement) || !target.dataset.deleteNote) {
      return;
    }

    state.data.notes = state.data.notes.filter((note) => note.id !== target.dataset.deleteNote);
    saveAppData();
    renderNotes();
  });

  els.taskForm.addEventListener("submit", (event) => {
    event.preventDefault();
    state.data.tasks.unshift({
      id: uid(),
      title: document.getElementById("task-title").value.trim(),
      priority: document.getElementById("task-priority").value,
      project: document.getElementById("task-project").value.trim(),
      dueDate: document.getElementById("task-due-date").value,
      completed: false,
    });
    els.taskForm.reset();
    saveAppData();
    renderTasks();
  });

  els.taskList.addEventListener("click", (event) => {
    const target = event.target;
    if (!(target instanceof HTMLElement)) {
      return;
    }

    if (target instanceof HTMLInputElement && target.dataset.toggleTask) {
      const task = state.data.tasks.find((item) => item.id === target.dataset.toggleTask);
      if (task) {
        task.completed = target.checked;
        saveAppData();
        renderTasks();
      }
      return;
    }

    if (target instanceof HTMLButtonElement && target.dataset.deleteTask) {
      state.data.tasks = state.data.tasks.filter((task) => task.id !== target.dataset.deleteTask);
      saveAppData();
      renderTasks();
    }
  });
}

function bootstrap() {
  bindEvents();
  els.generatedPassword.value = generatePasswordValue();
  renderPasswords();
  renderProjects();
  renderNotes();
  renderTasks();
}

bootstrap();
