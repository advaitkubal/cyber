/**
 * static/js/app.js
 * Primary client-side application logic for the SecureVault Dashboard:
 * - Notes & Credentials CRUD with encrypted transmission
 * - 10-second auto-masking credential reveal
 * - Raw ciphertext inspection (Cryptographic proof of encryption at rest)
 * - CSPRNG Password Generator (window.crypto.getRandomValues)
 * - Audit trail viewer
 * - Safe DOM rendering: strictly uses textContent & createElement (Zero innerHTML)
 * - Strict CSRF verification on all mutating requests
 */

document.addEventListener("DOMContentLoaded", () => {
  // CSRF token retrieval
  const csrfMeta = document.querySelector('meta[name="csrf-token"]');
  const csrfToken = csrfMeta ? csrfMeta.getAttribute("content") : "";

  // Helper: Toast Notifications
  const toastContainer = document.getElementById("toast-container");
  const showToast = (message, type = "info") => {
    if (!toastContainer) return;
    const toast = document.createElement("div");
    toast.className = `toast toast-${type}`;
    
    const textSpan = document.createElement("span");
    textSpan.textContent = message;
    toast.appendChild(textSpan);

    const closeBtn = document.createElement("button");
    closeBtn.className = "modal-close";
    closeBtn.textContent = "×";
    closeBtn.setAttribute("aria-label", "Close notification");
    closeBtn.addEventListener("click", () => toast.remove());
    toast.appendChild(closeBtn);

    toastContainer.appendChild(toast);
    setTimeout(() => {
      if (toast.isConnected) toast.remove();
    }, 3800);
  };

  // Helper: Secure JSON API Fetch
  const apiFetch = async (url, options = {}) => {
    const headers = options.headers || {};
    if (options.method && options.method !== "GET") {
      headers["X-CSRF-Token"] = csrfToken;
      headers["Content-Type"] = "application/json";
    }

    try {
      const response = await fetch(url, { ...options, headers });
      const data = await response.json().catch(() => ({}));

      if (!response.ok) {
        throw new Error(data.error || `HTTP error ${response.status}`);
      }
      return data;
    } catch (err) {
      showToast(err.message, "error");
      throw err;
    }
  };

  // =========================================================================
  // TAB NAVIGATION
  // =========================================================================
  const tabButtons = document.querySelectorAll(".nav-tab");
  const tabContents = document.querySelectorAll(".tab-content");

  const activateTab = (tabId) => {
    tabButtons.forEach((btn) => {
      const isSelected = btn.getAttribute("data-tab") === tabId;
      btn.classList.toggle("active", isSelected);
      btn.setAttribute("aria-selected", isSelected ? "true" : "false");
    });

    tabContents.forEach((content) => {
      content.classList.toggle("active", content.id === tabId);
    });

    if (tabId === "tab-notes") loadNotes();
    if (tabId === "tab-credentials") loadCredentials();
    if (tabId === "tab-audit") loadAuditLogs();
  };

  tabButtons.forEach((btn) => {
    btn.addEventListener("click", () => {
      const target = btn.getAttribute("data-tab");
      if (target) activateTab(target);
    });
  });

  // =========================================================================
  // MODAL MANAGEMENT (Keyboard accessible with Escape key support)
  // =========================================================================
  const allModals = document.querySelectorAll(".modal-backdrop");
  const closeModal = (modal) => {
    if (modal) modal.classList.add("hidden");
  };

  allModals.forEach((modal) => {
    modal.addEventListener("click", (e) => {
      if (e.target === modal) closeModal(modal);
    });
  });

  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      allModals.forEach((m) => closeModal(m));
    }
  });

  // =========================================================================
  // DELETE CONFIRMATION MODAL
  // =========================================================================
  const modalConfirm = document.getElementById("modal-confirm");
  const confirmMsg = document.getElementById("confirm-modal-message");
  const btnCancelConfirm = document.getElementById("btn-cancel-confirm");
  const btnCloseConfirmModal = document.getElementById("btn-close-confirm-modal");
  const btnExecuteConfirm = document.getElementById("btn-execute-confirm");
  let pendingDeleteAction = null;

  const showConfirmDialog = (message, onConfirm) => {
    if (confirmMsg) confirmMsg.textContent = message;
    pendingDeleteAction = onConfirm;
    if (modalConfirm) modalConfirm.classList.remove("hidden");
  };

  if (btnCancelConfirm) btnCancelConfirm.addEventListener("click", () => closeModal(modalConfirm));
  if (btnCloseConfirmModal) btnCloseConfirmModal.addEventListener("click", () => closeModal(modalConfirm));
  if (btnExecuteConfirm) {
    btnExecuteConfirm.addEventListener("click", async () => {
      if (pendingDeleteAction) {
        await pendingDeleteAction();
        pendingDeleteAction = null;
      }
      closeModal(modalConfirm);
    });
  }

  // =========================================================================
  // RAW CIPHERTEXT INSPECTION MODAL (Proof of Encryption at Rest)
  // =========================================================================
  const modalRaw = document.getElementById("modal-raw");
  const rawContent = document.getElementById("raw-ciphertext-content");
  const btnCloseRawModal = document.getElementById("btn-close-raw-modal");
  const btnDismissRaw = document.getElementById("btn-dismiss-raw");
  const btnCopyRaw = document.getElementById("btn-copy-raw");

  const showRawCiphertextModal = async (endpoint, titleText) => {
    const titleElem = document.getElementById("modal-raw-title");
    if (titleElem) titleElem.textContent = titleText;
    if (rawContent) rawContent.textContent = "Fetching raw ciphertext directly from database...";
    if (modalRaw) modalRaw.classList.remove("hidden");

    try {
      const data = await apiFetch(endpoint);
      if (rawContent) {
        rawContent.textContent = JSON.stringify(data, null, 2);
      }
    } catch {
      if (rawContent) rawContent.textContent = "Failed to load raw ciphertext.";
    }
  };

  if (btnCloseRawModal) btnCloseRawModal.addEventListener("click", () => closeModal(modalRaw));
  if (btnDismissRaw) btnDismissRaw.addEventListener("click", () => closeModal(modalRaw));
  if (btnCopyRaw) {
    btnCopyRaw.addEventListener("click", () => {
      if (rawContent) {
        navigator.clipboard.writeText(rawContent.textContent).then(() => {
          showToast("Raw ciphertext copied to clipboard", "success");
        });
      }
    });
  }

  // =========================================================================
  // NOTES MANAGEMENT
  // =========================================================================
  const notesContainer = document.getElementById("notes-container");
  const noteSearchInput = document.getElementById("note-search-input");
  const btnOpenCreateNote = document.getElementById("btn-open-create-note");
  const modalNote = document.getElementById("modal-note");
  const formNote = document.getElementById("form-note");
  const noteIdInput = document.getElementById("note-id-input");
  const noteTitleInput = document.getElementById("note-title-input");
  const noteBodyInput = document.getElementById("note-body-input");
  const btnCloseNoteModal = document.getElementById("btn-close-note-modal");
  const btnCancelNote = document.getElementById("btn-cancel-note");
  const modalNoteTitle = document.getElementById("modal-note-title");

  let currentNotes = [];

  const renderNotes = (notes) => {
    if (!notesContainer) return;
    while (notesContainer.firstChild) {
      notesContainer.removeChild(notesContainer.firstChild);
    }

    if (notes.length === 0) {
      const emptyState = document.createElement("div");
      emptyState.className = "loading-state";
      emptyState.textContent = "No encrypted notes found. Click '+ New Note' to create one.";
      notesContainer.appendChild(emptyState);
      return;
    }

    notes.forEach((note) => {
      const card = document.createElement("div");
      card.className = "note-card";

      const header = document.createElement("div");
      header.className = "note-header";

      const title = document.createElement("h3");
      title.className = "note-title";
      title.textContent = note.title;
      header.appendChild(title);

      const date = document.createElement("span");
      date.className = "note-date";
      date.textContent = new Date(note.created_at).toLocaleDateString();
      header.appendChild(date);
      card.appendChild(header);

      const body = document.createElement("div");
      body.className = "note-body";
      body.textContent = note.body;
      card.appendChild(body);

      const actions = document.createElement("div");
      actions.className = "note-actions";

      const btnEdit = document.createElement("button");
      btnEdit.type = "button";
      btnEdit.className = "btn btn-sm btn-outline";
      btnEdit.textContent = "Edit";
      btnEdit.addEventListener("click", () => openEditNoteModal(note));
      actions.appendChild(btnEdit);

      const btnRaw = document.createElement("button");
      btnRaw.type = "button";
      btnRaw.className = "btn btn-sm btn-secondary";
      btnRaw.textContent = "View Ciphertext";
      btnRaw.title = "Inspect raw AES-256-GCM ciphertext as stored in DB";
      btnRaw.addEventListener("click", () => {
        showRawCiphertextModal(`/api/notes/${note.id}/raw`, `Note #${note.id} Raw Stored Ciphertext`);
      });
      actions.appendChild(btnRaw);

      const btnDelete = document.createElement("button");
      btnDelete.type = "button";
      btnDelete.className = "btn btn-sm btn-danger";
      btnDelete.textContent = "Delete";
      btnDelete.addEventListener("click", () => {
        showConfirmDialog(`Are you sure you want to delete note "${note.title}"?`, async () => {
          await apiFetch(`/api/notes/${note.id}`, { method: "DELETE" });
          showToast("Note deleted successfully", "success");
          loadNotes();
        });
      });
      actions.appendChild(btnDelete);

      card.appendChild(actions);
      notesContainer.appendChild(card);
    });
  };

  const loadNotes = async () => {
    const query = noteSearchInput ? noteSearchInput.value.trim() : "";
    const url = query ? `/api/notes?q=${encodeURIComponent(query)}` : "/api/notes";
    try {
      const data = await apiFetch(url);
      currentNotes = data;
      renderNotes(currentNotes);
    } catch {
      // Handled via apiFetch
    }
  };

  const openCreateNoteModal = () => {
    if (modalNoteTitle) modalNoteTitle.textContent = "Create Encrypted Note";
    if (noteIdInput) noteIdInput.value = "";
    if (noteTitleInput) noteTitleInput.value = "";
    if (noteBodyInput) noteBodyInput.value = "";
    if (modalNote) modalNote.classList.remove("hidden");
    if (noteTitleInput) noteTitleInput.focus();
  };

  const openEditNoteModal = (note) => {
    if (modalNoteTitle) modalNoteTitle.textContent = "Edit Encrypted Note";
    if (noteIdInput) noteIdInput.value = note.id;
    if (noteTitleInput) noteTitleInput.value = note.title;
    if (noteBodyInput) noteBodyInput.value = note.body;
    if (modalNote) modalNote.classList.remove("hidden");
    if (noteTitleInput) noteTitleInput.focus();
  };

  if (btnOpenCreateNote) btnOpenCreateNote.addEventListener("click", openCreateNoteModal);
  if (btnCloseNoteModal) btnCloseNoteModal.addEventListener("click", () => closeModal(modalNote));
  if (btnCancelNote) btnCancelNote.addEventListener("click", () => closeModal(modalNote));

  if (noteSearchInput) {
    let timeout = null;
    noteSearchInput.addEventListener("input", () => {
      clearTimeout(timeout);
      timeout = setTimeout(loadNotes, 250);
    });
  }

  if (formNote) {
    formNote.addEventListener("submit", async (e) => {
      e.preventDefault();
      const id = noteIdInput ? noteIdInput.value : "";
      const title = noteTitleInput ? noteTitleInput.value.trim() : "";
      const body = noteBodyInput ? noteBodyInput.value.trim() : "";

      if (!title) {
        showToast("Note title is required", "error");
        return;
      }

      const method = id ? "PUT" : "POST";
      const url = id ? `/api/notes/${id}` : "/api/notes";

      try {
        await apiFetch(url, {
          method,
          body: JSON.stringify({ title, body }),
        });
        showToast(id ? "Note updated successfully" : "Encrypted note created", "success");
        closeModal(modalNote);
        loadNotes();
      } catch {
        // Handled via apiFetch
      }
    });
  }

  // =========================================================================
  // CREDENTIALS MANAGEMENT
  // =========================================================================
  const credsTbody = document.getElementById("credentials-tbody");
  const credSearchInput = document.getElementById("cred-search-input");
  const btnOpenCreateCred = document.getElementById("btn-open-create-cred");
  const modalCred = document.getElementById("modal-cred");
  const formCred = document.getElementById("form-cred");
  const credIdInput = document.getElementById("cred-id-input");
  const credSiteInput = document.getElementById("cred-site-input");
  const credUsernameInput = document.getElementById("cred-username-input");
  const credPasswordInput = document.getElementById("cred-password-input");
  const credPasswordHint = document.getElementById("cred-password-hint");
  const credUrlInput = document.getElementById("cred-url-input");
  const credRemarksInput = document.getElementById("cred-remarks-input");
  const btnCloseCredModal = document.getElementById("btn-close-cred-modal");
  const btnCancelCred = document.getElementById("btn-cancel-cred");
  const modalCredTitle = document.getElementById("modal-cred-title");

  let currentCredentials = [];
  const activeRevealTimers = new Map();

  const renderCredentials = (creds) => {
    if (!credsTbody) return;
    while (credsTbody.firstChild) {
      credsTbody.removeChild(credsTbody.firstChild);
    }

    if (creds.length === 0) {
      const row = document.createElement("tr");
      const td = document.createElement("td");
      td.colSpan = 6;
      td.className = "text-center";
      td.textContent = "No credentials stored. Click '+ Add Credential' to secure account details.";
      row.appendChild(td);
      credsTbody.appendChild(row);
      return;
    }

    creds.forEach((c) => {
      const row = document.createElement("tr");

      // Site
      const tdSite = document.createElement("td");
      const siteStrong = document.createElement("strong");
      siteStrong.textContent = c.site;
      tdSite.appendChild(siteStrong);
      row.appendChild(tdSite);

      // Username
      const tdUser = document.createElement("td");
      tdUser.textContent = c.username;
      row.appendChild(tdUser);

      // Password (Masked by default)
      const tdPass = document.createElement("td");
      const passBox = document.createElement("span");
      passBox.className = "password-masked-box";
      passBox.id = `pwd-display-${c.id}`;
      passBox.textContent = c.password_masked;
      tdPass.appendChild(passBox);
      row.appendChild(tdPass);

      // URL
      const tdUrl = document.createElement("td");
      if (c.url) {
        const link = document.createElement("a");
        link.href = c.url;
        link.target = "_blank";
        link.rel = "noopener noreferrer";
        link.textContent = c.url.length > 25 ? c.url.substring(0, 22) + "..." : c.url;
        tdUrl.appendChild(link);
      } else {
        tdUrl.textContent = "-";
      }
      row.appendChild(tdUrl);

      // Remarks
      const tdRemarks = document.createElement("td");
      tdRemarks.textContent = c.remarks || "-";
      row.appendChild(tdRemarks);

      // Actions
      const tdActions = document.createElement("td");
      const actionsDiv = document.createElement("div");
      actionsDiv.className = "table-actions";

      // Reveal Button (10-second timer)
      const btnReveal = document.createElement("button");
      btnReveal.type = "button";
      btnReveal.className = "btn btn-sm btn-secondary";
      btnReveal.id = `btn-reveal-${c.id}`;
      btnReveal.textContent = "Reveal";
      btnReveal.addEventListener("click", () => handleRevealPassword(c.id, passBox, btnReveal));
      actionsDiv.appendChild(btnReveal);

      // Copy Button
      const btnCopy = document.createElement("button");
      btnCopy.type = "button";
      btnCopy.className = "btn btn-sm btn-outline";
      btnCopy.textContent = "Copy";
      btnCopy.addEventListener("click", async () => {
        try {
          const res = await apiFetch(`/api/credentials/${c.id}/reveal`);
          await navigator.clipboard.writeText(res.password);
          showToast(`Password for ${c.site} copied to clipboard`, "success");
        } catch {
          // Handled
        }
      });
      actionsDiv.appendChild(btnCopy);

      // Raw Ciphertext Button
      const btnRaw = document.createElement("button");
      btnRaw.type = "button";
      btnRaw.className = "btn btn-sm btn-outline";
      btnRaw.textContent = "Raw";
      btnRaw.title = "View raw encrypted database row";
      btnRaw.addEventListener("click", () => {
        showRawCiphertextModal(`/api/credentials/${c.id}/raw`, `Credential #${c.id} Raw Ciphertext`);
      });
      actionsDiv.appendChild(btnRaw);

      // Edit Button
      const btnEdit = document.createElement("button");
      btnEdit.type = "button";
      btnEdit.className = "btn btn-sm btn-outline";
      btnEdit.textContent = "Edit";
      btnEdit.addEventListener("click", () => openEditCredModal(c));
      actionsDiv.appendChild(btnEdit);

      // Delete Button
      const btnDelete = document.createElement("button");
      btnDelete.type = "button";
      btnDelete.className = "btn btn-sm btn-danger";
      btnDelete.textContent = "Delete";
      btnDelete.addEventListener("click", () => {
        showConfirmDialog(`Are you sure you want to delete credential for "${c.site}"?`, async () => {
          await apiFetch(`/api/credentials/${c.id}`, { method: "DELETE" });
          showToast("Credential deleted successfully", "success");
          loadCredentials();
        });
      });
      actionsDiv.appendChild(btnDelete);

      tdActions.appendChild(actionsDiv);
      row.appendChild(tdActions);

      credsTbody.appendChild(row);
    });
  };

  const handleRevealPassword = async (credId, passBoxElem, btnElem) => {
    // If already active, reset timer or mask immediately
    if (activeRevealTimers.has(credId)) {
      clearInterval(activeRevealTimers.get(credId).interval);
      activeRevealTimers.delete(credId);
      passBoxElem.textContent = "••••••••";
      btnElem.textContent = "Reveal";
      return;
    }

    try {
      const data = await apiFetch(`/api/credentials/${credId}/reveal`);
      passBoxElem.textContent = data.password;

      let remaining = 10;
      btnElem.textContent = `Mask (${remaining}s)`;

      const interval = setInterval(() => {
        remaining -= 1;
        if (remaining > 0) {
          btnElem.textContent = `Mask (${remaining}s)`;
        } else {
          clearInterval(interval);
          activeRevealTimers.delete(credId);
          passBoxElem.textContent = "••••••••";
          btnElem.textContent = "Reveal";
        }
      }, 1000);

      activeRevealTimers.set(credId, { interval, passBoxElem, btnElem });
    } catch {
      // Handled
    }
  };

  const loadCredentials = async () => {
    const query = credSearchInput ? credSearchInput.value.trim() : "";
    const url = query ? `/api/credentials?q=${encodeURIComponent(query)}` : "/api/credentials";
    try {
      const data = await apiFetch(url);
      currentCredentials = data;
      renderCredentials(currentCredentials);
    } catch {
      // Handled
    }
  };

  const openCreateCredModal = () => {
    if (modalCredTitle) modalCredTitle.textContent = "Add Credential";
    if (credIdInput) credIdInput.value = "";
    if (credSiteInput) credSiteInput.value = "";
    if (credUsernameInput) credUsernameInput.value = "";
    if (credPasswordInput) {
      credPasswordInput.value = "";
      credPasswordInput.required = true;
    }
    if (credPasswordHint) credPasswordHint.textContent = "Encrypted using AES-256-GCM before saving.";
    if (credUrlInput) credUrlInput.value = "";
    if (credRemarksInput) credRemarksInput.value = "";
    if (modalCred) modalCred.classList.remove("hidden");
    if (credSiteInput) credSiteInput.focus();
  };

  const openEditCredModal = (c) => {
    if (modalCredTitle) modalCredTitle.textContent = "Edit Credential";
    if (credIdInput) credIdInput.value = c.id;
    if (credSiteInput) credSiteInput.value = c.site;
    if (credUsernameInput) credUsernameInput.value = c.username;
    if (credPasswordInput) {
      credPasswordInput.value = "";
      credPasswordInput.required = false;
    }
    if (credPasswordHint) credPasswordHint.textContent = "Leave blank to keep existing password.";
    if (credUrlInput) credUrlInput.value = c.url;
    if (credRemarksInput) credRemarksInput.value = c.remarks;
    if (modalCred) modalCred.classList.remove("hidden");
    if (credSiteInput) credSiteInput.focus();
  };

  if (btnOpenCreateCred) btnOpenCreateCred.addEventListener("click", openCreateCredModal);
  if (btnCloseCredModal) btnCloseCredModal.addEventListener("click", () => closeModal(modalCred));
  if (btnCancelCred) btnCancelCred.addEventListener("click", () => closeModal(modalCred));

  if (credSearchInput) {
    let timeout = null;
    credSearchInput.addEventListener("input", () => {
      clearTimeout(timeout);
      timeout = setTimeout(loadCredentials, 250);
    });
  }

  if (formCred) {
    formCred.addEventListener("submit", async (e) => {
      e.preventDefault();
      const id = credIdInput ? credIdInput.value : "";
      const site = credSiteInput ? credSiteInput.value.trim() : "";
      const username = credUsernameInput ? credUsernameInput.value.trim() : "";
      const password = credPasswordInput ? credPasswordInput.value : "";
      const url = credUrlInput ? credUrlInput.value.trim() : "";
      const remarks = credRemarksInput ? credRemarksInput.value.trim() : "";

      if (!site || !username) {
        showToast("Site and username are required", "error");
        return;
      }
      if (!id && !password) {
        showToast("Password is required for new credentials", "error");
        return;
      }

      const method = id ? "PUT" : "POST";
      const apiUrl = id ? `/api/credentials/${id}` : "/api/credentials";
      const payload = { site, username, url, remarks };
      if (password) payload.password = password;

      try {
        await apiFetch(apiUrl, {
          method,
          body: JSON.stringify(payload),
        });
        showToast(id ? "Credential updated" : "Credential saved securely", "success");
        closeModal(modalCred);
        loadCredentials();
      } catch {
        // Handled
      }
    });
  }

  // =========================================================================
  // PASSWORD GENERATOR (window.crypto.getRandomValues CSPRNG)
  // =========================================================================
  const generatedPwdDisplay = document.getElementById("generated-password-display");
  const btnCopyGenerated = document.getElementById("btn-copy-generated");
  const btnUseGenerated = document.getElementById("btn-use-generated");
  const btnRegenerate = document.getElementById("btn-regenerate");
  const pwdLengthSlider = document.getElementById("pwd-length-slider");
  const pwdLengthVal = document.getElementById("pwd-length-val");
  const genOptUpper = document.getElementById("gen-opt-uppercase");
  const genOptLower = document.getElementById("gen-opt-lowercase");
  const genOptDigits = document.getElementById("gen-opt-digits");
  const genOptSymbols = document.getElementById("gen-opt-symbols");

  const generateSecurePassword = () => {
    const length = pwdLengthSlider ? parseInt(pwdLengthSlider.value, 10) : 20;
    const useUpper = genOptUpper ? genOptUpper.checked : true;
    const useLower = genOptLower ? genOptLower.checked : true;
    const useDigits = genOptDigits ? genOptDigits.checked : true;
    const useSymbols = genOptSymbols ? genOptSymbols.checked : true;

    let charset = "";
    if (useUpper) charset += "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    if (useLower) charset += "abcdefghijklmnopqrstuvwxyz";
    if (useDigits) charset += "0123456789";
    if (useSymbols) charset += "!@#$%^&*()_+-=[]{}|;:,.<>?";

    if (!charset) {
      showToast("Select at least one character set for generator", "warning");
      return;
    }

    // SECURITY: CSPRNG - Uses window.crypto.getRandomValues instead of Math.random
    const randomBuffer = new Uint32Array(length);
    window.crypto.getRandomValues(randomBuffer);

    let password = "";
    for (let i = 0; i < length; i++) {
      password += charset[randomBuffer[i] % charset.length];
    }

    if (generatedPwdDisplay) {
      generatedPwdDisplay.value = password;
    }
  };

  if (pwdLengthSlider && pwdLengthVal) {
    pwdLengthSlider.addEventListener("input", () => {
      pwdLengthVal.textContent = pwdLengthSlider.value;
      generateSecurePassword();
    });
  }

  [genOptUpper, genOptLower, genOptDigits, genOptSymbols].forEach((opt) => {
    if (opt) opt.addEventListener("change", generateSecurePassword);
  });

  if (btnRegenerate) btnRegenerate.addEventListener("click", generateSecurePassword);

  if (btnCopyGenerated && generatedPwdDisplay) {
    btnCopyGenerated.addEventListener("click", () => {
      if (generatedPwdDisplay.value) {
        navigator.clipboard.writeText(generatedPwdDisplay.value).then(() => {
          showToast("Generated password copied to clipboard", "success");
        });
      }
    });
  }

  if (btnUseGenerated && generatedPwdDisplay) {
    btnUseGenerated.addEventListener("click", () => {
      const generated = generatedPwdDisplay.value;
      if (!generated) {
        generateSecurePassword();
      }
      activateTab("tab-credentials");
      openCreateCredModal();
      if (credPasswordInput) {
        credPasswordInput.value = generatedPwdDisplay.value;
      }
      showToast("Generated password applied to credential form", "info");
    });
  }

  // =========================================================================
  // AUDIT LOGS
  // =========================================================================
  const auditTbody = document.getElementById("audit-tbody");
  const btnRefreshAudit = document.getElementById("btn-refresh-audit");

  const loadAuditLogs = async () => {
    if (!auditTbody) return;
    try {
      const rows = await apiFetch("/api/audit");
      while (auditTbody.firstChild) {
        auditTbody.removeChild(auditTbody.firstChild);
      }

      if (rows.length === 0) {
        const row = document.createElement("tr");
        const td = document.createElement("td");
        td.colSpan = 3;
        td.className = "text-center";
        td.textContent = "No audit log entries recorded yet.";
        row.appendChild(td);
        auditTbody.appendChild(row);
        return;
      }

      rows.forEach((log) => {
        const tr = document.createElement("tr");

        const tdEvent = document.createElement("td");
        const eventBadge = document.createElement("span");
        eventBadge.className = "badge-tag";
        eventBadge.textContent = log.event;
        tdEvent.appendChild(eventBadge);
        tr.appendChild(tdEvent);

        const tdIp = document.createElement("td");
        tdIp.textContent = log.ip || "127.0.0.1";
        tr.appendChild(tdIp);

        const tdTime = document.createElement("td");
        tdTime.textContent = log.created_at;
        tr.appendChild(tdTime);

        auditTbody.appendChild(tr);
      });
    } catch {
      // Handled
    }
  };

  if (btnRefreshAudit) btnRefreshAudit.addEventListener("click", loadAuditLogs);

  // Initial load
  loadNotes();
  generateSecurePassword();
});
