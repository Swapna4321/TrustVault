
const authScreen = document.querySelector('#auth-screen');
const appScreen = document.querySelector('#app-screen');
const authForm = document.querySelector('#auth-form');
const authError = document.querySelector('#auth-error');
const authSwitch = document.querySelector('#auth-switch');
const dialogBackdrop = document.querySelector('#dialog-backdrop');
const dialogContent = document.querySelector('#dialog-content');
const toast = document.querySelector('#toast');

const state = {
  token: sessionStorage.getItem('trustvault-token'),
  user: null,
  registerMode: false,
  documents: [],
  toastTimer: null,
  searchTimer: null,
};

// ==========================================
// COMMON FUNCTIONS
// ==========================================

function escapeHTML(value) {
  return String(value ?? '').replace(/[&<>"']/g, (character) => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;',
  })[character]);
}

function showToast(message, isError = false) {
  clearTimeout(state.toastTimer);
  toast.textContent = message;
  toast.classList.toggle('is-error', isError);
  toast.classList.add('is-visible');

  state.toastTimer = setTimeout(
    () => toast.classList.remove('is-visible'),
    3400
  );
}

function isAdmin() {
  return String(state.user?.role || '').toLowerCase() === 'admin';
}

async function api(path, options = {}) {
  const headers = new Headers(options.headers || {});

  if (state.token) {
    headers.set('Authorization', `Bearer ${state.token}`);
  }

  const response = await fetch(path, {
    ...options,
    headers,
  });

  if (!response.ok) {
    let message = `Request failed (${response.status})`;

    try {
      const body = await response.json();
      if (body.detail) message = body.detail;
    } catch {
      // Keep the default error message.
    }

    throw new Error(message);
  }

  if (response.status === 204) return null;

  return response.json();
}

// ==========================================
// AUTHENTICATION
// ==========================================

function setAuthMode(registerMode) {
  state.registerMode = registerMode;
  authScreen.classList.toggle('is-register', registerMode);

  document.querySelector('#name-field').hidden = !registerMode;
  document.querySelector('#full-name').required = registerMode;

  document.querySelector('#password').autocomplete =
    registerMode ? 'new-password' : 'current-password';

  document.querySelector('#auth-eyebrow').textContent =
    registerMode ? 'CREATE YOUR VAULT' : 'SECURE ACCESS';

  document.querySelector('#auth-title').textContent =
    registerMode ? 'Create account' : 'Sign in';

  document.querySelector('#auth-intro').textContent =
    registerMode
      ? 'Set up your private document workspace.'
      : 'Access your private document workspace.';

  document.querySelector('#welcome-title').textContent =
    registerMode ? 'Hello, Friend!' : 'Welcome Back!';

  document.querySelector('#welcome-intro').textContent =
    registerMode
      ? 'Create an account to keep your important documents in one secure place.'
      : 'Enter your personal details to access your secure workspace.';

  document.querySelector('#auth-submit').innerHTML =
    registerMode
      ? 'Create account <span aria-hidden="true">↗</span>'
      : 'Sign in <span aria-hidden="true">↗</span>';

  document.querySelector('#switch-label').textContent =
    registerMode
      ? 'Already have an account?'
      : 'New to TrustVault?';

  authSwitch.textContent =
    registerMode ? 'Sign in' : 'Create account';

  authError.hidden = true;
}

async function enterWorkspace() {
  const result = await api('/users/me');

  state.user = result.user;

  authScreen.hidden = true;
  appScreen.hidden = false;

  document.querySelector('#user-name').textContent =
    state.user.full_name;

  document.querySelector('#user-role').textContent =
    state.user.role;

  document.querySelector('#user-avatar').textContent =
    state.user.full_name
      .split(/\s+/)
      .slice(0, 2)
      .map((part) => part[0])
      .join('')
      .toUpperCase();

  document.querySelector('#audit-nav').hidden = !isAdmin();

  document.querySelector('#users-nav').hidden = !isAdmin();
  document.querySelector('#overview-nav').hidden = !isAdmin();

  document.querySelector('#upload-open').hidden =
    String(state.user.role).toLowerCase() !== 'owner';
  document.querySelector('.search-box').hidden = isAdmin();

  document.querySelector('#empty-upload').hidden =
    String(state.user.role).toLowerCase() !== 'owner';

  document.querySelector('#profile-id').textContent = state.user.id;
  document.querySelector('#profile-name').textContent = state.user.full_name;
  document.querySelector('#profile-email').textContent = state.user.email;
  document.querySelector('#profile-role').textContent = state.user.role;
  document.querySelector('#profile-status').textContent =
    state.user.is_active ? 'Active' : 'Inactive';
  document.querySelector('#profile-avatar').textContent =
    document.querySelector('#user-avatar').textContent;

  const defaultView = isAdmin() ? 'overview' : 'documents';
  document.querySelectorAll('.nav-link').forEach((link) => {
    link.classList.toggle('is-active', link.dataset.view === defaultView);
  });

  if (isAdmin()) {
    appScreen.classList.add('is-admin-overview');
    document.querySelector('#documents-view').hidden = true;
    document.querySelector('#admin-overview-view').hidden = false;
    document.querySelector('#topbar-title').textContent = 'Dashboard';
    await loadAdminOverview();
    return;
  }

  appScreen.classList.remove('is-admin-overview');
  document.querySelector('#admin-overview-view').hidden = true;
  document.querySelector('#documents-view').hidden = false;
  await loadDocuments();
}

function leaveWorkspace() {
  state.token = null;
  state.user = null;

  sessionStorage.removeItem('trustvault-token');

  appScreen.hidden = true;
  authScreen.hidden = false;

  setAuthMode(false);
  authForm.reset();
}

authSwitch.addEventListener('click', () => {
  setAuthMode(!state.registerMode);
});

authForm.addEventListener('submit', async (event) => {
  event.preventDefault();

  authError.hidden = true;

  const submit = document.querySelector('#auth-submit');
  submit.disabled = true;

  try {
    if (state.registerMode) {
      await api('/register', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          full_name: document.querySelector('#full-name').value.trim(),
          email: document.querySelector('#email').value.trim(),
          password: document.querySelector('#password').value,
        }),
      });

      setAuthMode(false);
      document.querySelector('#password').value = '';

      showToast('Account created. Sign in to open your vault.');

    } else {
      const body = new URLSearchParams({
        username: document.querySelector('#email').value.trim(),
        password: document.querySelector('#password').value,
      });

      const result = await api('/login', {
        method: 'POST',
        body,
      });

      state.token = result.access_token;

      sessionStorage.setItem(
        'trustvault-token',
        state.token
      );

      await enterWorkspace();
    }

  } catch (error) {
    if (!state.registerMode && state.token) {
      leaveWorkspace();
    }

    authError.textContent = error.message;
    authError.hidden = false;

  } finally {
    submit.disabled = false;
  }
});

document.querySelector('#logout-button').addEventListener(
  'click',
  leaveWorkspace
);

// ==========================================
// DOCUMENT DISPLAY HELPERS
// ==========================================

function formatDate(value) {
  if (!value) return '—';

  const date = new Date(value);

  return Number.isNaN(date.getTime())
    ? '—'
    : new Intl.DateTimeFormat(undefined, {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
      }).format(date);
}

function formatTimestamp(value) {
  if (!value) return '—';

  const date = new Date(value);

  return Number.isNaN(date.getTime())
    ? '—'
    : new Intl.DateTimeFormat(undefined, {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: 'numeric',
        minute: '2-digit',
      }).format(date);
}

function fileType(name) {
  const extension = String(name).split('.').pop().toUpperCase();

  return extension.length > 4 ? 'FILE' : extension;
}

// ==========================================
// RENDER DOCUMENTS
// ==========================================

function renderDocuments(documents) {
  state.documents = documents;

  const rows = document.querySelector('#document-rows');

  const owned = documents.filter(
    (document) => document.owner_id === state.user.id
  ).length;

  const categories = new Set(
    documents
      .map((document) => document.category)
      .filter(Boolean)
  );

  document.querySelector('#stat-total').textContent =
    documents.length;

  document.querySelector('#stat-owned').textContent =
    owned;

  document.querySelector('#stat-categories').textContent =
    categories.size;

  document.querySelector('#nav-doc-count').textContent =
    documents.length;

  document.querySelector('#result-count').textContent =
    documents.length;

  document.querySelector('#documents-empty').hidden =
    documents.length > 0;

  rows.innerHTML = documents.map((document) => {
    const isOwner = document.owner_id === state.user.id;

    const canEdit =
      isOwner || document.access_type === 'EDIT';

    const actions = [
      `<button class="row-action"
        data-action="download"
        data-id="${document.id}"
        type="button">Download</button>`,
    ];

    if (canEdit) {
      actions.push(`
        <button class="row-action"
          data-action="edit"
          data-id="${document.id}"
          type="button">Edit</button>
      `);

      actions.push(`
        <button class="row-action"
          data-action="replace"
          data-id="${document.id}"
          type="button">Replace</button>
      `);
    }

    if (isOwner) {
      actions.push(`
        <button class="row-action"
          data-action="share"
          data-id="${document.id}"
          type="button">Share</button>
      `);

      actions.push(`
        <button class="row-action danger"
          data-action="delete"
          data-id="${document.id}"
          type="button">Delete</button>
      `);
    }

    return `
      <tr>
        <td>
          <div class="doc-cell">
            <span class="doc-icon">
              ${escapeHTML(fileType(document.name))}
            </span>

            <span>
              <span class="doc-name">
                ${escapeHTML(document.name)}
              </span>

              <small class="doc-id">
                ID ${escapeHTML(document.id)}
              </small>
            </span>
          </div>
        </td>

        <td>
          <span class="category-tag">
            ${escapeHTML(document.category || 'Uncategorized')}
          </span>
        </td>

        <td>
          ${
            isOwner
              ? '<span class="owner-tag">You</span>'
              : escapeHTML(
                  document.owner_name || `#${document.owner_id}`
                )
          }
        </td>

        <td>${escapeHTML(formatDate(document.created_at))}</td>

        <td>
          <div class="row-actions">
            ${actions.join('')}
          </div>
        </td>
      </tr>
    `;
  }).join('');
}

// ==========================================
// LOAD AND SEARCH DOCUMENTS
// ==========================================

async function loadDocuments() {
  const loading = document.querySelector('#documents-loading');
  const empty = document.querySelector('#documents-empty');

  loading.hidden = false;
  empty.hidden = true;

  try {
    const parameters = new URLSearchParams({
      name: document.querySelector('#search-name').value.trim(),
      category: document.querySelector('#search-category').value.trim(),
      owner: document.querySelector('#search-owner').value.trim(),
    });

    const dateFrom =
      document.querySelector('#search-date-from').value;

    const dateTo =
      document.querySelector('#search-date-to').value;

    if (dateFrom) {
      parameters.set('date_from', dateFrom);
    }

    if (dateTo) {
      parameters.set('date_to', dateTo);
    }

    const result = await api(
      `/documents/search?${parameters}`
    );

    renderDocuments(result.documents);

    document.querySelector('#last-updated').textContent =
      `Updated ${new Intl.DateTimeFormat(undefined, {
        hour: 'numeric',
        minute: '2-digit',
      }).format(new Date())}`;

  } catch (error) {
    if (
      error.message.toLowerCase().includes('authentication') ||
      error.message.toLowerCase().includes('token')
    ) {
      leaveWorkspace();
    } else {
      showToast(error.message, true);
    }

  } finally {
    loading.hidden = true;
  }
}

function debounceSearch() {
  clearTimeout(state.searchTimer);

  state.searchTimer = setTimeout(
    loadDocuments,
    220
  );
}

document.querySelector('#search-name').addEventListener(
  'input',
  debounceSearch
);

document.querySelector('#search-category').addEventListener(
  'input',
  debounceSearch
);

document.querySelector('#search-owner').addEventListener(
  'input',
  debounceSearch
);

document.querySelector('#search-date-from').addEventListener(
  'change',
  loadDocuments
);

document.querySelector('#search-date-to').addEventListener(
  'change',
  loadDocuments
);

document.querySelector('#refresh-documents').addEventListener(
  'click',
  loadDocuments
);

document.querySelector('#empty-upload').addEventListener(
  'click',
  () => openDialog('upload')
);

document.querySelector('#upload-open').addEventListener(
  'click',
  () => openDialog('upload')
);

// ==========================================
// NAVIGATION
// ==========================================

appScreen.addEventListener(
  'click',
  (event) => {
    const button = event.target.closest('[data-view]');

    if (!button) return;

    const view = button.dataset.view;

    if (
      (view === 'overview' || view === 'audit' || view === 'users') &&
      !isAdmin()
    ) {
      return;
    }

    document.querySelectorAll('.nav-link').forEach((link) => {
      link.classList.toggle('is-active', link.dataset.view === view);
    });
    appScreen.classList.toggle('is-admin-overview', view === 'overview');

    document.querySelector('#admin-overview-view').hidden =
      view !== 'overview';

    document.querySelector('#documents-view').hidden =
      view !== 'documents';

    document.querySelector('#audit-view').hidden =
      view !== 'audit';

    document.querySelector('#users-view').hidden =
      view !== 'users';

    document.querySelector('#profile-view').hidden =
      view !== 'profile';
    document.querySelector('.search-box').hidden =
      view !== 'documents';

    document.querySelector('#topbar-title').textContent =
      view === 'overview'
        ? 'Dashboard'
        : view === 'audit'
          ? 'Audit Logs'
          : view === 'users'
            ? 'User Management'
            : view === 'profile'
              ? 'Profile'
              : 'Documents';

    if (view === 'overview') loadAdminOverview();
    if (view === 'documents') loadDocuments();
    if (view === 'audit') loadAuditLogs();
    if (view === 'users') loadUsers();
  }
);

// ==========================================
// DOCUMENT ACTIONS
// ==========================================

document.querySelector('#document-rows').addEventListener(
  'click',
  async (event) => {
    const button = event.target.closest('[data-action]');

    if (!button) return;

    const documentId = Number(button.dataset.id);

    const item = state.documents.find(
      (document) => document.id === documentId
    );

    if (!item) return;

    try {
      if (button.dataset.action === 'download') {
        await downloadDocument(item);
      }

      if (button.dataset.action === 'edit') {
        openDialog('edit', item);
      }

      if (button.dataset.action === 'share') {
        openDialog('share', item);
      }

      if (button.dataset.action === 'replace') {
        openDialog('replace', item);
      }

      if (button.dataset.action === 'delete') {
        await deleteDocument(item);
      }

    } catch (error) {
      showToast(error.message, true);
    }
  }
);

async function downloadDocument(item) {
  const response = await fetch(
    `/documents/${item.id}/download`,
    {
      headers: {
        Authorization: `Bearer ${state.token}`,
      },
    }
  );

  if (!response.ok) {
    let message = `Download failed (${response.status})`;

    try {
      message = (await response.json()).detail || message;
    } catch {
      // Keep default message.
    }

    throw new Error(message);
  }

  const blob = await response.blob();
  const url = URL.createObjectURL(blob);

  const anchor = Object.assign(
    document.createElement('a'),
    {
      href: url,
      download: item.name,
    }
  );

  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();

  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

async function deleteDocument(item) {
  const confirmed = window.confirm(
    `Delete “${item.name}” from the vault? This cannot be undone.`
  );

  if (!confirmed) return;

  await api(`/documents/${item.id}`, {
    method: 'DELETE',
  });

  showToast('Document deleted.');

  await loadDocuments();
}

// ==========================================
// DIALOGS
// ==========================================

async function openDialog(kind, item = null) {
  let existingPermissions = '';

  if (kind === 'share') {
    try {
      const result = await api(
        `/documents/${item.id}/permissions`
      );

      existingPermissions = result.permissions.length
        ? result.permissions.map((permission) => `
            <div class="permission-row">
              <span>
                <b>${escapeHTML(permission.full_name)}</b>
                <small>${escapeHTML(permission.email)}</small>
              </span>

              <span class="permission-level">
                ${escapeHTML(permission.access_type)}
              </span>

              <button
                class="row-action danger"
                data-revoke-user="${permission.user_id}"
                data-document-id="${item.id}"
                type="button">
                Revoke
              </button>
            </div>
          `).join('')
        : '<p class="permission-empty">No one else has access yet.</p>';

    } catch (error) {
      showToast(error.message, true);
      return;
    }
  }

  const templates = {
    upload: {
      eyebrow: 'ADD TO YOUR VAULT',
      title: 'Upload document',

      content: `
        <form id="dialog-form">
          <label class="field">
            <span>Category</span>
            <input
              name="category"
              required
              maxlength="100"
              placeholder="e.g. Contracts">
          </label>

          <label class="field">
            <span>Choose a file</span>
            <input
              name="file"
              type="file"
              accept=".pdf,.doc,.docx,.txt,.png,.jpg,.jpeg"
              required>
          </label>

          <p class="dialog-help">
            PDF, Word, text, and image files up to 5 MB.
          </p>

          <div class="dialog-actions">
            <button class="button button-outline"
              data-cancel type="button">Cancel</button>

            <button class="button button-primary"
              type="submit">Upload file</button>
          </div>
        </form>
      `,
    },

    edit: {
      eyebrow: `DOCUMENT #${item?.id ?? ''}`,
      title: 'Edit details',

      content: `
        <form id="dialog-form">
          <label class="field">
            <span>Document name</span>
            <input
              name="new_name"
              required
              maxlength="255"
              value="${escapeHTML(item?.name || '')}">
          </label>

          <label class="field">
            <span>Category</span>
            <input
              name="new_category"
              maxlength="100"
              value="${escapeHTML(item?.category || '')}">
          </label>

          <div class="dialog-actions">
            <button class="button button-outline"
              data-cancel type="button">Cancel</button>

            <button class="button button-primary"
              type="submit">Save changes</button>
          </div>
        </form>
      `,
    },

    share: {
      eyebrow: `DOCUMENT #${item?.id ?? ''}`,
      title: 'Grant access',

      content: `
        <p class="dialog-help">
          Share <b>${escapeHTML(item?.name || '')}</b>
          with an active TrustVault account.
          Access takes effect immediately.
        </p>

        <form id="dialog-form">
          <label class="field">
            <span>Person's email</span>
            <input
              name="user_email"
              type="email"
              required
              placeholder="name@company.com">
          </label>

          <label class="field">
            <span>Permission</span>
            <select name="access_type">
              <option value="READ">Read</option>
              <option value="EDIT">Edit</option>
            </select>
          </label>

          <div class="dialog-actions">
            <button class="button button-outline"
              data-cancel type="button">Cancel</button>

            <button class="button button-primary"
              type="submit">Grant access</button>
          </div>
        </form>

        <div class="permission-list">
          <h3>Current access</h3>
          ${existingPermissions}
        </div>
      `,
    },

    replace: {
      eyebrow: `DOCUMENT #${item?.id ?? ''}`,
      title: 'Replace file',

      content: `
        <p class="dialog-help">
          The existing file will be replaced.
          The document's access grants stay the same.
        </p>

        <form id="dialog-form">
          <label class="field">
            <span>New file</span>
            <input
              name="file"
              type="file"
              accept=".pdf,.doc,.docx,.txt,.png,.jpg,.jpeg"
              required>
          </label>

          <p class="dialog-help">
            PDF, Word, text, and image files up to 5 MB.
          </p>

          <div class="dialog-actions">
            <button class="button button-outline"
              data-cancel type="button">Cancel</button>

            <button class="button button-primary"
              type="submit">Replace file</button>
          </div>
        </form>
      `,
    },
  };

  const template = templates[kind];

  if (!template) {
    showToast('Invalid dialog type.', true);
    return;
  }

  document.querySelector('#dialog-eyebrow').textContent =
    template.eyebrow;

  document.querySelector('#dialog-title').textContent =
    template.title;

  dialogContent.innerHTML = template.content;

  dialogBackdrop.hidden = false;

  dialogContent.querySelector('[data-cancel]')
    ?.addEventListener('click', closeDialog);

  dialogContent.querySelector('form')
    .addEventListener('submit', (event) => {
      submitDialog(event, kind, item);
    });

  dialogContent.querySelectorAll('[data-revoke-user]')
    .forEach((button) => {
      button.addEventListener('click', async () => {
        try {
          await api(
            `/documents/${button.dataset.documentId}/permissions/${button.dataset.revokeUser}`,
            {
              method: 'DELETE',
            }
          );

          showToast('Access revoked.');

          await openDialog('share', item);

        } catch (error) {
          showToast(error.message, true);
        }
      });
    });

  dialogContent.querySelector('input')?.focus();
}

// ==========================================
// FORM SUBMISSION
// ==========================================

async function submitDialog(event, kind, item) {
  event.preventDefault();

  const form = event.currentTarget;
  const submit = form.querySelector('[type="submit"]');

  submit.disabled = true;

  try {
    if (kind === 'upload') {
      const body = new FormData(form);

      await api('/documents/upload', {
        method: 'POST',
        body,
      });

      showToast('Document uploaded.');

    } else if (kind === 'edit') {
      await api(`/documents/${item.id}`, {
        method: 'PUT',
        body: new FormData(form),
      });

      showToast('Document details updated.');

    } else if (kind === 'replace') {
      await api(`/documents/${item.id}/file`, {
        method: 'PUT',
        body: new FormData(form),
      });

      showToast('Document file replaced.');

    } else if (kind === 'share') {
      const formData = new FormData(form);

      await api(`/documents/${item.id}/permissions`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          user_email: formData.get('user_email'),
          access_type: formData.get('access_type'),
        }),
      });

      showToast('Access granted.');
    }

    closeDialog();

    await loadDocuments();

  } catch (error) {
    showToast(error.message, true);

  } finally {
    submit.disabled = false;
  }
}

function closeDialog() {
  dialogBackdrop.hidden = true;
  dialogContent.replaceChildren();
}

document.querySelector('#dialog-close')
  .addEventListener('click', closeDialog);

dialogBackdrop.addEventListener('click', (event) => {
  if (event.target === dialogBackdrop) {
    closeDialog();
  }
});

document.addEventListener('keydown', (event) => {
  if (event.key === 'Escape' && !dialogBackdrop.hidden) {
    closeDialog();
  }

  if (
    event.key === '/' &&
    !appScreen.hidden &&
    !/input|textarea/i.test(document.activeElement.tagName)
  ) {
    event.preventDefault();
    document.querySelector('#search-name').focus();
  }
});

// ==========================================
// ADMIN OVERVIEW
// ==========================================

async function loadAdminOverview() {
  const loading = document.querySelector('#admin-overview-loading');
  const empty = document.querySelector('#overview-audit-empty');
  const errorState = document.querySelector('#admin-overview-error');
  const rows = document.querySelector('#overview-audit-rows');

  if (!isAdmin()) return;

  loading.hidden = false;
  empty.hidden = true;
  errorState.hidden = true;
  rows.replaceChildren();

  try {
    const result = await api('/admin/dashboard');

    if (!result.stats || !Array.isArray(result.recent_activity)) {
      throw new Error('The admin overview response was invalid.');
    }

    const values = {
      'overview-total-users': result.stats.total_users,
      'overview-active-users': result.stats.active_users,
      'overview-inactive-users': result.stats.inactive_users,
      'overview-owners': result.stats.owners,
      'overview-viewers': result.stats.viewers,
      'overview-admins': result.stats.admins,
    };

    for (const [id, value] of Object.entries(values)) {
      document.querySelector(`#${id}`).textContent = String(value);
    }

    rows.innerHTML = result.recent_activity.map((activity) => `
      <tr>
        <td>
          <span class="event-name">${escapeHTML(activity.action)}</span>
          <small class="event-detail">${escapeHTML(activity.details || '')}</small>
        </td>
        <td>
          ${escapeHTML(activity.user_name || 'Unknown')}
          <small class="event-detail">${escapeHTML(activity.user_email || '')}</small>
        </td>
        <td>${activity.document_id == null ? '—' : `#${escapeHTML(activity.document_id)}`}</td>
        <td>${escapeHTML(formatTimestamp(activity.created_at))}</td>
      </tr>
    `).join('');

    empty.hidden = result.recent_activity.length > 0;
  } catch (error) {
    errorState.textContent =
      `Unable to load the admin overview: ${error.message}`;
    errorState.hidden = false;
    showToast(error.message, true);
  } finally {
    loading.hidden = true;
  }
}

document.querySelector('#refresh-admin-overview')
  .addEventListener('click', loadAdminOverview);

// ==========================================
// ADMIN AUDIT LOGS
// ==========================================

async function loadAuditLogs() {
  const loading = document.querySelector('#audit-loading');
  const empty = document.querySelector('#audit-empty');
  const errorState = document.querySelector('#audit-error');

  loading.hidden = false;
  empty.hidden = true;
  errorState.hidden = true;

  try {
    if (!isAdmin()) {
      throw new Error('Administrator access is required to view audit logs.');
    }

    const result = await api('/admin/audit-logs');
    if (!Array.isArray(result.audit_logs)) {
      throw new Error('The audit log response was invalid.');
    }

    document.querySelector('#audit-total').textContent =
      result.total_logs;

    empty.hidden = result.audit_logs.length > 0;

    document.querySelector('#audit-rows').innerHTML =
      result.audit_logs.map((log) => `
        <tr>
          <td>
            <span class="event-name">
              ${escapeHTML(log.action)}
            </span>

            <small class="event-detail">
              ${escapeHTML(log.details || '')}
            </small>
          </td>

          <td>
            ${escapeHTML(log.user_name || 'Unknown')}

            <small class="event-detail">
              ${escapeHTML(log.user_email || '')}
            </small>
          </td>

          <td>
            ${
              log.document_id == null
                ? '—'
                : `#${escapeHTML(log.document_id)}`
            }
          </td>

          <td>
            <span class="result-pill ${
              log.success ? 'success' : 'failed'
            }">
              ${log.success ? 'SUCCESS' : 'FAILED'}
            </span>
          </td>

          <td>
            ${escapeHTML(formatTimestamp(log.created_at))}
          </td>
        </tr>
      `).join('');

  } catch (error) {
    document.querySelector('#audit-rows').replaceChildren();
    errorState.textContent = `Unable to load audit logs: ${error.message}`;
    errorState.hidden = false;
    showToast(error.message, true);

  } finally {
    loading.hidden = true;
  }
}

document.querySelector('#refresh-audit')
  .addEventListener('click', loadAuditLogs);

// ==========================================
// ADMIN USER MANAGEMENT
// ==========================================

async function loadUsers() {
  const loading = document.querySelector('#users-loading');
  const empty = document.querySelector('#users-empty');
  const errorState = document.querySelector('#users-error');

  loading.hidden = false;
  empty.hidden = true;
  errorState.hidden = true;

  try {
    if (!isAdmin()) {
      throw new Error('Administrator access is required to manage users.');
    }

    const result = await api('/admin/users');
    if (!Array.isArray(result.users)) {
      throw new Error('The user list response was invalid.');
    }

    empty.hidden = result.users.length > 0;

    document.querySelector('#user-rows').innerHTML =
      result.users.map((user) => `
        <tr>
          <td>
            #${escapeHTML(user.id)}
          </td>

          <td>
            <span class="event-name">
              ${escapeHTML(user.full_name)}
            </span>

            <small class="event-detail">
              ${escapeHTML(user.email)}
            </small>
          </td>

          <td>
            <span class="role-tag">
              ${escapeHTML(user.role)}
            </span>
          </td>

          <td>
            <span class="account-status ${
              user.is_active ? 'active' : 'inactive'
            }">
              ${user.is_active ? 'ACTIVE' : 'INACTIVE'}
            </span>
          </td>

          <td>
            ${escapeHTML(formatDate(user.created_at))}
          </td>

          <td>
            ${
              user.id === state.user.id
                ? '<span class="event-detail">Current account</span>'
                : `
                  <button
                    class="row-action ${user.is_active ? 'danger' : ''}"
                    data-user-status="${user.id}"
                    data-active="${!user.is_active}"
                    type="button">
                    ${user.is_active ? 'Deactivate' : 'Activate'}
                  </button>
                `
            }
          </td>
        </tr>
      `).join('');

  } catch (error) {
    document.querySelector('#user-rows').replaceChildren();
    errorState.textContent = `Unable to load users: ${error.message}`;
    errorState.hidden = false;
    showToast(error.message, true);

  } finally {
    loading.hidden = true;
  }
}

document.querySelector('#refresh-users')
  .addEventListener('click', loadUsers);

document.querySelector('#user-rows')
  .addEventListener('click', async (event) => {
    if (!isAdmin()) return;

    const button = event.target.closest('[data-user-status]');

    if (!button) return;

    const isActive = button.dataset.active === 'true';

    const confirmed = window.confirm(
      `${isActive ? 'Reactivate' : 'Deactivate'} this account?` +
      `${isActive ? '' : ' Existing sessions will stop working immediately.'}`
    );

    if (!confirmed) return;

    try {
      await api(
        `/admin/users/${button.dataset.userStatus}/status`,
        {
          method: 'PATCH',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            is_active: isActive,
          }),
        }
      );

      showToast(
        isActive
          ? 'Account reactivated.'
          : 'Account deactivated.'
      );

      await loadUsers();

    } catch (error) {
      showToast(error.message, true);
    }
  });

// ==========================================
// APPLICATION STARTUP
// ==========================================

if (state.token) {
  enterWorkspace().catch(() => leaveWorkspace());
}
