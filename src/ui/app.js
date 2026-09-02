



let switches = [];
let auditLogs = [];
let eventSource = null;


document.addEventListener('DOMContentLoaded', () => {
  initTabs();
  initSse();
  fetchSwitches();
  fetchAuditLogs();
  startCountdownTicker();
  setupShamirHandlers();
  setupTokenGenerator();
});


function initTabs() {
  const tabBtns = document.querySelectorAll('.tab-btn');
  tabBtns.forEach((btn) => {
    btn.addEventListener('click', () => {
      tabBtns.forEach((b) => b.classList.remove('active'));
      document.querySelectorAll('.tab-pane').forEach((p) => p.classList.remove('active'));

      btn.classList.add('active');
      const targetId = btn.getAttribute('data-tab');
      const targetPane = document.getElementById(targetId);
      if (targetPane) targetPane.classList.add('active');
    });
  });
}


function initSse() {
  const statusBadge = document.getElementById('sse-status');
  
  if (eventSource) {
    eventSource.close();
  }

  eventSource = new EventSource('/events');

  eventSource.onopen = () => {
    if (statusBadge) {
      statusBadge.innerHTML = '<span class="pulsing-dot"></span> Real-Time Connected';
    }
  };

  eventSource.onmessage = (event) => {
    try {
      const payload = JSON.parse(event.data);
      handleSseEvent(payload);
    } catch {}
  };

  eventSource.onerror = () => {
    if (statusBadge) {
      statusBadge.innerHTML = '<span style="width:8px;height:8px;border-radius:50%;background:#f43f5e;display:inline-block;"></span> Reconnecting...';
    }
    setTimeout(initSse, 5000);
  };
}


function handleSseEvent(payload) {
  if (payload.type === 'tick' && payload.data?.states) {
    switches = payload.data.states;
    renderSwitches();
    updateStatSummary();
  } else if (payload.type === 'switch:checkin') {
    showToast(`✓ Check-in received for switch [${payload.data.switchId}]`, 'success');
    fetchSwitches();
  } else if (payload.type === 'switch:triggered') {
    showToast(`🚨 Dead man switch [${payload.data.switchId}] TRIGGERED!`, 'danger');
    fetchSwitches();
    fetchAuditLogs();
  } else if (payload.type === 'switch:duress') {
    showToast(`⚠️ DURESS check-in received for [${payload.data.switchId}]!`, 'danger');
    fetchSwitches();
    fetchAuditLogs();
  }
}


async function fetchSwitches() {
  try {
    const res = await fetch('/api/v1/switches');
    const data = await res.json();
    if (data.switches) {
      switches = data.switches;
      renderSwitches();
      updateStatSummary();
    }
  } catch {}
}


async function fetchAuditLogs() {
  try {
    const res = await fetch('/api/v1/audit?limit=50');
    const data = await res.json();
    if (data.logs) {
      auditLogs = data.logs;
      renderAuditLogs();
    }
  } catch {}
}


function updateStatSummary() {
  const totalEl = document.getElementById('stat-total-switches');
  const armedEl = document.getElementById('stat-armed-switches');
  const nextEl = document.getElementById('stat-next-deadline');

  if (totalEl) totalEl.textContent = switches.length.toString();
  if (armedEl) {
    const armedCount = switches.filter((s) => s.status === 'ARMED').length;
    armedEl.textContent = armedCount.toString();
  }

  if (nextEl && switches.length > 0) {
    const activeSwitches = switches.filter((s) => s.status === 'ARMED' || s.status === 'GRACE_PERIOD');
    if (activeSwitches.length > 0) {
      const earliest = activeSwitches.reduce((min, s) => (s.nextDeadlineAt < min.nextDeadlineAt ? s : min));
      const remMs = Math.max(0, earliest.nextDeadlineAt - Date.now());
      nextEl.textContent = formatMsToTimer(remMs);
    } else {
      nextEl.textContent = 'None Active';
    }
  }
}


function startCountdownTicker() {
  setInterval(() => {
    switches.forEach((sw) => {
      const remMs = Math.max(0, sw.nextDeadlineAt - Date.now());
      const timerEl = document.getElementById(`timer-${sw.id}`);
      if (timerEl) {
        timerEl.textContent = formatMsToTimer(remMs);
      }
    });
    updateStatSummary();
  }, 1000);
}


function formatMsToTimer(ms) {
  if (ms <= 0) return '00:00:00 (EXPIRED)';
  const totalSeconds = Math.floor(ms / 1000);
  const days = Math.floor(totalSeconds / 86400);
  const hours = Math.floor((totalSeconds % 86400) / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  const seconds = totalSeconds % 60;

  const pad = (n) => n.toString().padStart(2, '0');

  if (days > 0) {
    return `${days}d ${pad(hours)}h ${pad(minutes)}m ${pad(seconds)}s`;
  }
  return `${pad(hours)}:${pad(minutes)}:${pad(seconds)}`;
}


function renderSwitches() {
  const container = document.getElementById('switch-grid-container');
  if (!container) return;

  if (switches.length === 0) {
    container.innerHTML = `
      <div style="grid-column: 1 / -1; text-align: center; padding: 40px; color: var(--text-muted); background: var(--bg-card); border-radius: var(--radius-lg); border: 1px solid var(--border-color);">
        <h3>No dead man switches configured yet.</h3>
        <p style="margin-top: 8px;">Add switches in your configuration file or use <code>obold init</code> to get started.</p>
      </div>
    `;
    return;
  }

  container.innerHTML = switches
    .map((sw) => {
      const isArmed = sw.status === 'ARMED';
      const isTriggered = sw.status === 'TRIGGERED';
      const isGrace = sw.status === 'GRACE_PERIOD';

      const statusBadge = isArmed
        ? '<span class="badge-armed">✓ ARMED</span>'
        : isTriggered
        ? '<span class="badge-triggered">🚨 TRIGGERED</span>'
        : isGrace
        ? '<span class="badge-grace">⚠️ GRACE PERIOD</span>'
        : `<span class="badge-armed" style="background:rgba(255,255,255,0.1);color:#94a3b8;">${sw.status}</span>`;

      const remMs = Math.max(0, sw.nextDeadlineAt - Date.now());
      const deadlineStr = new Date(sw.nextDeadlineAt).toLocaleString();

      return `
        <div class="switch-card" id="card-${sw.id}">
          <div class="switch-card-header">
            <div>
              <div class="switch-name">${escapeHtml(sw.name)}</div>
              <div class="switch-id">${escapeHtml(sw.id)}</div>
            </div>
            <div>${statusBadge}</div>
          </div>

          <div class="countdown-box">
            <div class="countdown-timer" id="timer-${sw.id}">${formatMsToTimer(remMs)}</div>
            <div class="countdown-subtext">Deadline: ${deadlineStr}</div>
          </div>

          <div class="action-row">
            <button class="btn btn-primary" onclick="performCheckin('${sw.id}')">
              ⚡ Check In Now
            </button>
            <button class="btn btn-secondary" onclick="generateTokenForSwitch('${sw.id}')">
              🔑 1-Click Link
            </button>
            <button class="btn btn-secondary" onclick="simulateTrigger('${sw.id}')">
              🧪 Dry-Run
            </button>
            <button class="btn btn-danger" onclick="performDuressCheckin('${sw.id}')">
              ⚠️ Duress
            </button>
          </div>
        </div>
      `;
    })
    .join('');
}


function renderAuditLogs() {
  const tbody = document.getElementById('audit-table-body');
  if (!tbody) return;

  if (auditLogs.length === 0) {
    tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:var(--text-muted);">No audit entries recorded yet.</td></tr>';
    return;
  }

  tbody.innerHTML = auditLogs
    .map((log) => {
      const timeStr = new Date(log.created_at).toLocaleTimeString();
      const levelClass =
        log.level === 'FATAL' || log.level === 'ERROR'
          ? 'badge-error'
          : log.level === 'WARN'
          ? 'badge-warn'
          : 'badge-info';

      return `
        <tr>
          <td><span style="font-family:monospace;font-size:12px;">${timeStr}</span></td>
          <td><span class="log-badge ${levelClass}">${log.level}</span></td>
          <td><strong>${escapeHtml(log.category)}</strong></td>
          <td>${log.switch_id ? `<code>${escapeHtml(log.switch_id)}</code>` : '-'}</td>
          <td>${escapeHtml(log.message)}</td>
        </tr>
      `;
    })
    .join('');
}


window.performCheckin = async function (switchId) {
  try {
    const res = await fetch(`/api/v1/switches/${switchId}/checkin`, { method: 'POST' });
    const data = await res.json();
    if (data.success) {
      showToast(`✓ Check-in confirmed! Switch [${switchId}] timer extended.`, 'success');
      fetchSwitches();
      fetchAuditLogs();
    } else {
      showToast(`Check-in failed: ${data.error}`, 'danger');
    }
  } catch (err) {
    showToast(`Network error: ${err.message}`, 'danger');
  }
};


window.performDuressCheckin = async function (switchId) {
  if (!confirm(`Engage DURESS Protocol for switch [${switchId}]?\nThis will secretly dispatch emergency distress actions.`)) {
    return;
  }
  try {
    const res = await fetch(`/api/v1/switches/${switchId}/duress`, { method: 'POST' });
    const data = await res.json();
    if (data.success) {
      showToast(`⚠️ Duress Protocol Triggered silently for [${switchId}].`, 'danger');
      fetchSwitches();
      fetchAuditLogs();
    }
  } catch (err) {
    showToast(`Network error: ${err.message}`, 'danger');
  }
};


window.simulateTrigger = async function (switchId) {
  try {
    const res = await fetch(`/api/v1/switches/${switchId}/trigger?dryRun=true`, { method: 'POST' });
    const data = await res.json();
    if (data.success) {
      showToast(`🧪 Dry-Run simulation executed for [${switchId}]. Zero actual data destroyed.`, 'success');
      fetchAuditLogs();
    }
  } catch (err) {
    showToast(`Error: ${err.message}`, 'danger');
  }
};


window.generateTokenForSwitch = async function (switchId) {
  try {
    const res = await fetch('/api/v1/token/generate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ switchId, ttlMs: 86400000 * 7 }), 
    });
    const data = await res.json();
    if (data.success && data.checkinUrl) {
      navigator.clipboard.writeText(data.checkinUrl);
      showToast(`📋 1-Click Link copied to clipboard! Valid for 7 days.`, 'success');
    }
  } catch (err) {
    showToast(`Failed to generate token: ${err.message}`, 'danger');
  }
};


function setupShamirHandlers() {
  const splitBtn = document.getElementById('btn-shamir-split');
  const combineBtn = document.getElementById('btn-shamir-combine');

  if (splitBtn) {
    splitBtn.addEventListener('click', async () => {
      const secret = document.getElementById('shamir-secret-input')?.value;
      const total = parseInt(document.getElementById('shamir-total-input')?.value || '5', 10);
      const threshold = parseInt(document.getElementById('shamir-threshold-input')?.value || '3', 10);
      const resultsBox = document.getElementById('shamir-split-results');

      if (!secret) {
        showToast('Please enter a secret to split.', 'danger');
        return;
      }

      try {
        const res = await fetch('/api/v1/crypto/shamir/split', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ secret, total, threshold }),
        });
        const data = await res.json();
        if (data.success && resultsBox) {
          resultsBox.textContent = data.shares.join('\n\n');
          showToast(`✓ Generated ${total} shares (Threshold: ${threshold} required).`, 'success');
        } else if (resultsBox) {
          resultsBox.textContent = `Error: ${data.error}`;
        }
      } catch (err) {
        showToast(`Error: ${err.message}`, 'danger');
      }
    });
  }

  if (combineBtn) {
    combineBtn.addEventListener('click', async () => {
      const rawShares = document.getElementById('shamir-combine-input')?.value;
      const resultsBox = document.getElementById('shamir-combine-results');

      if (!rawShares) {
        showToast('Please paste your shares.', 'danger');
        return;
      }

      const shares = rawShares
        .split('\n')
        .map((s) => s.trim())
        .filter((s) => s.startsWith('obold-share-'));

      try {
        const res = await fetch('/api/v1/crypto/shamir/combine', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ shares }),
        });
        const data = await res.json();
        if (data.success && resultsBox) {
          resultsBox.textContent = `🔓 RECONSTRUCTED SECRET:\n\n${data.secret}`;
          showToast('✓ Secret successfully reconstructed!', 'success');
        } else if (resultsBox) {
          resultsBox.textContent = `Error: ${data.error}`;
        }
      } catch (err) {
        showToast(`Error: ${err.message}`, 'danger');
      }
    });
  }
}


function setupTokenGenerator() {
  const genBtn = document.getElementById('btn-generate-link');
  if (genBtn) {
    genBtn.addEventListener('click', async () => {
      const switchId = document.getElementById('token-switch-select')?.value;
      const ttlDays = parseInt(document.getElementById('token-ttl-input')?.value || '30', 10);
      const isDuress = document.getElementById('token-duress-checkbox')?.checked || false;
      const resultsBox = document.getElementById('token-results-box');

      if (!switchId) {
        showToast('Select a switch first.', 'danger');
        return;
      }

      try {
        const res = await fetch('/api/v1/token/generate', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ switchId, ttlMs: ttlDays * 86400000, isDuress }),
        });
        const data = await res.json();
        if (data.success && resultsBox) {
          resultsBox.textContent = data.checkinUrl;
          navigator.clipboard.writeText(data.checkinUrl);
          showToast('✓ Link generated and copied to clipboard!', 'success');
        }
      } catch (err) {
        showToast(`Error: ${err.message}`, 'danger');
      }
    });
  }
}


function showToast(message, type = 'info') {
  let container = document.getElementById('toast-container');
  if (!container) {
    container = document.createElement('div');
    container.id = 'toast-container';
    container.className = 'toast-container';
    document.body.appendChild(container);
  }

  const toast = document.createElement('div');
  toast.className = 'toast';
  if (type === 'danger') toast.style.borderColor = 'rgba(244, 63, 94, 0.4)';
  if (type === 'success') toast.style.borderColor = 'rgba(16, 185, 129, 0.4)';

  toast.textContent = message;
  container.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateY(10px)';
    toast.style.transition = '0.3s ease';
    setTimeout(() => toast.remove(), 300);
  }, 4000);
}


function escapeHtml(str) {
  if (!str) return '';
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
