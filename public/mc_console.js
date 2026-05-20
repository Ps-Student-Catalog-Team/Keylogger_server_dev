let mcRefreshTimer = null;
const COMMAND_HISTORY_KEY = 'mcCommandHistory';
const COMMAND_HISTORY_MAX = 50;
const commandHistory = [];
let historyIndex = -1;
let mcLogLines = [];
let mcConsoleFilterText = '';
let mcStatsChart = null;
const mcStatsHistory = { cpu: [], memory: [], tps: [], labels: [] };
const MC_STATS_HISTORY_MAX = 240;
const MC_STATS_CHART_RANGES = { '5m': 20, '15m': 60, '1h': 120 };
let mcStatsChartRange = '15m';

function escapeHtml(value) {
  return String(value || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function stripMcColorCodes(text) {
  return String(text || '')
    .replace(/\u001b\[[0-9;]*m/g, '')
    .replace(/§[0-9A-FK-OR]/gi, '');
}

function classifyMcLogLevel(text) {
  const upper = String(text || '').toUpperCase();
  if (upper.includes('[SEVERE]') || upper.includes('[ERROR]') || upper.includes('[STDERR]')) {
    return 'error';
  }
  if (upper.includes('[WARN]') || upper.includes('[WARNING]') || upper.includes(' WARN ')) {
    return 'warn';
  }
  if (upper.includes('[INFO]')) {
    return 'info';
  }
  return null;
}

function getMcLogStyle(level) {
  if (level === 'error') return 'color: #ef4444;';
  if (level === 'warn') return 'color: #f59e0b;';
  if (level === 'info') return 'color: #10b981;';
  return '';
}

function formatMcColorCodes(text) {
  const colorMap = {
    '0': '#000000', '1': '#0000AA', '2': '#00AA00', '3': '#00AAAA',
    '4': '#AA0000', '5': '#AA00AA', '6': '#FFAA00', '7': '#AAAAAA',
    '8': '#555555', '9': '#5555FF', 'a': '#55FF55', 'b': '#55FFFF',
    'c': '#FF5555', 'd': '#FF55FF', 'e': '#FFFF55', 'f': '#FFFFFF'
  };
  const ansiColorMap = {
    30: '#000000', 31: '#AA0000', 32: '#00AA00', 33: '#AA5500',
    34: '#0000AA', 35: '#AA00AA', 36: '#00AAAA', 37: '#AAAAAA',
    90: '#555555', 91: '#FF5555', 92: '#55FF55', 93: '#FFFF55',
    94: '#5555FF', 95: '#FF55FF', 96: '#55FFFF', 97: '#FFFFFF'
  };
  const highlightLevels = {
    '\[INFO\]': 'color: #3b82f6; font-weight: 600',
    '\[WARN\]': 'color: #f59e0b; font-weight: 600',
    '\[ERROR\]': 'color: #ef4444; font-weight: 600',
    '\[SEVERE\]': 'color: #ef4444; font-weight: 600',
    '\[DEBUG\]': 'color: #6b7280; font-weight: 600'
  };

  let html = '';
  let currentStyle = { color: null, bold: false, italic: false, underline: false };
  const openSpan = () => {
    const styles = [];
    if (currentStyle.color) styles.push(`color: ${currentStyle.color}`);
    if (currentStyle.bold) styles.push('font-weight: 700');
    if (currentStyle.italic) styles.push('font-style: italic');
    if (currentStyle.underline) styles.push('text-decoration: underline');
    return styles.length ? `<span style="${styles.join('; ')}">` : '<span>';
  };
  const segments = String(text).split(/(\u001b\[[0-9;]*m|§[0-9A-FK-OR])/gi);
  let opened = false;
  segments.forEach((segment) => {
    if (!segment) return;
    const ansiMatch = segment.match(/^\u001b\[([0-9;]*)m$/);
    if (ansiMatch) {
      if (opened) html += '</span>';
      const codes = ansiMatch[1].split(';').map(Number).filter((n) => !Number.isNaN(n));
      codes.forEach((code) => {
        if (code === 0) {
          currentStyle = { color: null, bold: false, italic: false, underline: false };
        } else if (code === 1) {
          currentStyle.bold = true;
        } else if (code === 3) {
          currentStyle.italic = true;
        } else if (code === 4) {
          currentStyle.underline = true;
        } else if (ansiColorMap[code]) {
          currentStyle.color = ansiColorMap[code];
        }
      });
      html += openSpan();
      opened = true;
      return;
    }
    if (/^§[0-9A-FK-OR]$/i.test(segment)) {
      if (opened) html += '</span>';
      const code = segment[1].toLowerCase();
      if (code === 'r') {
        currentStyle = { color: null, bold: false, italic: false, underline: false };
      } else if (colorMap[code]) {
        currentStyle.color = colorMap[code];
      } else if (code === 'l') {
        currentStyle.bold = true;
      } else if (code === 'o') {
        currentStyle.italic = true;
      } else if (code === 'n') {
        currentStyle.underline = true;
      }
      html += openSpan();
      opened = true;
      return;
    }
    if (!opened) {
      html += '<span>' + escapeHtml(segment) + '</span>';
      opened = true;
      return;
    }
    html += escapeHtml(segment);
  });
  if (opened) html += '</span>';

  Object.keys(highlightLevels).forEach((pattern) => {
    const re = new RegExp(pattern, 'g');
    html = html.replace(re, (match) => `<span style="${highlightLevels[pattern]}">${match}</span>`);
  });
  return html;
}

function formatMcLogs(logs) {
  if (!Array.isArray(logs)) return formatMcColorCodes(logs);
  return logs.map((line) => formatMcColorCodes(line)).join('<br>');
}

function persistCommandHistory() {
  try {
    window.localStorage.setItem(COMMAND_HISTORY_KEY, JSON.stringify(commandHistory.slice(-COMMAND_HISTORY_MAX)));
  } catch (e) {
    console.warn('无法保存命令历史:', e);
  }
}

function loadCommandHistory() {
  try {
    const raw = window.localStorage.getItem(COMMAND_HISTORY_KEY);
    if (!raw) return;
    const items = JSON.parse(raw);
    if (Array.isArray(items)) {
      commandHistory.length = 0;
      items.slice(-COMMAND_HISTORY_MAX).forEach((item) => {
        if (typeof item === 'string' && item.trim()) {
          commandHistory.push(item);
        }
      });
      historyIndex = commandHistory.length;
    }
  } catch (e) {
    console.warn('无法加载命令历史:', e);
  }
}

function addToCommandHistory(command) {
  if (!command) return;
  const last = commandHistory[commandHistory.length - 1];
  if (last === command) return;
  commandHistory.push(command);
  while (commandHistory.length > COMMAND_HISTORY_MAX) {
    commandHistory.shift();
  }
  historyIndex = commandHistory.length;
  persistCommandHistory();
}

let mcAutoScroll = true;

function appendMcLog(line) {
  let text = '';
  let level = null;
  if (typeof line === 'object' && line !== null) {
    text = String(line.text || '');
    level = String(line.level || classifyMcLogLevel(text)).toLowerCase();
  } else {
    text = String(line || '');
    level = classifyMcLogLevel(text);
  }
  if (!['info', 'warn', 'error'].includes(level)) return;
  mcLogLines.push({ text, level });
  if (mcLogLines.length > 1000) {
    mcLogLines.shift();
  }
  renderMcConsole();
}

  // Backups UI
  async function loadMcBackups() {
    try {
      const resp = await fetch('/api/mc/backups');
      const data = await resp.json();
      const container = document.getElementById('mcBackupsList');
      if (!container) return;
      if (!data.success) {
        container.innerHTML = `<p class="mc-player-empty">加载备份列表失败</p>`;
        return;
      }
      if (!data.backups || data.backups.length === 0) {
        container.innerHTML = `<p class="mc-player-empty">暂无备份文件</p>`;
        return;
      }
      const items = data.backups.map(b => {
        const date = new Date(b.mtime).toLocaleString();
        return `<div class="mc-player-item"><span>${b.name} <small style="color:var(--gray);">${date} · ${Math.round(b.size/1024)} KB</small></span><div style="display:flex;gap:0.5rem;"><button class="btn btn-sm btn-success" onclick="downloadMcBackup('${b.name}')"><i class="fas fa-download"></i> 下载</button><button class="btn btn-sm btn-secondary" onclick="confirmRestoreMcBackup('${b.name}')"><i class="fas fa-undo"></i> 还原</button></div></div>`;
      }).join('');
      container.innerHTML = `<div>${items}</div>`;
    } catch (e) {
      console.error('加载备份失败', e);
      const container = document.getElementById('mcBackupsList');
      if (container) container.innerHTML = `<p class="mc-player-empty">加载备份列表失败</p>`;
    }
  }

  function downloadMcBackup(name) {
    try {
      const link = document.createElement('a');
      link.href = `/api/mc/backups/${encodeURIComponent(name)}/download`;
      link.download = name;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      showToast('开始下载备份', 'success');
    } catch (e) {
      console.error('下载备份失败', e);
      showToast('下载备份失败', 'error');
    }
  }

  function confirmRestoreMcBackup(name) {
    if (typeof showConfirmModal === 'function') {
      showConfirmModal('确认还原', `确认要从备份 ${name} 还原世界吗？此操作会覆盖当前世界，并在完成后重启服务器。`, () => restoreMcBackup(name));
    } else if (window.confirm(`确认要从备份 ${name} 还原世界吗？此操作会覆盖当前世界，并在完成后重启服务器。`)) {
      restoreMcBackup(name);
    }
  }

  async function restoreMcBackup(name) {
    try {
      const resp = await fetch(`/api/mc/backups/${encodeURIComponent(name)}/restore`, { method: 'POST' });
      const data = await resp.json();
      if (data.success) {
        showToast('还原已完成，服务器已重启（如果配置）', 'success');
        setTimeout(() => { loadMcStatus(); }, 2000);
      } else {
        showToast(data.error || '还原失败', 'error');
      }
    } catch (e) {
      console.error('还原请求失败', e);
      showToast('还原请求失败', 'error');
    }
  }

  async function createMcBackup() {
    try {
      const resp = await fetch('/api/mc/backup', { method: 'POST' });
      const data = await resp.json();
      if (data.success) {
        showToast('备份已创建: ' + data.name, 'success');
        setTimeout(loadMcBackups, 800);
      } else {
        showToast(data.error || '创建备份失败', 'error');
      }
    } catch (e) {
      console.error('创建备份失败', e);
      showToast('创建备份失败', 'error');
    }
  }

function highlightConsoleLine(htmlLine, keyword) {
  if (!keyword) return htmlLine;
  const escapedKeyword = keyword.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return htmlLine.replace(new RegExp(`(${escapedKeyword})`, 'gi'), '<span style="background: rgba(245, 158, 11, 0.25); color: #fff;">$1</span>');
}

function renderMcConsole() {
    const output = document.getElementById('mcStdout');
    if (!output) return;

    // 获取过滤关键字（按日志内容过滤）
    const filter = (mcConsoleFilterText || '').trim().toLowerCase();

    // 过滤日志：如果有关键字，则匹配日志文本内容
    const lines = mcLogLines.filter((entry) => {
        if (!filter) return true;
        return entry.text.toLowerCase().includes(filter);
    });

    // 生成 HTML：级别（带颜色样式） + 日志内容
    output.innerHTML = lines.map((entry) => {
        const style = getMcLogStyle(entry.level);
        const levelText = escapeHtml(entry.level.toUpperCase());
        const contentText = escapeHtml(entry.text);
        return `<span style="${style}; font-weight: 700;">${levelText}</span> ${contentText}`;
    }).join('<br>');

    // 自动滚动到底部（如果开启）
    if (mcAutoScroll) {
        output.scrollTop = output.scrollHeight;
    }
}

function clearMcConsole() {
  mcLogLines = [];
  const output = document.getElementById('mcStdout');
  if (output) {
    output.innerHTML = '';
  }
}

function toggleMcAutoScroll() {
  mcAutoScroll = !mcAutoScroll;
  const button = document.getElementById('mcAutoScrollBtn');
  if (button) {
    button.innerHTML = `<i class="fas fa-${mcAutoScroll ? 'lock-open' : 'lock'}"></i> ${mcAutoScroll ? '自动滚动' : '锁定滚动'}`;
  }
  showToast(mcAutoScroll ? '自动滚动已启用' : '已锁定滚动', 'info');
}

function formatMcStatsTimeLabel(timestamp) {
  const date = new Date(timestamp);
  return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

function initMcStatsChart() {
  const canvas = document.getElementById('mcStatsChart');
  if (!canvas || !canvas.getContext || typeof Chart === 'undefined') return;
  if (mcStatsChart) {
    mcStatsChart.destroy();
    mcStatsChart = null;
  }
  const ctx = canvas.getContext('2d');
  const gradientCpu = ctx.createLinearGradient(0, 0, 0, canvas.height);
  gradientCpu.addColorStop(0, 'rgba(59, 130, 246, 0.28)');
  gradientCpu.addColorStop(1, 'rgba(59, 130, 246, 0.04)');
  const gradientMem = ctx.createLinearGradient(0, 0, 0, canvas.height);
  gradientMem.addColorStop(0, 'rgba(16, 185, 129, 0.24)');
  gradientMem.addColorStop(1, 'rgba(16, 185, 129, 0.04)');
  const gradientTps = ctx.createLinearGradient(0, 0, 0, canvas.height);
  gradientTps.addColorStop(0, 'rgba(245, 158, 11, 0.2)');
  gradientTps.addColorStop(1, 'rgba(245, 158, 11, 0.04)');

  mcStatsChart = new Chart(ctx, {
    type: 'line',
    data: {
      labels: [],
      datasets: [
        { label: 'CPU %', data: [], backgroundColor: gradientCpu, borderColor: '#3b82f6', fill: true, tension: 0.35, borderWidth: 2, pointRadius: 0, yAxisID: 'y' },
        { label: '内存 MB', data: [], backgroundColor: gradientMem, borderColor: '#10b981', fill: true, tension: 0.35, borderWidth: 2, pointRadius: 0, yAxisID: 'y' },
        { label: 'TPS', data: [], backgroundColor: gradientTps, borderColor: '#f59e0b', fill: true, tension: 0.35, borderWidth: 2, pointRadius: 0, yAxisID: 'y1' }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      interaction: { mode: 'index', intersect: false },
      plugins: {
        legend: { position: 'top', labels: { usePointStyle: true, pointStyle: 'circle' } },
        tooltip: {
          mode: 'index',
          intersect: false,
          callbacks: {
            label(context) {
              const value = context.parsed.y;
              if (context.dataset.yAxisID === 'y1') return `${context.dataset.label}: ${value ?? '-'} `;
              return `${context.dataset.label}: ${value ?? '-'}${context.dataset.label === 'CPU %' ? '%' : ''}`;
            }
          }
        }
      },
      scales: {
        x: {
          type: 'category',
          grid: { color: 'rgba(107, 117, 128, 0.12)' },
          ticks: { autoSkip: true, maxRotation: 0, minRotation: 0 }
        },
        y: {
          type: 'linear',
          position: 'left',
          title: { display: true, text: 'CPU (%) / 内存 (MB)' },
          beginAtZero: true,
          grid: { color: 'rgba(107, 117, 128, 0.12)' }
        },
        y1: {
          type: 'linear',
          position: 'right',
          title: { display: true, text: 'TPS' },
          beginAtZero: true,
          grid: { drawOnChartArea: false, color: 'rgba(107, 117, 128, 0.12)' },
          min: 0,
          max: 20
        }
      }
    }
  });
}

function getMcStatsDisplayCount() {
  return MC_STATS_CHART_RANGES[mcStatsChartRange] || mcStatsHistory.labels.length;
}

function updateMcStatsChart() {
  if (!mcStatsChart) initMcStatsChart();
  if (!mcStatsChart) return;
  const displayCount = getMcStatsDisplayCount();
  const labels = mcStatsHistory.labels.slice(-displayCount).map((ts) => formatMcStatsTimeLabel(ts));
  mcStatsChart.data.labels = labels;
  mcStatsChart.data.datasets[0].data = mcStatsHistory.cpu.slice(-displayCount);
  mcStatsChart.data.datasets[1].data = mcStatsHistory.memory.slice(-displayCount);
  mcStatsChart.data.datasets[2].data = mcStatsHistory.tps.slice(-displayCount);
  mcStatsChart.update('none');
}

function setMcStatsRange(range) {
  if (!MC_STATS_CHART_RANGES[range]) return;
  mcStatsChartRange = range;
  document.querySelectorAll('.mc-stats-range-btn').forEach((btn) => {
    btn.classList.toggle('active', btn.dataset.range === range);
  });
  updateMcStatsChart();
}

function toNumber(value) {
  if (typeof value === 'number') return Number.isFinite(value) ? value : null;
  const num = parseFloat(String(value || '').replace(/[^0-9.+-eE]/g, ''));
  return Number.isFinite(num) ? num : null;
}

function normalizeMemory(memo) {
  if (!memo) return { used: null, total: null };
  if (typeof memo === 'object') {
    return { used: toNumber(memo.used), total: toNumber(memo.total) };
  }
  return { used: toNumber(memo), total: null };
}

function updateMcStats(cpu, memory, tps) {
  const cpuNode = document.getElementById('mcCpu');
  const memoryNode = document.getElementById('mcMemory');
  const tpsNode = document.getElementById('mcTps');
  const cpuValue = toNumber(cpu);
  const memoryValue = normalizeMemory(memory);
  const tpsValue = toNumber(tps);

  if (cpuNode) {
    cpuNode.textContent = cpuValue != null ? `${cpuValue.toFixed(1)} %` : '-';
  }
  if (memoryNode) {
    const formatMb = (mb) => {
      if (mb == null) return '-';
      if (mb >= 1024) return `${(mb / 1024).toFixed(2)} GB`;
      return `${mb} MB`;
    };
    const usedMb = memoryValue.used != null ? Math.round(memoryValue.used / 1024 / 1024) : null;
    const totalMb = memoryValue.total != null ? Math.round(memoryValue.total / 1024 / 1024) : null;
    memoryNode.textContent = `${formatMb(usedMb)} / ${formatMb(totalMb)}`;
  }
  if (tpsNode) {
    tpsNode.textContent = tpsValue != null ? tpsValue.toFixed(2) : '-';
  }

  mcStatsHistory.cpu.push(cpuValue != null ? cpuValue : 0);
  mcStatsHistory.memory.push(memoryValue.used != null ? memoryValue.used / 1024 / 1024 : 0);
  mcStatsHistory.tps.push(tpsValue != null ? tpsValue : null);
  mcStatsHistory.labels.push(Date.now());

  while (mcStatsHistory.cpu.length > MC_STATS_HISTORY_MAX) {
    mcStatsHistory.cpu.shift();
    mcStatsHistory.memory.shift();
    mcStatsHistory.tps.shift();
    mcStatsHistory.labels.shift();
  }

  updateMcStatsChart();
}

function renderPlayerList(players, count, max) {
  const container = document.getElementById('mcPlayerList');
  const countLabel = document.getElementById('mcPlayerCount');
  const maxLabel = document.getElementById('mcPlayerMax');
  if (countLabel) {
    countLabel.textContent = `${count || (players ? players.length : 0)}`;
  }
  if (maxLabel) {
    maxLabel.textContent = `${max || '-'}`;
  }
  if (!container) return;

  if (!Array.isArray(players) || players.length === 0) {
    container.innerHTML = '<p class="mc-player-empty">暂无玩家在线</p>';
    return;
  }

  const listItems = players.map((player) => {
    const safeName = player.replace(/'/g, "\\'");
    return `<div class="mc-player-item">
              <span><i class="fas fa-user"></i> ${player}</span>
              <div style="display:flex; gap:0.5rem; flex-wrap: wrap;">
                <button class="btn btn-secondary btn-sm" title="踢出玩家 ${player}" onclick="confirmMcPlayerAction('${safeName}', 'kick')"><i class="fas fa-sign-out-alt"></i> 踢出</button>
                <button class="btn btn-danger btn-sm" title="封禁玩家 ${player}" onclick="confirmMcPlayerAction('${safeName}', 'ban')"><i class="fas fa-ban"></i> 封禁</button>
                <button class="btn btn-success btn-sm" title="授予 OP ${player}" onclick="confirmMcPlayerAction('${safeName}', 'op')"><i class="fas fa-user-shield"></i> OP</button>
                <button class="btn btn-secondary btn-sm" title="撤销 OP ${player}" onclick="confirmMcPlayerAction('${safeName}', 'deop')"><i class="fas fa-user-minus"></i> DEOP</button>
              </div>
            </div>`;
  });

  container.innerHTML = `<div>${listItems.join('')}</div>`;
}

function confirmMcPlayerAction(player, action) {
  let actionLabel = '操作';
  let command = '';
  if (action === 'ban') {
    actionLabel = '封禁';
    command = `ban ${player}`;
  } else if (action === 'kick') {
    actionLabel = '踢出';
    command = `kick ${player}`;
  } else if (action === 'op') {
    actionLabel = '授予 OP';
    command = `op ${player}`;
  } else if (action === 'deop') {
    actionLabel = '撤销 OP';
    command = `deop ${player}`;
  }
  if (!command) return;
  const message = `确定要${actionLabel} 玩家 ${player} 吗？`;
  if (typeof showConfirmModal === 'function') {
    showConfirmModal(`确认${actionLabel}`, message, () => sendMcCommand(command));
  } else if (window.confirm(message)) {
    sendMcCommand(command);
  }
}

async function refreshMcPlayerList() {
  try {
    const response = await fetch('/api/mc/players/refresh', { method: 'POST' });
    const data = await response.json();
    if (data.success) {
      showToast(data.message || '玩家列表刷新中，请稍候', 'success');
      if (Array.isArray(data.players)) {
        renderPlayerList(data.players, data.count || 0, data.max || 0);
      } else {
        setTimeout(loadMcPlayers, 1500);
      }
    } else {
      showToast(data.error || '刷新失败', 'error');
    }
  } catch (error) {
    console.error('刷新玩家列表失败:', error);
    showToast('刷新玩家列表失败', 'error');
  }
}

function downloadMcLog() {
  try {
    const link = document.createElement('a');
    link.href = '/api/mc/logs/download';
    link.download = 'mc_latest.log';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    showToast('MC 日志下载已开始', 'success');
  } catch (error) {
    console.error('下载 MC 日志失败:', error);
    showToast('下载 MC 日志失败', 'error');
  }
}

async function loadMcConfig() {
  try {
    const response = await fetch('/api/mc/config');
    const data = await response.json();
    if (!data.success) {
      showToast(data.message || '获取 MC 配置失败', 'error');
      return;
    }
    document.getElementById('mcConfigCommand').value = data.config.fullCommand || '';
    document.getElementById('mcConfigDir').value = data.config.workingDir || '';
    const autoRestartCheckbox = document.getElementById('mcAutoRestartInput');
    if (autoRestartCheckbox) autoRestartCheckbox.checked = !!data.config.autoRestart;
    const delay = document.getElementById('mcAutoRestartDelay');
    if (delay && typeof data.config.autoRestartDelaySeconds === 'number') delay.value = data.config.autoRestartDelaySeconds;
    const maxRetries = document.getElementById('mcAutoRestartMaxRetries');
    if (maxRetries && typeof data.config.autoRestartMaxRetries === 'number') maxRetries.value = data.config.autoRestartMaxRetries;
    const backupDirInput = document.getElementById('mcBackupDir');
    if (backupDirInput && typeof data.config.backupDir === 'string') backupDirInput.value = data.config.backupDir || '';
    const autoBackupCheckbox = document.getElementById('mcAutoBackupEnable');
    if (autoBackupCheckbox) autoBackupCheckbox.checked = !!data.config.autoBackupEnabled;
    const autoBackupCron = document.getElementById('mcAutoBackupCron');
    if (autoBackupCron && typeof data.config.autoBackupCron === 'string') autoBackupCron.value = data.config.autoBackupCron || '';
    const retentionCount = document.getElementById('mcBackupRetentionCount');
    if (retentionCount && typeof data.config.backupRetentionCount === 'number') retentionCount.value = data.config.backupRetentionCount;
    const retentionDays = document.getElementById('mcBackupRetentionDays');
    if (retentionDays && typeof data.config.backupRetentionDays === 'number') retentionDays.value = data.config.backupRetentionDays;
    const playerInt = document.getElementById('mcPlayerListInterval');
    if (playerInt && typeof data.config.playerListIntervalSeconds === 'number') playerInt.value = data.config.playerListIntervalSeconds;
    updateMcAutoRestartDisplay(!!data.config.autoRestart);
  } catch (error) {
    console.error('加载 MC 配置失败:', error);
    showToast('加载 MC 配置失败', 'error');
  }
}

async function saveMcConfig() {
  const fullCommand = document.getElementById('mcConfigCommand')?.value.trim();
  const workingDir = document.getElementById('mcConfigDir')?.value.trim();
  const autoRestart = !!document.getElementById('mcAutoRestartInput')?.checked;
  const autoRestartDelaySeconds = parseInt(document.getElementById('mcAutoRestartDelay')?.value || '0', 10) || undefined;
  const autoRestartMaxRetries = parseInt(document.getElementById('mcAutoRestartMaxRetries')?.value || '0', 10) || undefined;
  const backupDir = document.getElementById('mcBackupDir')?.value.trim();
  const autoBackupEnabled = !!document.getElementById('mcAutoBackupEnable')?.checked;
  const autoBackupCron = document.getElementById('mcAutoBackupCron')?.value.trim();
  const backupRetentionCount = parseInt(document.getElementById('mcBackupRetentionCount')?.value || '0', 10) || undefined;
  const backupRetentionDays = parseInt(document.getElementById('mcBackupRetentionDays')?.value || '0', 10) || undefined;
  const playerListIntervalSeconds = parseInt(document.getElementById('mcPlayerListInterval')?.value || '0', 10) || undefined;
  try {
    const response = await fetch('/api/mc/config', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ fullCommand, workingDir, backupDir, autoBackupEnabled, autoBackupCron, backupRetentionCount, backupRetentionDays, autoRestart, autoRestartDelaySeconds, autoRestartMaxRetries, playerListIntervalSeconds }),
    });
    const data = await response.json();
    if (data.success) {
      showToast('MC 配置已保存', 'success');
      updateMcAutoRestartDisplay(autoRestart);
    } else {
      showToast(data.error || data.message || '保存 MC 配置失败', 'error');
    }
  } catch (error) {
    console.error('保存 MC 配置失败:', error);
    showToast('保存 MC 配置失败', 'error');
  }
}

async function loadMcStatus() {
  try {
    const response = await fetch('/api/mc/status');
    const data = await response.json();
    if (data.running) {
      document.getElementById('mcStatus').textContent = '运行中';
      document.getElementById('mcPid').textContent = data.pid || '-';
    } else {
      document.getElementById('mcStatus').textContent = '未运行';
      document.getElementById('mcPid').textContent = '-';
    }
  } catch (error) {
    console.error('加载 MC 状态失败:', error);
    document.getElementById('mcStatus').textContent = '未知';
    document.getElementById('mcPid').textContent = '-';
  }
}

async function loadMcLogs() {
  try {
    const response = await fetch('/api/mc/logs');
    const data = await response.json();
    if (!data.success) {
      showToast(data.message || '获取 MC 日志失败', 'error');
      return;
    }
    mcLogLines = [];
    if (Array.isArray(data.logs)) {
      data.logs.slice(-1000).forEach((item) => {
        const text = String(item || '');
        const level = classifyMcLogLevel(text);
        if (['info', 'warn', 'error'].includes(level)) {
          mcLogLines.push({ text, level });
        }
      });
    }
    renderMcConsole();
  } catch (error) {
    console.error('获取 MC 日志失败:', error);
  }
}

function updateMcAutoRestartDisplay(enabled) {
  const node = document.getElementById('mcAutoRestart');
  if (node) {
    node.textContent = enabled ? '已启用' : '已禁用';
  }
}

async function loadMcPlayers() {
  try {
    const response = await fetch('/api/mc/players');
    const data = await response.json();
    if (data.success) {
      renderPlayerList(data.players || [], data.count || 0, data.max || 0);
      window.mcPlayersLastUpdate = Date.now();
    }
  } catch (error) {
    console.error('加载 MC 玩家列表失败:', error);
  }
}

async function startMinecraftServer() {
  try {
    const response = await fetch('/api/mc/start', { method: 'POST' });
    const data = await response.json();
    if (data.success) {
      showToast('Minecraft 服务器启动中', 'success');
      await loadMcStatus();
      loadMcLogs();
      loadMcPlayers();
    } else {
      showToast('启动失败', 'error');
    }
  } catch (error) {
    console.error('启动 MC 失败:', error);
    showToast('启动失败', 'error');
  }
}

async function stopMinecraftServer() {
  try {
    const response = await fetch('/api/mc/stop', { method: 'POST' });
    const data = await response.json();
    if (data.success) {
      showToast('已发送停止命令', 'success');
    } else {
      showToast('停止失败', 'error');
    }
    await loadMcStatus();
  } catch (error) {
    console.error('停止 MC 失败:', error);
    showToast('停止失败', 'error');
  }
}

async function killMinecraftServer() {
  try {
    const response = await fetch('/api/mc/kill', { method: 'POST' });
    const data = await response.json();
    if (data.success) {
      showToast('已强制终止 MC 服务器', 'success');
    } else {
      showToast('强制终止失败', 'error');
    }
    await loadMcStatus();
  } catch (error) {
    console.error('强制终止 MC 失败:', error);
    showToast('强制终止失败', 'error');
  }
}

async function sendMcCommand(commandInput) {
  const input = document.getElementById('mcCommandInput');
  const command = commandInput || input?.value.trim();
  if (!command) {
    showToast('请输入要发送的命令', 'warning');
    return;
  }
  try {
    const response = await fetch('/api/mc/command', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ command }),
    });
    const data = await response.json();
    if (data.success) {
      showToast('命令已发送', 'success');
      addToCommandHistory(command);
      if (input && !commandInput) input.value = '';
      loadMcLogs();
    } else {
      showToast(data.error || '命令发送失败', 'error');
    }
  } catch (error) {
    console.error('发送 MC 命令失败:', error);
    showToast('命令发送失败', 'error');
  }
}

const mcCommandInput = document.getElementById('mcCommandInput');
if (mcCommandInput) {
  mcCommandInput.addEventListener('keydown', (event) => {
    if (event.key === 'Enter') {
      event.preventDefault();
      sendMcCommand();
      return;
    }

    if (event.key === 'ArrowUp') {
      if (commandHistory.length === 0) return;
      historyIndex = Math.max(0, historyIndex - 1);
      mcCommandInput.value = commandHistory[historyIndex] || '';
      event.preventDefault();
      return;
    }

    if (event.key === 'ArrowDown') {
      if (commandHistory.length === 0) return;
      historyIndex = Math.min(commandHistory.length, historyIndex + 1);
      mcCommandInput.value = commandHistory[historyIndex] || '';
      event.preventDefault();
    }
  });
}

const mcConsoleFilter = document.getElementById('mcConsoleFilter');
if (mcConsoleFilter) {
  mcConsoleFilter.addEventListener('input', (event) => {
    mcConsoleFilterText = event.target.value || '';
    renderMcConsole();
  });
}

loadCommandHistory();
