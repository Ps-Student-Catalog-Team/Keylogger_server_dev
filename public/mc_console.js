let mcRefreshTimer = null;
const commandHistory = [];
let historyIndex = -1;
const mcStatsHistory = { cpu: [], memory: [], tps: [] };
const MC_STATS_HISTORY_MAX = 80;

function escapeHtml(value) {
  return String(value || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
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
  return html;
}

function formatMcLogs(logs) {
  if (!Array.isArray(logs)) return formatMcColorCodes(logs);
  return logs.map((line) => formatMcColorCodes(line)).join('<br>');
}

function addToCommandHistory(command) {
  if (!command) return;
  const last = commandHistory[commandHistory.length - 1];
  if (last === command) return;
  commandHistory.push(command);
  while (commandHistory.length > 20) {
    commandHistory.shift();
  }
  historyIndex = commandHistory.length;
}

let mcAutoScroll = true;

function appendMcLog(line) {
  const output = document.getElementById('mcStdout');
  if (!output || typeof line !== 'string') return;
  output.innerHTML += formatMcColorCodes(line) + '<br>';
  if (mcAutoScroll) {
    output.scrollTop = output.scrollHeight;
  }
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

function clearMcConsole() {
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

function drawMcStatsChart() {
  const canvas = document.getElementById('mcStatsChart');
  if (!canvas || !canvas.getContext) return;
  const ctx = canvas.getContext('2d');
  const width = canvas.width;
  const height = canvas.height;
  const padding = 30;
  ctx.clearRect(0, 0, width, height);
  ctx.fillStyle = '#111';
  ctx.fillRect(0, 0, width, height);
  const len = Math.max(mcStatsHistory.cpu.length, mcStatsHistory.memory.length, mcStatsHistory.tps.length);
  if (len < 2) return;
  const maxCpu = 100;
  const maxMem = Math.max(...mcStatsHistory.memory.map(m => m || 0), 1);
  const maxTps = mcStatsHistory.tps.length > 0 ? Math.max(...mcStatsHistory.tps.map(t => t || 0), 20) : 20;
  const graphWidth = width - padding * 2;
  const graphHeight = height - padding * 2;
  const xStep = graphWidth / (Math.max(len - 1, 1));
  const drawLine = (values, color, scaleFn) => {
    if (!values || values.length < 2) return;
    ctx.strokeStyle = color;
    ctx.lineWidth = 2;
    ctx.beginPath();
    values.forEach((value, index) => {
      const x = padding + index * xStep;
      const y = padding + graphHeight - scaleFn(value) * graphHeight;
      if (index === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    });
    ctx.stroke();
  };
  ctx.strokeStyle = '#ccc';
  ctx.lineWidth = 1;
  for (let i = 0; i <= 4; i++) {
    const y = padding + (graphHeight / 4) * i;
    ctx.beginPath();
    ctx.moveTo(padding, y);
    ctx.lineTo(width - padding, y);
    ctx.stroke();
    const labelValue = Math.round(maxCpu - (maxCpu / 4) * i);
    ctx.fillStyle = '#999';
    ctx.font = '11px sans-serif';
    ctx.fillText(`${labelValue}%`, 6, y + 4);
  }
  drawLine(mcStatsHistory.cpu, '#39b5e0', (value) => (value || 0) / maxCpu);
  drawLine(mcStatsHistory.memory, '#4ade80', (value) => (value || 0) / maxMem);
  if (mcStatsHistory.tps.length > 0) {
    drawLine(mcStatsHistory.tps, '#f59e0b', (value) => Math.min((value || 0) / maxTps, 1));
  }
  ctx.fillStyle = '#222';
  ctx.font = '12px sans-serif';
  ctx.fillText(`CPU`, padding + 4, padding - 10);
  ctx.fillStyle = '#4ade80';
  ctx.fillText(`MEM`, padding + 60, padding - 10);
  if (mcStatsHistory.tps.length > 0) {
    ctx.fillStyle = '#f59e0b';
    ctx.fillText(`TPS`, padding + 110, padding - 10);
  }
  ctx.fillStyle = '#555';
  ctx.font = '10px sans-serif';
  ctx.fillText(`CPU ${mcStatsHistory.cpu[mcStatsHistory.cpu.length-1]?.toFixed(1) ?? '-'}%`, padding, height - 8);
  ctx.fillText(`MEM ${mcStatsHistory.memory[mcStatsHistory.memory.length-1]?.toFixed(1) ?? '-'} MB`, padding + 180, height - 8);
  if (mcStatsHistory.tps.length > 0) {
    ctx.fillText(`TPS ${mcStatsHistory.tps[mcStatsHistory.tps.length-1]?.toFixed(2) ?? '-'}`, padding + 360, height - 8);
  }
}

function updateMcStats(cpu, memory, tps) {
  const cpuNode = document.getElementById('mcCpu');
  const memoryNode = document.getElementById('mcMemory');
  const tpsNode = document.getElementById('mcTps');
  if (cpuNode) {
    cpuNode.textContent = `${cpu != null ? cpu.toFixed(1) : '-'} %`;
  }
  if (memoryNode) {
    const usedMb = memory && memory.used ? Math.round(memory.used / 1024 / 1024) : '-';
    const totalMb = memory && memory.total ? Math.round(memory.total / 1024 / 1024) : '-';
    memoryNode.textContent = `${usedMb} MB / ${totalMb} MB`;
  }
  if (tpsNode) {
    tpsNode.textContent = typeof tps === 'number' ? tps.toFixed(2) : '-';
  }
  mcStatsHistory.cpu.push(cpu != null ? cpu : 0);
  mcStatsHistory.memory.push(memory && memory.used ? memory.used / 1024 / 1024 : 0);
  if (typeof tps === 'number') {
    mcStatsHistory.tps.push(tps);
  }
  if (mcStatsHistory.cpu.length > MC_STATS_HISTORY_MAX) mcStatsHistory.cpu.shift();
  if (mcStatsHistory.memory.length > MC_STATS_HISTORY_MAX) mcStatsHistory.memory.shift();
  if (mcStatsHistory.tps.length > MC_STATS_HISTORY_MAX) mcStatsHistory.tps.shift();
  drawMcStatsChart();
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
      showToast('正在刷新玩家列表', 'success');
      loadMcPlayers();
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
  const playerListIntervalSeconds = parseInt(document.getElementById('mcPlayerListInterval')?.value || '0', 10) || undefined;
  try {
    const response = await fetch('/api/mc/config', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ fullCommand, workingDir, autoRestart, autoRestartDelaySeconds, autoRestartMaxRetries, playerListIntervalSeconds }),
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
    const output = document.getElementById('mcStdout');
    if (output) {
      output.innerHTML = formatMcLogs(data.logs);
      output.scrollTop = output.scrollHeight;
    }
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
