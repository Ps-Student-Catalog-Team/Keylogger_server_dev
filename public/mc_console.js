let mcRefreshTimer = null;
const commandHistory = [];
let historyIndex = -1;

function formatMcLogs(logs) {
  return Array.isArray(logs) ? logs.join('\n') : String(logs || '');
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
  output.textContent += line + '\n';
  if (mcAutoScroll) {
    output.scrollTop = output.scrollHeight;
  }
}

function clearMcConsole() {
  const output = document.getElementById('mcStdout');
  if (output) {
    output.textContent = '';
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

function updateMcStats(cpu, memory) {
  const cpuNode = document.getElementById('mcCpu');
  const memoryNode = document.getElementById('mcMemory');
  if (cpuNode) {
    cpuNode.textContent = `${cpu != null ? cpu.toFixed(1) : '-'} %`;
  }
  if (memoryNode) {
    const usedMb = memory && memory.used ? Math.round(memory.used / 1024 / 1024) : '-';
    const totalMb = memory && memory.total ? Math.round(memory.total / 1024 / 1024) : '-';
    memoryNode.textContent = `${usedMb} MB / ${totalMb} MB`;
  }
}

function renderPlayerList(players, count, max) {
  const container = document.getElementById('mcPlayerList');
  const countLabel = document.getElementById('mcPlayerCount');
  if (countLabel) {
    countLabel.textContent = `${count || (players ? players.length : 0)} / ${max || '-'}`;
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
              </div>
            </div>`;
  });

  container.innerHTML = `<div>${listItems.join('')}</div>`;
}

function confirmMcPlayerAction(player, action) {
  const actionLabel = action === 'ban' ? '封禁' : '踢出';
  const command = action === 'ban' ? `ban ${player}` : `kick ${player}`;
  if (typeof showConfirmModal === 'function') {
    showConfirmModal(`确认${actionLabel}`, `确定要${actionLabel} 玩家 ${player} 吗？`, () => sendMcCommand(command));
  } else if (window.confirm(`确定要${actionLabel} 玩家 ${player} 吗？`)) {
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
    const autoRestartStatus = document.getElementById('mcAutoRestart');
    if (autoRestartStatus) {
      autoRestartStatus.textContent = data.config.autoRestart ? '已启用' : '已禁用';
    }
  } catch (error) {
    console.error('加载 MC 配置失败:', error);
    showToast('加载 MC 配置失败', 'error');
  }
}

async function saveMcConfig() {
  const fullCommand = document.getElementById('mcConfigCommand')?.value.trim();
  const workingDir = document.getElementById('mcConfigDir')?.value.trim();
  try {
    const response = await fetch('/api/mc/config', {
      method: 'POST',
      body: JSON.stringify({ fullCommand, workingDir }),
    });
    const data = await response.json();
    if (data.success) {
      showToast('MC 配置已保存', 'success');
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
      output.textContent = formatMcLogs(data.logs);
      output.scrollTop = output.scrollHeight;
    }
  } catch (error) {
    console.error('获取 MC 日志失败:', error);
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
