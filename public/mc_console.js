let mcRefreshTimer = null;
const MC_AUTO_REFRESH_INTERVAL = 2000;

function formatMcLogs(logs) {
  return Array.isArray(logs) ? logs.join('\n') : String(logs || '');
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

function startMcAutoRefresh() {
  stopMcAutoRefresh();
  mcRefreshTimer = setInterval(() => {
    loadMcStatus();
    loadMcLogs();
  }, MC_AUTO_REFRESH_INTERVAL);
}

function stopMcAutoRefresh() {
  if (mcRefreshTimer) {
    clearInterval(mcRefreshTimer);
    mcRefreshTimer = null;
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

async function sendMcCommand() {
  const input = document.getElementById('mcCommandInput');
  if (!input) return;
  const command = input.value.trim();
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
      input.value = '';
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
    }
  });
}
