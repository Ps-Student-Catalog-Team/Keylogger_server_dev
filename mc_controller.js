// mc_controller.js
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');

const CONFIG_FILE = path.join(__dirname, 'mc_config.json');
const LOG_DIR = path.join(__dirname, 'logs', 'mc');
const LOG_FILE = path.join(LOG_DIR, 'latest.log');
const LOG_MAX_LINES = 1000;
const WS_OPEN = 1;
let mcProcess = null;
let mcLogs = [];
let playerInfo = { players: [], count: 0, max: 0 };
let config = {
  fullCommand: '',
  workingDir: process.cwd(),
  javaPath: 'java',
  jarPath: 'server.jar',
  minMemory: '1024M',
  maxMemory: '2048M',
  additionalArgs: '',
  autostart: false,
  autoRestart: false,
  autoRestartDelaySeconds: 5,
  autoRestartMaxRetries: 3,
  playerListIntervalSeconds: 5,
};
let restartAttempts = 0;
let manualStopRequested = false;
let playerListTimer = null;
let statsTimer = null;
let wsServer = null;

function setWebSocketServer(server) {
  wsServer = server;
}

function ensureLogDirectory() {
  if (!fs.existsSync(LOG_DIR)) {
    fs.mkdirSync(LOG_DIR, { recursive: true });
  }
}

function broadcastMcPayload(payload) {
  if (!wsServer) return;
  const message = JSON.stringify(payload);
  wsServer.clients.forEach((ws) => {
    if (ws.readyState !== WS_OPEN) return;
    if (payload.type === 'mc_log' && ws.subscribedMc !== true) return;
    if (payload.type === 'mc_players' && ws.subscribedMcPlayers !== true) return;
    if (payload.type === 'mc_stats' && ws.subscribedMcStats !== true) return;
    ws.send(message);
  });
}

function loadConfig() {
  if (fs.existsSync(CONFIG_FILE)) {
    try {
      const data = fs.readFileSync(CONFIG_FILE, 'utf8');
      config = { ...config, ...JSON.parse(data) };
    } catch (e) {
      console.error('加载 MC 配置失败', e);
    }
  }
}

function saveConfig() {
  fs.writeFileSync(CONFIG_FILE, JSON.stringify(config, null, 2), 'utf8');
}

function parsePlayerList(stdoutLine) {
  const regex = /There are (\d+) of a max of (\d+) players online: ?(.*)/;
  const match = String(stdoutLine).match(regex);
  if (match) {
    const count = parseInt(match[1], 10);
    const max = parseInt(match[2], 10);
    const players = match[3] ? match[3].split(', ').map((p) => p.trim()).filter(Boolean) : [];
    return { count, max, players };
  }
  return null;
}

function updatePlayerInfo(data) {
  if (!data) return;
  playerInfo = {
    players: data.players || [],
    count: Number.isInteger(data.count) ? data.count : (data.players ? data.players.length : 0),
    max: Number.isInteger(data.max) ? data.max : 0,
  };
  broadcastMcPayload({ type: 'mc_players', players: playerInfo.players, count: playerInfo.count, max: playerInfo.max });
}

function appendLogToFile(formatted) {
  ensureLogDirectory();
  fs.appendFile(LOG_FILE, formatted + os.EOL, (err) => {
    if (err) {
      console.error('写入 MC 日志文件失败', err);
    }
  });
}

function pushLog(line) {
  const normalized = String(line).replace(/\r?\n$/, '');
  if (!normalized) return;
  const formatted = `${new Date().toISOString()} ${normalized}`;
  mcLogs.push(formatted);
  while (mcLogs.length > LOG_MAX_LINES) {
    mcLogs.shift();
  }
  appendLogToFile(formatted);
  broadcastMcPayload({ type: 'mc_log', line: formatted });

  const parsed = parsePlayerList(normalized);
  if (parsed) {
    updatePlayerInfo(parsed);
  }
}

function getStatus() {
  return { running: mcProcess !== null, pid: mcProcess ? mcProcess.pid : null };
}

function getLogs() {
  return mcLogs.slice(-200);
}

function startPlayerListPolling() {
  stopPlayerListPolling();
  if (!config.playerListIntervalSeconds || !mcProcess) return;
  playerListTimer = setInterval(() => {
    if (mcProcess) {
      sendCommand('list');
    }
  }, config.playerListIntervalSeconds * 1000);
}

function stopPlayerListPolling() {
  if (playerListTimer) {
    clearInterval(playerListTimer);
    playerListTimer = null;
  }
}

function startStatsPolling() {
  stopStatsPolling();
  if (!mcProcess) return;
  statsTimer = setInterval(async () => {
    if (!mcProcess || !mcProcess.pid) return;
    const stats = await getMcProcessStats(mcProcess.pid);
    if (stats) {
      broadcastMcPayload({ type: 'mc_stats', cpu: stats.cpu, memory: stats.memory });
    }
  }, 10000);
}

function stopStatsPolling() {
  if (statsTimer) {
    clearInterval(statsTimer);
    statsTimer = null;
  }
}

async function getMcProcessStats(pid) {
  try {
    if (process.platform === 'win32') {
      return await getWindowsProcessStats(pid);
    }
    return await getUnixProcessStats(pid);
  } catch (e) {
    console.error('获取 MC 进程统计失败', e);
    return null;
  }
}

function getWindowsProcessStats(pid) {
  return new Promise((resolve) => {
    const child = spawn('wmic', ['path', 'Win32_PerfFormattedData_PerfProc_Process', 'where', `IDProcess=${pid}`, 'get', 'PercentProcessorTime,WorkingSetPrivate', '/format:list'], { windowsHide: true });
    let output = '';
    child.stdout.on('data', (data) => { output += data.toString(); });
    child.on('close', () => {
      const result = {};
      output.split(/\r?\n/).forEach((line) => {
        const [key, value] = line.split('=');
        if (key && value !== undefined) {
          result[key.trim()] = value.trim();
        }
      });
      const cpu = parseFloat(result.PercentProcessorTime || '0');
      const used = parseInt(result.WorkingSetPrivate || '0', 10);
      resolve({ cpu: Number.isNaN(cpu) ? 0 : cpu, memory: { used, total: os.totalmem() } });
    });
    child.on('error', () => resolve(null));
  });
}

function getUnixProcessStats(pid) {
  return new Promise((resolve) => {
    const child = spawn('ps', ['-p', String(pid), '-o', '%cpu=', '-o', 'rss='], { windowsHide: true });
    let output = '';
    child.stdout.on('data', (data) => { output += data.toString(); });
    child.on('close', () => {
      const parts = output.trim().split(/\s+/);
      if (parts.length >= 2) {
        const cpu = parseFloat(parts[0] || '0');
        const rss = parseInt(parts[1] || '0', 10) * 1024;
        resolve({ cpu: Number.isNaN(cpu) ? 0 : cpu, memory: { used: rss, total: os.totalmem() } });
      } else {
        resolve(null);
      }
    });
    child.on('error', () => resolve(null));
  });
}

function startMinecraft() {
  if (mcProcess) return false;
  const { fullCommand, workingDir } = config;
  if (!fullCommand || !fullCommand.trim()) return false;

  try {
    manualStopRequested = false;
    restartAttempts = 0;
    mcProcess = spawn(fullCommand, [], { cwd: workingDir, shell: true, windowsHide: true, detached: false });
    pushLog(`启动命令: ${fullCommand}`);

    mcProcess.stdout.on('data', (data) => pushLog(data.toString()));
    mcProcess.stderr.on('data', (data) => pushLog(`[STDERR] ${data.toString()}`));
    mcProcess.on('close', (code) => {
      pushLog(`Minecraft 服务器进程已退出，退出码: ${code}`);
      mcProcess = null;
      stopPlayerListPolling();
      stopStatsPolling();
      if (config.autoRestart && !manualStopRequested) {
        if (restartAttempts < config.autoRestartMaxRetries) {
          restartAttempts += 1;
          pushLog(`将在 ${config.autoRestartDelaySeconds} 秒后自动重启（${restartAttempts}/${config.autoRestartMaxRetries}）`);
          setTimeout(() => {
            if (!mcProcess) {
              startMinecraft();
            }
          }, config.autoRestartDelaySeconds * 1000);
        } else {
          pushLog('已达到最大自动重启次数，不再继续重启');
        }
      }
    });
    mcProcess.on('error', (err) => {
      pushLog(`启动失败: ${err.message}`);
      mcProcess = null;
      stopPlayerListPolling();
      stopStatsPolling();
    });
    startPlayerListPolling();
    startStatsPolling();
    return true;
  } catch (e) {
    pushLog(`启动异常: ${e.message}`);
    mcProcess = null;
    stopPlayerListPolling();
    stopStatsPolling();
    return false;
  }
}

function stopMinecraft() {
  if (!mcProcess) return false;
  try {
    manualStopRequested = true;
    stopPlayerListPolling();
    mcProcess.stdin.write('stop\n');
    pushLog('已发送 stop 命令，Minecraft 服务器正在关闭...');
    return true;
  } catch (e) {
    pushLog(`发送 stop 失败: ${e.message}`);
    return false;
  }
}

function killMinecraft() {
  if (!mcProcess) return false;
  try {
    manualStopRequested = true;
    stopPlayerListPolling();
    mcProcess.kill('SIGTERM');
    pushLog('已强制终止 Minecraft 服务器进程');
    return true;
  } catch (e) {
    pushLog(`强制终止失败: ${e.message}`);
    return false;
  }
}

function sendCommand(command) {
  if (!mcProcess || mcProcess.stdin.destroyed) return false;
  try {
    mcProcess.stdin.write(command + '\n');
    pushLog(`> ${command}`);
    return true;
  } catch (e) {
    pushLog(`发送命令失败: ${e.message}`);
    return false;
  }
}

function setupRoutes(app) {
  app.get('/api/mc/config', (req, res) => {
    res.json({ success: true, config });
  });

  app.post('/api/mc/config', (req, res) => {
    const { fullCommand, workingDir, javaPath, jarPath, minMemory, maxMemory, additionalArgs, autoRestart, autoRestartDelaySeconds, autoRestartMaxRetries, playerListIntervalSeconds } = req.body;
    if (fullCommand !== undefined) config.fullCommand = fullCommand;
    if (workingDir !== undefined) config.workingDir = workingDir;
    if (javaPath !== undefined) config.javaPath = javaPath;
    if (jarPath !== undefined) config.jarPath = jarPath;
    if (minMemory !== undefined) config.minMemory = minMemory;
    if (maxMemory !== undefined) config.maxMemory = maxMemory;
    if (additionalArgs !== undefined) config.additionalArgs = additionalArgs;
    if (autoRestart !== undefined) config.autoRestart = Boolean(autoRestart);
    if (typeof autoRestartDelaySeconds === 'number') config.autoRestartDelaySeconds = autoRestartDelaySeconds;
    if (typeof autoRestartMaxRetries === 'number') config.autoRestartMaxRetries = autoRestartMaxRetries;
    if (typeof playerListIntervalSeconds === 'number') config.playerListIntervalSeconds = playerListIntervalSeconds;
    saveConfig();
    res.json({ success: true, message: '配置已保存' });
  });

  app.get('/api/mc/players', (req, res) => {
    res.json({ success: true, players: playerInfo.players, count: playerInfo.count, max: playerInfo.max });
  });

  app.post('/api/mc/players/refresh', (req, res) => {
    if (!mcProcess) {
      return res.status(400).json({ success: false, error: 'Minecraft 服务器未运行' });
    }
    const ok = sendCommand('list');
    if (!ok) {
      return res.status(500).json({ success: false, error: '刷新玩家列表失败' });
    }
    res.json({ success: true, message: '玩家列表刷新中，请稍候' });
  });

  app.post('/api/mc/start', (req, res) => {
    res.json({ success: startMinecraft() });
  });

  app.post('/api/mc/stop', (req, res) => {
    res.json({ success: stopMinecraft() });
  });

  app.post('/api/mc/kill', (req, res) => {
    res.json({ success: killMinecraft() });
  });

  app.post('/api/mc/command', (req, res) => {
    const { command } = req.body;
    if (!command) return res.status(400).json({ success: false, error: '命令不能为空' });
    res.json({ success: sendCommand(command) });
  });

  app.get('/api/mc/status', (req, res) => {
    res.json(getStatus());
  });

  app.get('/api/mc/logs', (req, res) => {
    res.json({ success: true, logs: getLogs() });
  });

  app.get('/api/mc/logs/download', (req, res) => {
    ensureLogDirectory();
    if (!fs.existsSync(LOG_FILE)) {
      return res.status(404).json({ success: false, error: 'MC 日志文件不存在' });
    }
    res.download(LOG_FILE, 'mc_latest.log', (err) => {
      if (err) {
        res.status(500).json({ success: false, error: '下载日志失败' });
      }
    });
  });
}

loadConfig();

module.exports = { setupRoutes, loadConfig, setWebSocketServer };
