// mc_controller.js
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');

const CONFIG_FILE = path.join(__dirname, 'mc_config.json');
const LOG_DIR = path.join(__dirname, 'logs', 'mc');
const LOG_FILE = path.join(LOG_DIR, 'latest.log');
const BACKUP_DIR = path.join(__dirname, 'backups');
const BACKUP_AUDIT = path.join(LOG_DIR, 'backups.log');
const DATA_DIR = path.join(__dirname, 'data');
const PID_FILE = path.join(DATA_DIR, 'mc.pid');
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
  maxMemory: '4096M',
  additionalArgs: '',
  backupDir: BACKUP_DIR,
  autoBackupEnabled: false,
  autoBackupCron: '',
  backupRetentionCount: 7,
  backupRetentionDays: 30,
  autostart: false,
  autoRestart: false,
  autoRestartDelaySeconds: 5,
  autoRestartMaxRetries: 3,
  playerListIntervalSeconds: 0,
};
let restartAttempts = 0;
let lastStartTimestamp = 0;
let manualStopRequested = false;
let playerListTimer = null;
let statsTimer = null;
let wsServer = null;
let latestTps = null;
let latestCpu = 0;
let latestMemory = { used: 0, total: os.totalmem() };
let autoBackupTimer = null;
let lastAutoBackupKey = null;
let backupInProgress = false;

function setWebSocketServer(server) {
  wsServer = server;
}

function getBackupDir() {
  if (!config.backupDir) return BACKUP_DIR;
  const base = config.workingDir || process.cwd();
  return path.isAbsolute(config.backupDir) ? config.backupDir : path.resolve(base, config.backupDir);
}

function ensureMcDirectories() {
  if (!fs.existsSync(LOG_DIR)) {
    fs.mkdirSync(LOG_DIR, { recursive: true });
  }
  const backupDir = getBackupDir();
  if (!fs.existsSync(backupDir)) {
    fs.mkdirSync(backupDir, { recursive: true });
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
      // 配置加载后（如包含自动备份设置）需要重新配置调度
      configureAutoTasks();
    } catch (e) {
      console.error('加载 MC 配置失败', e);
      pushLog(`加载 MC 配置失败: ${e.message}`);
    }
  }
}

async function checkCompressionTools() {
  try {
    if (process.platform === 'win32') {
      try {
        const out = await runChildProcess('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', "(Get-Command Compress-Archive -ErrorAction SilentlyContinue).Name"], { windowsHide: true });
        if (!out || !out.trim()) {
          pushLog('警告：系统未检测到 PowerShell 的 Compress-Archive，备份压缩可能失败');
        }
      } catch (e) {
        pushLog('警告：无法检测 PowerShell Compress-Archive，备份压缩可能失败');
      }
    } else {
      try {
        await runChildProcess('tar', ['--version'], { windowsHide: true });
      } catch (e) {
        pushLog('警告：系统未检测到 tar 命令，备份压缩可能失败');
      }
    }
  } catch (e) {
    // ignore
  }
}

function saveConfig() {
  fs.writeFileSync(CONFIG_FILE, JSON.stringify(config, null, 2), 'utf8');
}

function parseCronField(field, value, min, max) {
  if (field === '*') return true;
  if (field.includes(',')) return field.split(',').some((part) => parseCronField(part.trim(), value, min, max));
  if (field.indexOf('/') > -1) {
    const [base, step] = field.split('/');
    const interval = parseInt(step, 10);
    if (Number.isNaN(interval) || interval <= 0) return false;
    if (base === '*') {
      return (value - min) % interval === 0;
    }
    return false;
  }
  if (field.indexOf('-') > -1) {
    const [start, end] = field.split('-').map((v) => parseInt(v, 10));
    if (Number.isNaN(start) || Number.isNaN(end)) return false;
    return value >= start && value <= end;
  }
  const expected = parseInt(field, 10);
  return !Number.isNaN(expected) && value === expected;
}

function isCronScheduleDue(cronExpression, now) {
  const parts = String(cronExpression || '').trim().split(/\s+/);
  if (parts.length !== 5) return false;
  const [minuteExpr, hourExpr, dayExpr, monthExpr, dowExpr] = parts;
  return parseCronField(minuteExpr, now.getMinutes(), 0, 59)
    && parseCronField(hourExpr, now.getHours(), 0, 23)
    && parseCronField(dayExpr, now.getDate(), 1, 31)
    && parseCronField(monthExpr, now.getMonth() + 1, 1, 12)
    && parseCronField(dowExpr, now.getDay(), 0, 6);
}

function getAutoBackupKey(now) {
  return `${now.getFullYear()}-${now.getMonth() + 1}-${now.getDate()}-${now.getHours()}-${now.getMinutes()}`;
}

function stopAutoBackup() {
  if (autoBackupTimer) {
    clearInterval(autoBackupTimer);
    autoBackupTimer = null;
  }
}

function configureAutoTasks() {
  stopAutoBackup();
  lastAutoBackupKey = null;
  if (!config.autoBackupEnabled || !String(config.autoBackupCron || '').trim()) return;
  autoBackupTimer = setInterval(async () => {
    if (!config.autoBackupEnabled || !config.autoBackupCron) return;
    const now = new Date();
    if (!isCronScheduleDue(config.autoBackupCron, now)) return;
    const key = getAutoBackupKey(now);
    if (key === lastAutoBackupKey) return;
    lastAutoBackupKey = key;
    if (backupInProgress) return;
    backupInProgress = true;
    try {
      const backupDir = getBackupDir();
      const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
      const idPart = mcProcess && mcProcess.pid ? String(mcProcess.pid) : 'local';
      const name = process.platform === 'win32' ? `backup-${idPart}-${timestamp}.zip` : `backup-${idPart}-${timestamp}.tar.gz`;
      const dest = path.join(backupDir, name);
      const cwd = config.workingDir || process.cwd();
      const worldNames = ['world', 'world_nether', 'world_the_end'];
      const toArchive = worldNames.filter((d) => fs.existsSync(path.join(cwd, d))).map((d) => d);
      if (toArchive.length === 0) {
        pushLog('自动备份跳过：未找到 world 目录');
        return;
      }
      pushLog(`开始自动备份: ${name}`);
      await safeBackupWorlds(toArchive, dest, cwd);
      if (fs.existsSync(dest)) {
        await fs.promises.appendFile(BACKUP_AUDIT, `${new Date().toISOString()} CREATED ${name}\n`);
        pushLog(`自动备份完成: ${name}`);
        await cleanupOldBackups();
      } else {
        pushLog('自动备份失败：备份文件未创建');
      }
    } catch (e) {
      pushLog(`自动备份异常: ${e.message}`);
    } finally {
      backupInProgress = false;
    }
  }, 30 * 1000);
}

function stripMcColorCodes(text) {
  return String(text).replace(/§[0-9A-FK-OR]/gi, '').replace(/\u001b\[[0-9;]*m/g, '');
}

function classifyMcLogLevel(line) {
  const text = String(line || '').toUpperCase();
  if (text.includes('[SEVERE]') || text.includes('[ERROR]') || text.includes('[STDERR]') || /\b(EXCEPTION|FAILED|FAILURE|ERR(OR)?|CRITICAL)\b/.test(text)) {
    return 'error';
  }
  if (text.includes('[WARN]') || text.includes('[WARNING]') || text.includes('WARN ')) {
    return 'warn';
  }
  if (text.includes('[DEBUG]') || text.includes('[TRACE]')) {
    return 'debug';
  }
  return 'info';
}

function parsePlayerList(stdoutLine) {
  const line = stripMcColorCodes(String(stdoutLine || '')).trim();
  const patterns = [
    /There are (\d+) of a max of (\d+) players online: ?(.*)/i,
    /当前在线\s*(\d+)\s*名?玩家[\s\S]*?最大\s*(\d+)\s*名?在线:?\s*(.*)/,
  ];

  for (const regex of patterns) {
    const match = line.match(regex);
    if (match) {
      const count = parseInt(match[1], 10);
      const max = parseInt(match[2], 10);
      const players = match[3] ? match[3].split(',').map((p) => p.trim()).filter(Boolean) : [];
      return { count, max, players };
    }
  }

  return null;
}

function parseTpsValue(stdoutLine) {
  if (!stdoutLine) return null;
  const cleaned = stripMcColorCodes(stdoutLine);
  const regex = /TPS(?:\s*from\s*last[^:]*:)?\s*([0-9]+(?:\.[0-9]+)?)/i;
  const match = cleaned.match(regex);
  if (match) {
    return parseFloat(match[1]);
  }
  const fallback = cleaned.match(/([0-9]+(?:\.[0-9]+)?)\s*tps/i);
  return fallback ? parseFloat(fallback[1]) : null;
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

function ensureLogDirectory() {
  if (!fs.existsSync(LOG_DIR)) {
    fs.mkdirSync(LOG_DIR, { recursive: true });
  }
}

function appendLogToFile(formatted) {
  ensureLogDirectory();
  const sanitized = stripMcColorCodes(formatted);
  fs.appendFile(LOG_FILE, sanitized + os.EOL, (err) => {
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
  const level = classifyMcLogLevel(normalized);
  broadcastMcPayload({ type: 'mc_log', line: formatted, level });

  const parsed = parsePlayerList(normalized);
  if (parsed) {
    updatePlayerInfo(parsed);
  }

  const tps = parseTpsValue(normalized);
  if (tps !== null && !Number.isNaN(tps)) {
    latestTps = tps;
    broadcastMcPayload({ type: 'mc_stats', cpu: latestCpu, memory: latestMemory, tps: latestTps });
  }
}

function getStatus() {
  const running = mcProcess !== null;
  const pid = mcProcess ? mcProcess.pid : null;
  const recovered = mcProcess && mcProcess.recovered === true;
  return { running, pid, recovered };
}

function ensureDataDir() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
}

function writePidFile(pid) {
  try {
    ensureDataDir();
    fs.writeFileSync(PID_FILE, String(pid), 'utf8');
  } catch (e) {
    console.error('写入 PID 文件失败', e);
  }
}

function readPidFile() {
  try {
    if (!fs.existsSync(PID_FILE)) return null;
    const raw = fs.readFileSync(PID_FILE, 'utf8').trim();
    const pid = parseInt(raw, 10);
    return Number.isFinite(pid) ? pid : null;
  } catch (e) {
    return null;
  }
}

function clearPidFile() {
  try {
    if (fs.existsSync(PID_FILE)) fs.unlinkSync(PID_FILE);
  } catch (e) {
    console.error('清理 PID 文件失败', e);
  }
}

async function processExists(pid) {
  if (!pid) return false;
  try {
    if (process.platform === 'win32') {
      const out = await runChildProcess('tasklist', ['/FI', `PID eq ${pid}`]);
      return out && out.indexOf(String(pid)) !== -1;
    }
    // unix-like
    try {
      process.kill(pid, 0);
      return true;
    } catch (e) {
      return false;
    }
  } catch (e) {
    return false;
  }
}

async function tryRestoreFromPidFile() {
  const pid = readPidFile();
  if (!pid) return false;
  const exists = await processExists(pid);
  if (!exists) {
    clearPidFile();
    return false;
  }
  mcProcess = { pid, recovered: true };
  pushLog(`检测到已存在的 Minecraft 进程 (pid=${pid})，状态已恢复为“运行中”（只读模式）`);
  // start stats polling so UI can show CPU/memory
  startStatsPolling();
  // do not enable player list polling or stdin-based commands for recovered processes
  return true;
}

async function scanForMcProcess() {
  try {
    const lookFor = [];
    if (config.jarPath) lookFor.push(path.basename(config.jarPath));
    if (config.fullCommand) lookFor.push(config.fullCommand.split(' ').slice(0,3).join(' '));
    // fallback keywords
    lookFor.push('server.jar');
    lookFor.push('java');

    if (process.platform === 'win32') {
        try {
          const out = await runChildProcess('wmic', ['process', 'get', 'ProcessId,CommandLine'], { windowsHide: true });
          const lines = out.split(/\r?\n/).map(l => l.trim()).filter(Boolean);
          for (const line of lines) {
            const m = line.match(/(.*)\s+(\d+)$/);
            if (!m) continue;
            const cmd = m[1] || '';
            const pid = parseInt(m[2], 10);
            if (!pid) continue;
            const combined = cmd.toLowerCase();
            if (lookFor.some(k => combined.indexOf(k.toLowerCase()) !== -1)) {
              mcProcess = { pid, recovered: true };
              pushLog(`通过进程扫描关联到 PID ${pid}`);
              startStatsPolling();
              return true;
            }
          }
        } catch (e) {
          // 如果 wmic 不可用，回退到 PowerShell 的进程查询
          try {
            const out = await runChildProcess('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', "Get-CimInstance Win32_Process | Select-Object CommandLine,ProcessId | ConvertTo-Json -Depth 2"], { windowsHide: true });
            let parsed = null;
            try { parsed = JSON.parse(out); } catch (pe) { parsed = null; }
            const entries = Array.isArray(parsed) ? parsed : (parsed ? [parsed] : []);
            for (const entry of entries) {
              const cmd = String(entry.CommandLine || '');
              const pid = parseInt(entry.ProcessId, 10);
              if (!pid) continue;
              const combined = cmd.toLowerCase();
              if (lookFor.some(k => combined.indexOf(k.toLowerCase()) !== -1)) {
                mcProcess = { pid, recovered: true };
                pushLog(`通过 PowerShell 进程扫描关联到 PID ${pid}`);
                startStatsPolling();
                return true;
              }
            }
          } catch (pe) {
            // ignore
          }
        }
    } else {
      const out = await runChildProcess('ps', ['-eo', 'pid,cmd'], { windowsHide: true });
      const lines = out.split(/\n/).map(l => l.trim()).filter(Boolean);
      for (const line of lines) {
        const m = line.match(/^(\d+)\s+(.*)$/);
        if (!m) continue;
        const pid = parseInt(m[1], 10);
        const cmd = m[2] || '';
        const combined = cmd.toLowerCase();
        if (lookFor.some(k => combined.indexOf(k.toLowerCase()) !== -1)) {
          mcProcess = { pid, recovered: true };
          pushLog(`通过进程扫描关联到 PID ${pid}`);
          startStatsPolling();
          return true;
        }
      }
    }
    return false;
  } catch (e) {
    console.error('扫描进程失败', e);
    return false;
  }
}

function getLogs() {
  return mcLogs.slice(-200);
}

function startPlayerListPolling() {
  stopPlayerListPolling();
  if (!config.playerListIntervalSeconds || !mcProcess || !mcProcess.stdin) return;
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
      latestCpu = stats.cpu;
      latestMemory = stats.memory;
      broadcastMcPayload({ type: 'mc_stats', cpu: latestCpu, memory: latestMemory, tps: latestTps });
    }
  }, 1000);
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

function waitForMcProcessClose(timeoutMs = 15000) {
  if (!mcProcess) return Promise.resolve(true);
  // if process looks like a recovered placeholder, cannot wait on events
  if (!mcProcess || !mcProcess.on) return Promise.resolve(false);
  return new Promise((resolve) => {
    const procRef = mcProcess;
    const onClose = () => {
      clearTimeout(timer);
      resolve(true);
    };
    const timer = setTimeout(() => {
      procRef.removeListener('close', onClose);
      resolve(false);
    }, timeoutMs);
    procRef.once('close', onClose);
  });
}

function getWindowsProcessStats(pid) {
  return new Promise(async (resolve) => {
    try {
      // 使用 PowerShell 的 Get-Process 回退（不再依赖 WMIC）
      const cmd = `Get-Process -Id ${pid} -ErrorAction SilentlyContinue | Select-Object -Property CPU,WorkingSet64 | ConvertTo-Json`;
      const out = await runChildProcess('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', cmd], { windowsHide: true });
      let parsed = null;
      try { parsed = JSON.parse(out); } catch (e) { parsed = null; }
      if (!parsed) return resolve(null);
      // parsed 可能是对象或数组
      const proc = Array.isArray(parsed) ? parsed[0] : parsed;
      const cpuSeconds = typeof proc.CPU === 'number' ? proc.CPU : (parseFloat(proc.CPU) || 0);
      const used = Number(proc.WorkingSet64) || 0;
      // CPU 以秒计，不转换为百分比；UI 可决定如何展示或进一步计算
      resolve({ cpu: cpuSeconds, memory: { used, total: os.totalmem() } });
    } catch (e) {
      // 回退到 null
      resolve(null);
    }
  });
}

function getUnixProcessStats(pid) {
  return new Promise((resolve) => {
    const stats = [];
    const gather = (processId, callback) => {
      const proc = spawn('ps', ['-p', String(processId), '-o', '%cpu=', '-o', 'rss='], { windowsHide: true });
      let output = '';
      proc.stdout.on('data', (data) => { output += data.toString(); });
      proc.on('close', () => {
        const parts = output.trim().split(/\s+/);
        if (parts.length >= 2) {
          stats.push({ cpu: parseFloat(parts[0] || '0'), rss: parseInt(parts[1] || '0', 10) * 1024 });
        }
        callback();
      });
      proc.on('error', () => callback());
    };

    const gatherChildren = (processId, callback) => {
      const proc = spawn('ps', ['--ppid', String(processId), '-o', 'pid='], { windowsHide: true });
      let output = '';
      proc.stdout.on('data', (data) => { output += data.toString(); });
      proc.on('close', () => {
        const childPids = output.trim().split(/\s+/).filter(Boolean);
        if (childPids.length === 0) return callback();
        let remaining = childPids.length;
        childPids.forEach((childPid) => {
          gather(childPid, () => {
            remaining -= 1;
            if (remaining === 0) callback();
          });
        });
      });
      proc.on('error', () => callback());
    };

    gather(pid, () => {
      gatherChildren(pid, () => {
        const totalCpu = stats.reduce((sum, item) => sum + (Number.isFinite(item.cpu) ? item.cpu : 0), 0);
        const totalUsed = stats.reduce((sum, item) => sum + (Number.isFinite(item.rss) ? item.rss : 0), 0);
        resolve({ cpu: totalCpu, memory: { used: totalUsed, total: os.totalmem() } });
      });
    });
  });
}

function startMinecraft(manualStart = true) {
  if (mcProcess) return false;
  const { fullCommand, workingDir } = config;
  if (!fullCommand || !fullCommand.trim()) return false;

  try {
    manualStopRequested = false;
    if (manualStart) {
      restartAttempts = 0;
    }
    lastStartTimestamp = Date.now();
    mcProcess = spawn(fullCommand, [], { cwd: workingDir, shell: true, windowsHide: true, detached: false });
    try {
      writePidFile(mcProcess.pid);
    } catch (e) {
      console.error('写 PID 文件失败', e);
    }
    pushLog(`启动命令: ${fullCommand}`);

    mcProcess.stdout.on('data', (data) => pushLog(data.toString()));
    mcProcess.stderr.on('data', (data) => pushLog(`[STDERR] ${data.toString()}`));
    mcProcess.on('close', (code) => {
      pushLog(`Minecraft 服务器进程已退出，退出码: ${code}`);
      const runDuration = Date.now() - lastStartTimestamp;
      const restartResetMs = 30 * 1000;
      if (runDuration > restartResetMs) {
        restartAttempts = 0;
      }
      mcProcess = null;
      clearPidFile();
      stopPlayerListPolling();
      stopStatsPolling();
      if (config.autoRestart && !manualStopRequested) {
        if (restartAttempts < config.autoRestartMaxRetries) {
          const delaySeconds = Math.max(1, Number(config.autoRestartDelaySeconds) || 5);
          const backoff = Math.min(delaySeconds * Math.pow(2, restartAttempts), 60);
          restartAttempts += 1;
          pushLog(`将在 ${backoff} 秒后自动重启（${restartAttempts}/${config.autoRestartMaxRetries}）`);
          setTimeout(() => {
            if (!mcProcess) {
              startMinecraft(false);
            }
          }, backoff * 1000);
        } else {
          pushLog('已达到最大自动重启次数，不再继续重启');
        }
      }
    });
    mcProcess.on('error', (err) => {
      pushLog(`启动失败: ${err.message}`);
      mcProcess = null;
      clearPidFile();
      stopPlayerListPolling();
      stopStatsPolling();
    });
    startStatsPolling();
    startPlayerListPolling();
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
  if (mcProcess.recovered) {
    pushLog('无法向恢复的进程发送停止命令（stdin 不可用）；请使用强制终止或在主机上手动停止');
    return false;
  }
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
    stopStatsPolling();
    const pid = mcProcess.pid;
    if (!pid) return false;
    if (process.platform === 'win32') {
      spawn('taskkill', ['/pid', String(pid), '/f', '/t'], { windowsHide: true });
    } else {
      try {
        process.kill(pid, 'SIGTERM');
      } catch (err) {
        // fallback to spawn kill
        spawn('kill', ['-TERM', String(pid)], { windowsHide: true });
      }
    }
    pushLog('已强制终止 Minecraft 服务器进程');
    clearPidFile();
    return true;
  } catch (e) {
    pushLog(`强制终止失败: ${e.message}`);
    return false;
  }
}

function runChildProcess(command, args, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { windowsHide: true, ...options });
    let output = '';
    child.stdout.on('data', (data) => { output += data.toString(); });
    child.stderr.on('data', (data) => { output += data.toString(); });
    child.on('close', (code) => {
      if (code === 0) resolve(output);
      else reject(new Error(output || `退出码 ${code}`));
    });
    child.on('error', (err) => reject(err));
  });
}

async function createBackupArchive(worldDirs, dest, cwd) {
  if (process.platform === 'win32') {
    const quotedPaths = worldDirs.map((dir) => `'${dir.replace(/'/g, "''")}'`).join(', ');
    const quotedDest = dest.replace(/'/g, "''");
    try {
      await runChildProcess('powershell.exe', [
        '-NoProfile',
        '-NonInteractive',
        '-Command',
        `Compress-Archive -Path ${quotedPaths} -DestinationPath '${quotedDest}' -Force`
      ], { cwd });
      return;
    } catch (archiveError) {
      // 在纯净的 Windows 环境中，我们要求使用 PowerShell；不要回退到 tar（可能不存在）
      throw archiveError;
    }
  }
  await runChildProcess('tar', ['-czf', dest, ...worldDirs], { cwd });
}

async function extractBackupArchive(file, cwd) {
  if (file.toLowerCase().endsWith('.zip')) {
    if (process.platform === 'win32') {
      const quotedFile = file.replace(/'/g, "''");
      const quotedCwd = cwd.replace(/'/g, "''");
      try {
        await runChildProcess('powershell.exe', [
          '-NoProfile',
          '-NonInteractive',
          '-Command',
          `Expand-Archive -Path '${quotedFile}' -DestinationPath '${quotedCwd}' -Force`
        ], { cwd });
        return;
      } catch (e) {
        // 不回退到 unzip，在没有 PowerShell 的纯净 Windows 环境中应当报错
        throw e;
      }
    }
    await runChildProcess('unzip', ['-o', file, '-d', cwd], { cwd });
    return;
  }
  await runChildProcess('tar', ['-xzf', file, '-C', cwd], { cwd });
}

function sendCommand(command) {
  if (!mcProcess) return false;
  if (mcProcess.recovered) {
    pushLog('无法向已恢复的进程发送命令（stdin 不可用）');
    return false;
  }
  if (!mcProcess.stdin || mcProcess.stdin.destroyed) return false;
  try {
    mcProcess.stdin.write(command + '\n');
    pushLog(`> ${command}`);
    return true;
  } catch (e) {
    pushLog(`发送命令失败: ${e.message}`);
    return false;
  }
}

async function cleanupOldBackups() {
  try {
    ensureMcDirectories();
    const backupDir = getBackupDir();
    const files = fs.readdirSync(backupDir).filter((name) => /\.(tar\.gz|zip)$/i.test(name));
    let list = files.map((name) => {
      const filePath = path.join(backupDir, name);
      const st = fs.statSync(filePath);
      return { name, path: filePath, mtime: st.mtimeMs };
    }).sort((a, b) => b.mtime - a.mtime);

    const now = Date.now();
    if (Number.isInteger(config.backupRetentionDays) && config.backupRetentionDays > 0) {
      const cutoff = now - config.backupRetentionDays * 24 * 60 * 60 * 1000;
      for (const item of list) {
        if (item.mtime < cutoff) {
          try {
            fs.unlinkSync(item.path);
            await fs.promises.appendFile(BACKUP_AUDIT, `${new Date().toISOString()} PURGED_BY_AGE ${item.name}\n`);
            pushLog(`清理旧备份: ${item.name}（超过 ${config.backupRetentionDays} 天）`);
          } catch (e) {
            console.error('清理旧备份失败:', e);
          }
        }
      }
      // 重新读取列表，避免后续按数量删除时依据过期前的静态列表误删
      const refreshed = fs.readdirSync(backupDir).filter((name) => /\.(tar\.gz|zip)$/i.test(name));
      list = refreshed.map((name) => {
        const filePath = path.join(backupDir, name);
        const st = fs.statSync(filePath);
        return { name, path: filePath, mtime: st.mtimeMs };
      }).sort((a, b) => b.mtime - a.mtime);
    }

    if (Number.isInteger(config.backupRetentionCount) && config.backupRetentionCount > 0) {
      const toPurge = list.slice(config.backupRetentionCount);
      for (const item of toPurge) {
        try {
          fs.unlinkSync(item.path);
          await fs.promises.appendFile(BACKUP_AUDIT, `${new Date().toISOString()} PURGED_BY_COUNT ${item.name}\n`);
          pushLog(`清理旧备份: ${item.name}（保留最新 ${config.backupRetentionCount} 个）`);
        } catch (e) {
          console.error('清理旧备份失败:', e);
        }
      }
    }
  } catch (e) {
    console.error('清理旧备份失败', e);
  }
}

async function safeBackupWorlds(worldDirs, dest, cwd) {
  let saveOffSent = false;
  if (mcProcess) {
    if (mcProcess.recovered === true) {
      pushLog('检测到恢复的进程；跳过自动备份以避免不一致的世界快照');
      throw new Error('进程处于恢复模式，无法执行安全备份');
    }
    pushLog('正在执行 save-off/save-all 同步世界数据，以开始安全备份');
    saveOffSent = sendCommand('save-off');
    sendCommand('save-all');
    await new Promise((resolve) => setTimeout(resolve, 3000));
  }

  try {
    await createBackupArchive(worldDirs, dest, cwd);
  } finally {
    if (saveOffSent && mcProcess) {
      sendCommand('save-on');
      pushLog('已恢复自动保存 (save-on)');
    }
  }
}

function setupRoutes(app) {
  app.get('/api/mc/config', (req, res) => {
    res.json({ success: true, config });
  });

  app.post('/api/mc/config', (req, res) => {
    const {
      fullCommand,
      workingDir,
      javaPath,
      jarPath,
      minMemory,
      maxMemory,
      additionalArgs,
      backupDir,
      autoBackupEnabled,
      autoBackupCron,
      backupRetentionCount,
      backupRetentionDays,
      autoRestart,
      autoRestartDelaySeconds,
      autoRestartMaxRetries,
      playerListIntervalSeconds,
    } = req.body;
    if (fullCommand !== undefined) config.fullCommand = fullCommand;
    if (workingDir !== undefined) config.workingDir = workingDir;
    if (javaPath !== undefined) config.javaPath = javaPath;
    if (jarPath !== undefined) config.jarPath = jarPath;
    if (minMemory !== undefined) config.minMemory = minMemory;
    if (maxMemory !== undefined) config.maxMemory = maxMemory;
    if (additionalArgs !== undefined) config.additionalArgs = additionalArgs;
    if (backupDir !== undefined) config.backupDir = backupDir;
    if (autoBackupEnabled !== undefined) config.autoBackupEnabled = Boolean(autoBackupEnabled);
    if (autoBackupCron !== undefined) config.autoBackupCron = autoBackupCron;
    if (typeof backupRetentionCount === 'number') config.backupRetentionCount = backupRetentionCount;
    if (typeof backupRetentionDays === 'number') config.backupRetentionDays = backupRetentionDays;
    if (autoRestart !== undefined) config.autoRestart = Boolean(autoRestart);
    if (typeof autoRestartDelaySeconds === 'number') config.autoRestartDelaySeconds = autoRestartDelaySeconds;
    if (typeof autoRestartMaxRetries === 'number') config.autoRestartMaxRetries = autoRestartMaxRetries;
    if (typeof playerListIntervalSeconds === 'number') config.playerListIntervalSeconds = playerListIntervalSeconds;
    saveConfig();
    // 重配置自动任务（例如 autoBackupCron）
    configureAutoTasks();
    if (mcProcess) {
      startPlayerListPolling();
    }
    pushLog('Minecraft 配置已保存');
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

  app.post('/api/mc/sync', async (req, res) => {
    try {
      // First try PID file restoration
      const restored = await tryRestoreFromPidFile();
      if (restored) {
        startPlayerListPolling();
        return res.json({ success: true, message: '已根据 PID 文件恢复运行状态', pid: mcProcess.pid, recovered: true });
      }
      // Otherwise scan processes for likely MC process
      const found = await scanForMcProcess();
      if (found) {
        writePidFile(mcProcess.pid);
        startPlayerListPolling();
        return res.json({ success: true, message: '已找到并关联现有进程', pid: mcProcess.pid, recovered: true });
      }
      return res.json({ success: false, message: '未找到正在运行的 MC 进程' });
    } catch (e) {
      console.error('同步 MC 状态失败', e);
      res.status(500).json({ success: false, error: e.message });
    }
  });

  // Backups: create, list, download, restore
  app.post('/api/mc/backup', async (req, res) => {
    try {
      ensureMcDirectories();
      const backupDir = getBackupDir();
      const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
      const name = process.platform === 'win32' ? `backup-${timestamp}.zip` : `backup-${timestamp}.tar.gz`;
      const dest = path.join(backupDir, name);
      const worldNames = ['world', 'world_nether', 'world_the_end'];
      const cwd = config.workingDir || process.cwd();

      const toArchive = worldNames.filter((d) => fs.existsSync(path.join(cwd, d))).map((d) => d);
      if (toArchive.length === 0) {
        return res.status(400).json({ success: false, error: '未找到任何 world 目录可备份' });
      }

      pushLog(`开始创建备份: ${name}`);
      await safeBackupWorlds(toArchive, dest, cwd);
      if (!fs.existsSync(dest)) {
        throw new Error('备份文件创建失败');
      }

      await fs.promises.appendFile(BACKUP_AUDIT, `${new Date().toISOString()} CREATED ${name}\n`);
      pushLog(`备份创建完成: ${name}`);
      await cleanupOldBackups();
      res.json({ success: true, name });
    } catch (e) {
      console.error('创建备份失败', e);
      pushLog(`创建备份失败: ${e.message}`);
      res.status(500).json({ success: false, error: e.message });
    }
  });

  app.get('/api/mc/backups', (req, res) => {
    try {
      ensureMcDirectories();
      const backupDir = getBackupDir();
      if (!fs.existsSync(backupDir)) return res.json({ success: true, backups: [] });
      const files = fs.readdirSync(backupDir).filter(f => f.endsWith('.tar.gz') || f.endsWith('.zip'));
      const list = files.map((f) => {
        const st = fs.statSync(path.join(backupDir, f));
        return { name: f, size: st.size, mtime: st.mtimeMs };
      }).sort((a,b)=>b.mtime-a.mtime);
      res.json({ success: true, backups: list });
    } catch (e) {
      console.error('列出备份失败', e);
      res.status(500).json({ success: false, error: e.message });
    }
  });

  app.get('/api/mc/backups/:name/download', (req, res) => {
    try {
      ensureMcDirectories();
      const backupDir = getBackupDir();
      const name = path.basename(req.params.name);
      const file = path.join(backupDir, name);
      if (!fs.existsSync(file)) return res.status(404).json({ success: false, error: '备份文件不存在' });
      res.download(file, name, (err) => {
        if (err) res.status(500).json({ success: false, error: '下载失败' });
      });
    } catch (e) {
      console.error('下载备份失败', e);
      res.status(500).json({ success: false, error: e.message });
    }
  });

  app.post('/api/mc/backups/:name/restore', async (req, res) => {
    try {
      ensureMcDirectories();
      const backupDir = getBackupDir();
      const name = path.basename(req.params.name);
      const file = path.join(backupDir, name);
      if (!fs.existsSync(file)) return res.status(404).json({ success: false, error: '备份文件不存在' });
      if (mcProcess) {
        pushLog(`准备还原备份: ${name}，正在停止服务器...`);
        stopMinecraft();
        const closed = await waitForMcProcessClose(10000);
        if (!closed && mcProcess) {
          killMinecraft();
          await waitForMcProcessClose(5000);
        }
      }
      const cwd = config.workingDir || process.cwd();
      pushLog(`开始从备份还原: ${name}`);
      await extractBackupArchive(file, cwd);
      await fs.promises.appendFile(BACKUP_AUDIT, `${new Date().toISOString()} RESTORED ${name}\n`);
      const started = startMinecraft();
      pushLog(`备份还原完成: ${name}`);
      res.json({ success: true, restored: name, started });
    } catch (e) {
      console.error('还原备份失败', e);
      pushLog(`还原备份失败: ${e.message}`);
      res.status(500).json({ success: false, error: e.message });
    }
  });
}

loadConfig();
// 检查压缩/解压工具可用性，提示管理员
checkCompressionTools().catch(() => {});
// 尝试根据 PID 文件或进程扫描恢复已存在的 MC 进程状态
try {
  tryRestoreFromPidFile().catch(() => {});
} catch (e) {
  // ignore
}

module.exports = { setupRoutes, loadConfig, setWebSocketServer };
