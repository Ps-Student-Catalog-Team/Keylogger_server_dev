// mc_controller.js
const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');

const CONFIG_FILE = path.join(__dirname, 'mc_config.json');
const LOG_MAX_LINES = 1000;
let mcProcess = null;
let mcLogs = [];
let config = {
  fullCommand: '',
  workingDir: process.cwd(),
  javaPath: 'java',
  jarPath: 'server.jar',
  minMemory: '1024M',
  maxMemory: '2048M',
  additionalArgs: '',
  autostart: false,
};

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

function pushLog(line) {
  const normalized = String(line).replace(/\r?\n$/, '');
  if (!normalized) return;
  mcLogs.push(`${new Date().toISOString()} ${normalized}`);
  while (mcLogs.length > LOG_MAX_LINES) {
    mcLogs.shift();
  }
}

function getStatus() {
  return { running: mcProcess !== null, pid: mcProcess ? mcProcess.pid : null };
}

function getLogs() {
  return mcLogs.slice(-200);
}

function startMinecraft() {
  if (mcProcess) return false;
  const { fullCommand, workingDir } = config;
  if (!fullCommand || !fullCommand.trim()) return false;

  try {
    mcProcess = spawn(fullCommand, [], { cwd: workingDir, shell: true });
    pushLog(`启动命令: ${fullCommand}`);

    mcProcess.stdout.on('data', (data) => pushLog(data.toString()));
    mcProcess.stderr.on('data', (data) => pushLog(`[STDERR] ${data.toString()}`));
    mcProcess.on('close', (code) => {
      pushLog(`Minecraft 服务器进程已退出，退出码: ${code}`);
      mcProcess = null;
    });
    mcProcess.on('error', (err) => {
      pushLog(`启动失败: ${err.message}`);
      mcProcess = null;
    });
    return true;
  } catch (e) {
    pushLog(`启动异常: ${e.message}`);
    mcProcess = null;
    return false;
  }
}

function stopMinecraft() {
  if (!mcProcess) return false;
  try {
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
    const { fullCommand, workingDir, javaPath, jarPath, minMemory, maxMemory, additionalArgs } = req.body;
    if (fullCommand !== undefined) config.fullCommand = fullCommand;
    if (workingDir !== undefined) config.workingDir = workingDir;
    if (javaPath !== undefined) config.javaPath = javaPath;
    if (jarPath !== undefined) config.jarPath = jarPath;
    if (minMemory !== undefined) config.minMemory = minMemory;
    if (maxMemory !== undefined) config.maxMemory = maxMemory;
    if (additionalArgs !== undefined) config.additionalArgs = additionalArgs;
    saveConfig();
    res.json({ success: true, message: '配置已保存' });
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
}

loadConfig();

module.exports = { setupRoutes, loadConfig };
