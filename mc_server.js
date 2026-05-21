const fs = require('fs');
const path = require('path');
const os = require('os');
const { spawn } = require('child_process');

const LOG_MAX_LINES = 2000;
const PLAYER_COUNT_REGEX = /There are\s+(\d+)\s+of\s+a\s+max\s+of\s+(\d+)\s+players\s+online/i;
const PLAYER_LIST_REGEX = /^(?:\[.*?\]\s*)?\[?\s*([^\]]*?)\s*\]?$/;
const TPS_REGEX = /TPS\s+from\s+last\s+.*?:\s*([\d.]+)/i;

class McServer {
  constructor(id, config = {}, baseDir = process.cwd(), eventCallback = null) {
    this.id = String(id || 'default');
    this.baseDir = baseDir;
    this.eventCallback = typeof eventCallback === 'function' ? eventCallback : null;
    this.config = Object.assign({
      name: this.id,
      display_name: this.id,
      fullCommand: '',
      workingDir: baseDir,
      javaPath: 'java',
      jarPath: 'server.jar',
      minMemory: '1024M',
      maxMemory: '4096M',
      additionalArgs: '',
      backupDir: 'backups',
      autoBackupEnabled: false,
      autoBackupCron: '',
      backupRetentionCount: 7,
      backupRetentionDays: 30,
      autoRestart: false,
      autoRestartDelaySeconds: 5,
      autoRestartMaxRetries: 3,
      playerListIntervalSeconds: 0
    }, config || {});

    this.logs = [];
    this.process = null;
    this.playerInfo = { players: [], count: 0, max: 0 };
    this.latestTps = null;
    this.manualStopRequested = false;
    this.restartAttempts = 0;
    this.playerListTimer = null;
    this.autoBackupTimer = null;
    this.lastAutoBackupKey = null;
    this.backupInProgress = false;
    this.logDir = path.join(this.baseDir, 'logs', 'mc', this.id);
    this.logFile = path.join(this.logDir, 'latest.log');
    this.configureAutoTasks();
  }

  emit(event, payload = {}) {
    if (!this.eventCallback) return;
    try {
      this.eventCallback(event, this.id, payload);
    } catch (e) {
      // ignore callback errors
    }
  }

  setConfig(config = {}) {
    this.config = Object.assign({}, this.config, config);
    if (config.name) this.config.name = config.name;
    if (config.display_name) this.config.display_name = config.display_name;
    if (config.backupDir !== undefined) this.config.backupDir = config.backupDir;
    this.configureAutoTasks();
    return this.config;
  }

  configureAutoTasks() {
    this.stopAutoBackup();
    if (!this.config.autoBackupEnabled || !String(this.config.autoBackupCron || '').trim()) {
      return;
    }
    this.autoBackupTimer = setInterval(async () => {
      if (!this.config.autoBackupEnabled || !this.config.autoBackupCron) return;
      const now = new Date();
      if (!this.isCronScheduleDue(this.config.autoBackupCron, now)) return;
      const key = this.getAutoBackupKey(now);
      if (key === this.lastAutoBackupKey) return;
      this.lastAutoBackupKey = key;
      await this.runScheduledBackup();
    }, 30 * 1000);
  }

  parseCronField(field, value, min, max) {
    if (field === '*') return true;
    if (field.includes(',')) {
      return field.split(',').some((part) => this.parseCronField(part.trim(), value, min, max));
    }
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

  isCronScheduleDue(cronExpression, now) {
    const parts = String(cronExpression || '').trim().split(/\s+/);
    if (parts.length !== 5) return false;
    const [minuteExpr, hourExpr, dayExpr, monthExpr, dowExpr] = parts;
    return this.parseCronField(minuteExpr, now.getMinutes(), 0, 59)
      && this.parseCronField(hourExpr, now.getHours(), 0, 23)
      && this.parseCronField(dayExpr, now.getDate(), 1, 31)
      && this.parseCronField(monthExpr, now.getMonth() + 1, 1, 12)
      && this.parseCronField(dowExpr, now.getDay(), 0, 6);
  }

  getAutoBackupKey(now) {
    return `${now.getFullYear()}-${now.getMonth() + 1}-${now.getDate()}-${now.getHours()}-${now.getMinutes()}`;
  }

  stopAutoBackup() {
    if (this.autoBackupTimer) {
      clearInterval(this.autoBackupTimer);
      this.autoBackupTimer = null;
    }
  }

  async runScheduledBackup() {
    if (this.backupInProgress) return;
    this.backupInProgress = true;
    try {
      const fileName = await this.createBackup();
      this.pushLog(`自动备份完成: ${fileName}`);
    } catch (e) {
      this.pushLog(`自动备份失败: ${e.message}`);
    } finally {
      this.backupInProgress = false;
    }
  }

  startPlayerListPolling() {
    this.stopPlayerListPolling();
    const intervalSeconds = Number(this.config.playerListIntervalSeconds) || 0;
    if (!intervalSeconds || !this.process || !this.process.stdin || this.process.stdin.destroyed) return;
    this.playerListTimer = setInterval(() => {
      if (this.process && this.process.stdin && !this.process.stdin.destroyed) {
        this.sendCommand('list');
      }
    }, intervalSeconds * 1000);
  }

  stopPlayerListPolling() {
    if (this.playerListTimer) {
      clearInterval(this.playerListTimer);
      this.playerListTimer = null;
    }
  }

  scheduleAutoRestart() {
    if (!this.config.autoRestart || this.manualStopRequested) return;
    const maxRetries = Number(this.config.autoRestartMaxRetries) || 0;
    if (this.restartAttempts >= maxRetries) {
      this.pushLog('已达到最大自动重启次数，不再继续重启');
      return;
    }
    const delay = Math.max(1, Number(this.config.autoRestartDelaySeconds) || 5);
    const backoff = Math.min(delay * Math.pow(2, this.restartAttempts), 60);
    this.restartAttempts += 1;
    this.pushLog(`将在 ${backoff} 秒后自动重启（${this.restartAttempts}/${maxRetries}）`);
    this.autoRestartTimer = setTimeout(() => {
      this.autoRestartTimer = null;
      if (!this.process) {
        this.start(false);
      }
    }, backoff * 1000);
  }

  stopAutoRestart() {
    if (this.autoRestartTimer) {
      clearTimeout(this.autoRestartTimer);
      this.autoRestartTimer = null;
    }
  }

  waitForProcessClose(timeoutMs = 15000) {
    if (!this.process) return Promise.resolve();
    return new Promise((resolve) => {
      const processRef = this.process;
      const onClose = () => {
        clearTimeout(timer);
        resolve();
      };
      const timer = setTimeout(() => {
        processRef.removeListener('close', onClose);
        resolve();
      }, timeoutMs);
      processRef.once('close', onClose);
    });
  }

  getLaunchCommand() {
    const cmd = String(this.config.fullCommand || '').trim();
    if (cmd) return cmd;
    const javaPath = String(this.config.javaPath || 'java').trim();
    const jarPath = String(this.config.jarPath || 'server.jar').trim();
    const minMemory = String(this.config.minMemory || '1024M').trim();
    const maxMemory = String(this.config.maxMemory || '4096M').trim();
    const args = String(this.config.additionalArgs || '').trim();
    if (!jarPath) return '';
    return `${javaPath} -Xms${minMemory} -Xmx${maxMemory} -jar ${jarPath} nogui ${args}`.trim();
  }

  resolveWorkingDir() {
    return path.isAbsolute(this.config.workingDir || '') ? this.config.workingDir : path.join(this.baseDir, String(this.config.workingDir || ''));
  }

  resolveBackupDir() {
    const backupDir = this.config.backupDir || 'backups';
    return path.isAbsolute(backupDir) ? backupDir : path.join(this.baseDir, backupDir);
  }

  ensureDir(dir) {
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  }

  ensureLogDir() {
    this.ensureDir(this.logDir);
  }

  pushLog(line) {
    const normalized = String(line || '').replace(/\r?\n$/, '');
    if (!normalized) return;
    const formatted = `${new Date().toISOString()} ${normalized}`;
    this.logs.push(formatted);
    while (this.logs.length > LOG_MAX_LINES) this.logs.shift();
    this.ensureLogDir();
    fs.promises.appendFile(this.logFile, formatted + os.EOL).catch(() => {});

    const level = this.classifyLogLevel(normalized);
    this.updatePlayerInfoFromLine(normalized);
    this.updateTpsFromLine(normalized);
    this.emit('mc_log', { line: normalized, level });
  }

  getLogs(limit = 200) {
    return this.logs.slice(-limit);
  }

  classifyLogLevel(text) {
    const upper = String(text || '').toUpperCase();
    if (upper.includes('[SEVERE]') || upper.includes('[ERROR]') || upper.includes('[STDERR]')) return 'error';
    if (upper.includes('[WARN]') || upper.includes('[WARNING]') || upper.includes(' WARN ')) return 'warn';
    if (upper.includes('[INFO]')) return 'info';
    return 'info';
  }

  updatePlayerInfoFromLine(line) {
    const countMatch = line.match(PLAYER_COUNT_REGEX);
    if (countMatch) {
      this.playerInfo.count = parseInt(countMatch[1], 10) || 0;
      this.playerInfo.max = parseInt(countMatch[2], 10) || 0;
      this.emit('mc_players', { players: this.playerInfo.players, count: this.playerInfo.count, max: this.playerInfo.max });
      return;
    }
    if (line.trim().startsWith('[')) {
      const listMatch = line.match(PLAYER_LIST_REGEX);
      if (listMatch) {
        const raw = listMatch[1].trim();
        if (raw === '' || raw === '[]') {
          this.playerInfo.players = [];
        } else {
          const players = raw.replace(/^\[|\]$/g, '').split(/,\s*/).map((name) => name.replace(/^"|"$/g, '').trim()).filter(Boolean);
          this.playerInfo.players = players;
        }
        this.emit('mc_players', { players: this.playerInfo.players, count: this.playerInfo.players.length, max: this.playerInfo.max });
      }
    }
  }

  updateTpsFromLine(line) {
    const tpsMatch = line.match(TPS_REGEX);
    if (tpsMatch) {
      const tps = parseFloat(tpsMatch[1]);
      if (!Number.isNaN(tps)) {
        this.latestTps = tps;
        this.emit('mc_stats', { cpu: null, memory: null, tps: tps });
      }
    }
  }

  start(manual = true) {
    if (this.process) return false;
    const command = this.getLaunchCommand();
    if (!command) {
      this.pushLog('启动命令未配置，无法启动');
      return false;
    }
    const cwd = this.resolveWorkingDir();
    this.ensureLogDir();

    try {
      this.manualStopRequested = false;
      if (manual) this.restartAttempts = 0;
      this.process = spawn(command, [], { cwd, shell: true, windowsHide: true });
      this.pushLog(`启动命令: ${command}`);

      if (this.process.stdout) {
        this.process.stdout.on('data', (data) => this.pushLog(data.toString()));
      }
      if (this.process.stderr) {
        this.process.stderr.on('data', (data) => this.pushLog('[STDERR] ' + data.toString()));
      }

      this.process.on('close', (code) => {
        this.pushLog(`进程已退出，退出码: ${code}`);
        this.process = null;
        this.stopPlayerListPolling();
        if (!this.manualStopRequested && this.config.autoRestart) {
          this.scheduleAutoRestart();
        }
      });
      this.process.on('error', (err) => {
        this.pushLog(`启动失败: ${err.message}`);
        this.process = null;
      });

      this.startPlayerListPolling();
      return true;
    } catch (e) {
      this.pushLog(`启动异常: ${e.message}`);
      this.process = null;
      return false;
    }
  }

  stop() {
    if (!this.process) return false;
    try {
      this.manualStopRequested = true;
      this.stopPlayerListPolling();
      this.stopAutoRestart();
      if (this.process.stdin && !this.process.stdin.destroyed) {
        this.process.stdin.write('stop\n');
      }
      this.pushLog('已发送 stop 命令');
      return true;
    } catch (e) {
      this.pushLog(`发送 stop 失败: ${e.message}`);
      return false;
    }
  }

  kill() {
    if (!this.process) return false;
    try {
      this.manualStopRequested = true;
      this.stopPlayerListPolling();
      this.stopAutoRestart();
      const pid = this.process.pid;
      if (!pid) return false;
      if (process.platform === 'win32') {
        spawn('taskkill', ['/pid', String(pid), '/f', '/t'], { windowsHide: true });
      } else {
        try {
          process.kill(pid, 'SIGTERM');
        } catch (e) {
          spawn('kill', ['-TERM', String(pid)], { windowsHide: true });
        }
      }
      this.pushLog('已强制终止进程');
      this.process = null;
      return true;
    } catch (e) {
      this.pushLog(`强制终止失败: ${e.message}`);
      return false;
    }
  }

  sendCommand(cmd) {
    if (!cmd || !this.process) return false;
    try {
      if (this.process.stdin && !this.process.stdin.destroyed) {
        this.process.stdin.write(cmd + '\n');
        this.pushLog('> ' + cmd);
        return true;
      }
      return false;
    } catch (e) {
      this.pushLog(`发送命令失败: ${e.message}`);
      return false;
    }
  }

  getStatus() {
    const running = this.process !== null;
    const pid = this.process ? this.process.pid : null;
    const recovered = this.process && this.process.recovered === true;
    return { id: this.id, running, pid, recovered, latestTps: this.latestTps };
  }

  async createBackup() {
    const backupDir = this.resolveBackupDir();
    this.ensureDir(backupDir);
    const cwd = this.resolveWorkingDir();
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const idPart = (this.config && this.config.name) ? String(this.config.name).replace(/[^a-zA-Z0-9-_]/g, '_') : this.id;
    const filename = process.platform === 'win32' ? `backup-${idPart}-${timestamp}.zip` : `backup-${idPart}-${timestamp}.tar.gz`;
    const dest = path.join(backupDir, filename);
    const worldDirs = ['world', 'world_nether', 'world_the_end']
      .map((dir) => path.join(cwd, dir))
      .filter((dirPath) => fs.existsSync(dirPath));

    if (worldDirs.length === 0) {
      throw new Error('未找到任何 world 目录可备份');
    }

    await this.safeBackupWorlds(worldDirs, dest, cwd);
    this.cleanupOldBackups();
    return filename;
  }

  async listBackups() {
    const backupDir = this.resolveBackupDir();
    if (!fs.existsSync(backupDir)) return [];
    return fs.readdirSync(backupDir)
      .filter((name) => name.endsWith('.zip') || name.endsWith('.tar.gz'))
      .map((name) => {
        const filePath = path.join(backupDir, name);
        const st = fs.statSync(filePath);
        return { name, size: st.size, mtime: st.mtimeMs };
      })
      .sort((a, b) => b.mtime - a.mtime);
  }

  getBackupPath(name) {
    return path.join(this.resolveBackupDir(), path.basename(name));
  }

  async restoreBackup(name) {
    const backupPath = this.getBackupPath(name);
    if (!fs.existsSync(backupPath)) {
      throw new Error('备份文件不存在');
    }
    if (this.process) {
      this.stop();
      await this.waitForProcessClose(15000);
      if (this.process) {
        this.kill();
        await this.waitForProcessClose(5000);
      }
    }
    await this.extractBackupArchive(backupPath, this.resolveWorkingDir());
    this.start();
    return true;
  }

  async createBackupArchive(worldDirs, dest, cwd) {
    if (process.platform === 'win32') {
      const quotedPaths = worldDirs.map((dir) => `'${dir.replace(/'/g, "''")}'`).join(', ');
      const quotedDest = dest.replace(/'/g, "''");
      await this.runChildProcess('powershell.exe', [
        '-NoProfile',
        '-NonInteractive',
        '-Command',
        `Compress-Archive -Path ${quotedPaths} -DestinationPath '${quotedDest}' -Force`
      ], { cwd });
      return;
    }
    await this.runChildProcess('tar', ['-czf', dest, ...worldDirs], { cwd });
  }

  async extractBackupArchive(file, cwd) {
    if (file.toLowerCase().endsWith('.zip')) {
      if (process.platform === 'win32') {
        const quotedFile = file.replace(/'/g, "''");
        await this.runChildProcess('powershell.exe', [
          '-NoProfile',
          '-NonInteractive',
          '-Command',
          `Expand-Archive -Path '${quotedFile}' -DestinationPath '${cwd}' -Force`
        ], { cwd });
        return;
      }
      await this.runChildProcess('unzip', ['-o', file, '-d', cwd], { cwd });
      return;
    }
    await this.runChildProcess('tar', ['-xzf', file, '-C', cwd], { cwd });
  }

  async runChildProcess(command, args, options = {}) {
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

  async safeBackupWorlds(worldDirs, dest, cwd) {
    let saveOffSent = false;
    if (this.process) {
      if (this.process.recovered === true) {
        this.pushLog('检测到恢复的进程；跳过自动备份以避免不一致的世界快照');
        throw new Error('进程处于恢复模式，无法执行安全备份');
      }
      this.pushLog('正在执行 save-off/save-all 同步世界数据，以开始安全备份');
      saveOffSent = this.sendCommand('save-off');
      if (!saveOffSent) {
        this.pushLog('警告: save-off 命令发送失败，备份期间数据可能不一致');
      }
      this.sendCommand('save-all');
      await new Promise((resolve) => setTimeout(resolve, 3000));
    }

    try {
      await this.createBackupArchive(worldDirs, dest, cwd);
    } finally {
      if (saveOffSent && this.process) {
        this.sendCommand('save-on');
        this.pushLog('已恢复自动保存 (save-on)');
      }
    }
  }

  cleanupOldBackups() {
    try {
      const backupDir = this.resolveBackupDir();
      this.ensureDir(backupDir);
      const files = fs.readdirSync(backupDir).filter((name) => /\.(tar\.gz|zip)$/i.test(name));
      let list = files.map((name) => {
        const filePath = path.join(backupDir, name);
        const st = fs.statSync(filePath);
        return { name, path: filePath, mtime: st.mtimeMs };
      }).sort((a, b) => b.mtime - a.mtime);

      const now = Date.now();
      if (Number.isFinite(this.config.backupRetentionDays) && this.config.backupRetentionDays > 0) {
        const cutoff = now - this.config.backupRetentionDays * 24 * 60 * 60 * 1000;
        for (const item of list) {
          if (item.mtime < cutoff) {
            try { fs.unlinkSync(item.path); } catch (e) { }
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

      if (Number.isFinite(this.config.backupRetentionCount) && this.config.backupRetentionCount > 0) {
        list.slice(this.config.backupRetentionCount).forEach((item) => {
          try { fs.unlinkSync(item.path); } catch (e) { }
        });
      }
    } catch (e) {
      // ignore cleanup errors
    }
  }

  // 更通用的玩家解析，兼容多种服务端输出格式
  parsePlayerListLine(line) {
    const text = String(line || '').replace(/§[0-9A-FK-OR]/gi, '').trim();
    const patterns = [
      /There are\s+(\d+)\s+of\s+a\s+max\s+of\s+(\d+)\s+players\s+online:?\s*(.*)/i,
      /当前在线\s*(\d+)\s*名?玩家[\s\S]*?最大\s*(\d+)\s*名?在线:?:?\s*(.*)/,
      /There are (\d+)\/([0-9]+) players online:?\s*(.*)/i,
    ];
    for (const rx of patterns) {
      const m = text.match(rx);
      if (m) {
        const count = parseInt(m[1], 10) || 0;
        const max = parseInt(m[2], 10) || 0;
        const players = m[3] ? m[3].replace(/^\[|\]$/g, '').split(/,\s*/).map(p => p.replace(/^"|"$/g, '').trim()).filter(Boolean) : [];
        return { count, max, players };
      }
    }
    return null;
  }
}

module.exports = McServer;
