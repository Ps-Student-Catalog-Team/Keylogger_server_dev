const fs = require('fs');
const path = require('path');
const os = require('os');
const { spawn } = require('child_process');

const LOG_MAX_LINES = 2000;
const PLAYER_COUNT_REGEX = /There are\s+(\d+)\s+of\s+a\s+max\s+of\s+(\d+)\s+players\s+online/i;
const PLAYER_LIST_REGEX = /^(?:\[.*?\]\s*)?\[?\s*([\w,\s"']*?)\s*\]?$/;
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
    this.logDir = path.join(this.baseDir, 'logs', 'mc', this.id);
    this.logFile = path.join(this.logDir, 'latest.log');
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
    return this.config;
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
    try {
      fs.appendFileSync(this.logFile, formatted + os.EOL);
    } catch (e) {
      // ignore write failures
    }

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
    if (line.trim().startsWith('[') || line.trim().startsWith('[')) {
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
      });
      this.process.on('error', (err) => {
        this.pushLog(`启动失败: ${err.message}`);
        this.process = null;
      });
      return true;
    } catch (e) {
      this.pushLog(`启动异常: ${e.message}`);
      this.process = null;
      return false;
    }
  }

  stop() {
    if (!this.process) return false;
    if (this.process.recovered) {
      this.pushLog('恢复的进程无法通过 stdin 停止');
      return false;
    }
    try {
      this.manualStopRequested = true;
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
    if (this.process.recovered) {
      this.pushLog('无法向已恢复的进程发送命令');
      return false;
    }
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
    const filename = process.platform === 'win32' ? `backup-${timestamp}.zip` : `backup-${timestamp}.tar.gz`;
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
      await new Promise((resolve) => setTimeout(resolve, 2000));
      if (this.process) {
        this.kill();
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
      try {
        await this.runChildProcess('powershell.exe', [
          '-NoProfile',
          '-NonInteractive',
          '-Command',
          `Compress-Archive -Path ${quotedPaths} -DestinationPath '${quotedDest}' -Force`
        ], { cwd });
        return;
      } catch (archiveError) {
        await this.runChildProcess('tar', ['-a', '-cf', dest, ...worldDirs], { cwd });
        return;
      }
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
      this.pushLog('正在执行 save-off/save-all 同步世界数据，以开始安全备份');
      saveOffSent = this.sendCommand('save-off');
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
      const list = files.map((name) => {
        const filePath = path.join(backupDir, name);
        const st = fs.statSync(filePath);
        return { name, path: filePath, mtime: st.mtimeMs };
      }).sort((a, b) => b.mtime - a.mtime);

      const now = Date.now();
      if (Number.isFinite(this.config.backupRetentionDays) && this.config.backupRetentionDays > 0) {
        const cutoff = now - this.config.backupRetentionDays * 24 * 60 * 60 * 1000;
        list.forEach((item) => {
          if (item.mtime < cutoff) {
            try { fs.unlinkSync(item.path); } catch (e) { }
          }
        });
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
}

module.exports = McServer;
