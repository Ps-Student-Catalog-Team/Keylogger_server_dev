const fs = require('fs');
const path = require('path');
const McServer = require('./mc_server');

class McServerManager {
  constructor(dbPool, baseDir = process.cwd(), eventCallback = null) {
    this.servers = new Map();
    this.dbPool = dbPool;
    this.baseDir = baseDir;
    this.eventCallback = typeof eventCallback === 'function' ? eventCallback : null;
  }

  emitEvent(serverId, event, payload) {
    if (!this.eventCallback) return;
    try {
      this.eventCallback(event, serverId, payload);
    } catch (e) {
      // ignore callback errors
    }
  }

  async loadFromDatabase() {
    if (!this.dbPool) return;
    try {
      const [rows] = await this.dbPool.execute('SELECT * FROM mc_servers');
      for (const row of rows) {
        const rowId = row && row.id ? row.id : '(unknown)';
        const rowName = row && row.name ? row.name : '';
        let cfg = {};
        if (typeof row.config === 'string') {
          if (row.config.trim()) {
            try {
              cfg = JSON.parse(row.config);
            } catch (e) {
              console.warn(`mc_servers[${rowId}] config JSON 解析失败，已使用默认配置: ${e.message}`);
              cfg = {};
            }
          }
        } else if (Buffer.isBuffer(row.config)) {
          try {
            const text = row.config.toString('utf8');
            cfg = text.trim() ? JSON.parse(text) : {};
          } catch (e) {
            console.warn(`mc_servers[${rowId}] config Buffer 解析失败，已使用默认配置: ${e.message}`);
            cfg = {};
          }
        } else if (typeof row.config === 'object' && row.config !== null) {
          cfg = row.config;
        }
        if (typeof cfg !== 'object' || cfg === null) cfg = {};
        if (!cfg.name) cfg.name = rowName || String(rowId);
        if (!cfg.display_name) cfg.display_name = row.display_name || cfg.name;

        let srv;
        try {
          srv = new McServer(row.id, cfg, this.baseDir, (event, serverId, payload) => this.emitEvent(serverId, event, payload));
        } catch (e) {
          console.warn(`mc_servers[${rowId}] 实例创建失败，已跳过该记录: ${e.message}`);
          continue;
        }

        this.servers.set(String(row.id), srv);
        if (row.auto_start) {
          setImmediate(async () => {
            try {
              await srv.start(false);
            } catch (e) {
              console.warn(`mc_servers[${rowId}] 自动启动失败: ${e.message}`);
            }
          });
        }
      }
    } catch (e) {
      console.warn('加载 mc_servers 表失败:', e.message);
    }
  }

  getServer(id) {
    if (!id) return null;
    return this.servers.get(String(id));
  }

  getAllServersInfo() {
    return Array.from(this.servers.entries()).map(([id, s]) => ({
      id,
      name: s.config.display_name || s.config.name || id,
      status: s.getStatus()
    }));
  }

  async createServer(name, config = {}) {
    if (!this.dbPool) throw new Error('数据库未配置');
    const payload = Object.assign({}, config, {
      name,
      display_name: config.display_name || name
    });
    const [result] = await this.dbPool.execute(
      'INSERT INTO mc_servers (name, display_name, config, auto_start) VALUES (?, ?, ?, ?)',
      [name, payload.display_name, JSON.stringify(payload), payload.auto_start || payload.autoStart ? 1 : 0]
    );
    const id = result.insertId;
    const srv = new McServer(id, payload, this.baseDir, (event, serverId, payloadData) => this.emitEvent(serverId, event, payloadData));
    this.servers.set(String(id), srv);
    return srv;
  }

  async updateServer(id, data = {}) {
    const sid = String(id);
    const server = this.servers.get(sid);
    if (!server) throw new Error('MC 服务器不存在');
    const updates = [];
    const params = [];

    if (data.name !== undefined) {
      server.config.name = data.name;
      updates.push('name = ?');
      params.push(data.name);
    }
    if (data.display_name !== undefined) {
      server.config.display_name = data.display_name;
      updates.push('display_name = ?');
      params.push(data.display_name);
    }
    if (data.config !== undefined) {
      server.setConfig(data.config);
      updates.push('config = ?');
      params.push(JSON.stringify(server.config));
    }
    if (data.auto_start !== undefined) {
      updates.push('auto_start = ?');
      params.push(data.auto_start ? 1 : 0);
    }

    if (updates.length > 0 && this.dbPool) {
      params.push(id);
      await this.dbPool.execute(`UPDATE mc_servers SET ${updates.join(', ')} WHERE id = ?`, params);
    }

    return server;
  }

  async deleteServer(id, options = { removeFiles: false }) {
    const sid = String(id);
    const srv = this.servers.get(sid);
    if (srv && srv.process) {
      try { srv.kill(); } catch (e) { }
    }
    if (this.dbPool) {
      await this.dbPool.execute('DELETE FROM mc_servers WHERE id = ?', [id]);
    }
    // 可选地删除服务器相关备份、日志与工作目录（谨慎）
    if (options && options.removeFiles && srv) {
      try {
        const backupDir = srv.resolveBackupDir ? srv.resolveBackupDir() : path.join(this.baseDir, 'backups', sid);
        const logDir = srv.logDir || path.join(this.baseDir, 'logs', 'mc', sid);
        const workDir = srv.resolveWorkingDir ? srv.resolveWorkingDir() : null;
        if (backupDir && fs.existsSync(backupDir)) {
          try { fs.rmSync(backupDir, { recursive: true, force: true }); } catch (e) { }
        }
        if (logDir && fs.existsSync(logDir)) {
          try { fs.rmSync(logDir, { recursive: true, force: true }); } catch (e) { }
        }
        // 仅在明确配置了自定义工作目录且该目录位于 baseDir 的子目录时才删除，防止误删重要路径
        if (workDir && path.resolve(workDir).startsWith(path.resolve(this.baseDir))) {
          try { fs.rmSync(workDir, { recursive: true, force: true }); } catch (e) { }
        }
      } catch (e) {
        // ignore file deletion errors
      }
    }

    this.servers.delete(sid);
    return true;
  }
}

module.exports = McServerManager;
