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

  parseStoredConfig(rawConfig) {
    let cfg = {};
    if (typeof rawConfig === 'string') {
      if (rawConfig.trim()) {
        try {
          cfg = JSON.parse(rawConfig);
        } catch (e) {
          console.warn(`mc_servers config JSON 解析失败，已使用默认配置: ${e.message}`);
          cfg = {};
        }
      }
    } else if (Buffer.isBuffer(rawConfig)) {
      try {
        const text = rawConfig.toString('utf8');
        cfg = text.trim() ? JSON.parse(text) : {};
      } catch (e) {
        console.warn(`mc_servers config Buffer 解析失败，已使用默认配置: ${e.message}`);
        cfg = {};
      }
    } else if (typeof rawConfig === 'object' && rawConfig !== null) {
      cfg = rawConfig;
    }
    return typeof cfg === 'object' && cfg !== null ? cfg : {};
  }

  parseBoolean(value) {
    if (value === true || value === 1 || value === '1' || String(value).toLowerCase() === 'true') {
      return true;
    }
    return false;
  }

  normalizeConfigInput(config) {
    if (typeof config === 'string') {
      try {
        return JSON.parse(config);
      } catch (e) {
        throw new Error('config JSON 解析失败');
      }
    }
    if (typeof config !== 'object' || config === null) {
      throw new Error('config 必须为对象');
    }
    return config;
  }

  async loadFromDatabase() {
    if (!this.dbPool) return;
    try {
      const [rows] = await this.dbPool.execute('SELECT * FROM mc_servers');
      for (const row of rows) {
        const rowId = row && row.id ? row.id : '(unknown)';
        const rowName = row && row.name ? row.name : '';
        let cfg = this.parseStoredConfig(row.config);
        if (!cfg.name) cfg.name = rowName || String(rowId);
        if (!cfg.display_name) cfg.display_name = row.display_name || cfg.name;
        cfg.auto_start = this.parseBoolean(row.auto_start);

        let srv;
        try {
          srv = new McServer(row.id, cfg, this.baseDir, (event, serverId, payload) => this.emitEvent(serverId, event, payload));
        } catch (e) {
          console.warn(`mc_servers[${rowId}] 实例创建失败，已跳过该记录: ${e.message}`);
          continue;
        }

        this.servers.set(String(row.id), srv);
        if (this.parseBoolean(row.auto_start)) {
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
    console.debug('[mc_manager] createServer called', { name, config });
    const normalizedConfig = this.normalizeConfigInput(config || {});
    const basePayload = Object.assign({}, normalizedConfig, {
      name,
      display_name: normalizedConfig.display_name || name
    });

    // 尝试插入，若 name 唯一索引冲突则自动生成带后缀的唯一 name 重试
    let attempt = 0;
    let attemptName = String(name);
    while (attempt < 10) {
      const payload = Object.assign({}, basePayload, { name: attemptName });
      payload.auto_start = this.parseBoolean(payload.auto_start || payload.autoStart);
      try {
        console.debug('[mc_manager] inserting mc_server', { attemptName, payload });
        const [result] = await this.dbPool.execute(
          'INSERT INTO mc_servers (name, display_name, config, auto_start) VALUES (?, ?, ?, ?)',
          [attemptName, payload.display_name, JSON.stringify(payload), payload.auto_start ? 1 : 0]
        );
        console.debug('[mc_manager] insert result', { insertId: result && result.insertId });
        const id = result.insertId;
        const srv = new McServer(id, payload, this.baseDir, (event, serverId, payloadData) => this.emitEvent(serverId, event, payloadData));
        this.servers.set(String(id), srv);
        return srv;
      } catch (e) {
        console.error('[mc_manager] createServer error', e && (e.stack || e.message));
        const msg = String(e && e.message || '').toLowerCase();
        if (msg.includes('duplicate') || e && e.code === 'ER_DUP_ENTRY') {
          attempt += 1;
          attemptName = `${String(name)}-${attempt}`;
          continue;
        }
        throw e;
      }
    }
    throw new Error('无法创建 MC 服务器：name 重复冲突（尝试多次失败）');
  }

  async updateServer(id, data = {}) {
    console.debug('[mc_manager] updateServer called', { id, data });
    const sid = String(id);
    const server = this.servers.get(sid);
    if (!server) throw new Error('MC 服务器不存在');
    const updates = [];
    const params = [];

    if (data.name !== undefined) {
      server.config.name = String(data.name);
      updates.push('name = ?');
      params.push(server.config.name);
    }
    if (data.display_name !== undefined) {
      server.config.display_name = String(data.display_name);
      updates.push('display_name = ?');
      params.push(server.config.display_name);
    }
    if (data.config !== undefined) {
      const normalizedConfig = this.normalizeConfigInput(data.config);
      server.setConfig(normalizedConfig);
      updates.push('config = ?');
      params.push(JSON.stringify(server.config));
    }
    if (data.auto_start !== undefined || data.autoStart !== undefined) {
      const autoStartValue = this.parseBoolean(data.auto_start !== undefined ? data.auto_start : data.autoStart);
      server.config.auto_start = autoStartValue;
      updates.push('auto_start = ?');
      params.push(autoStartValue ? 1 : 0);
    }

    if (updates.length > 0 && this.dbPool) {
      params.push(id);
      console.debug('[mc_manager] updateServer SQL', { updates, params });
      try {
        await this.dbPool.execute(`UPDATE mc_servers SET ${updates.join(', ')} WHERE id = ?`, params);
        console.debug('[mc_manager] updateServer completed', { id });
      } catch (e) {
        console.error('[mc_manager] updateServer error', e && (e.stack || e.message));
        throw e;
      }
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
