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
        let cfg = {};
        try { cfg = JSON.parse(row.config || '{}'); } catch (e) { cfg = {}; }
        const srv = new McServer(row.id, cfg, this.baseDir, (event, serverId, payload) => this.emitEvent(serverId, event, payload));
        this.servers.set(String(row.id), srv);
        if (row.auto_start) {
          setImmediate(() => srv.start(false));
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

  async deleteServer(id) {
    const sid = String(id);
    const srv = this.servers.get(sid);
    if (srv && srv.process) {
      try { srv.kill(); } catch (e) { }
    }
    if (this.dbPool) {
      await this.dbPool.execute('DELETE FROM mc_servers WHERE id = ?', [id]);
    }
    this.servers.delete(sid);
    return true;
  }
}

module.exports = McServerManager;
