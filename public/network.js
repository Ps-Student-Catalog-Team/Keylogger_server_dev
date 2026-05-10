const express = require('express');
const net = require('net');

/**
 * 返回一个 Express Router，负责处理 /auth/check 和网络名单管理接口
 * @param {import('mysql2/promise').Pool} pool - 数据库连接池
 * @param {import('winston').Logger} logger - 日志记录器
 * @returns {express.Router}
 */
module.exports = function(pool, logger) {
    const router = express.Router();
    const isValidIp = ip => net.isIP(ip) !== 0;

    router.get('/auth/check', async (req, res) => {
        try {
            let ip = req.socket.remoteAddress || req.ip || '';
            ip = String(ip).replace(/^::ffff:/, '');

            logger.debug(`[network] /auth/check 检查 IP: ${ip}`);

            if (!isValidIp(ip)) {
                logger.warn(`[network] 非法 IP 地址: ${ip}`);
                return res.status(400).json(false);
            }

            const [rows] = await pool.execute(
                'SELECT 1 FROM network_ips WHERE ip = ? LIMIT 1',
                [ip]
            );

            const isValid = rows.length > 0;
            logger.debug(`[network] IP ${ip} 是否允许: ${isValid}`);
            res.json(isValid);
        } catch (error) {
            logger.error(`[network] /auth/check 错误: ${error.message}`);
            res.status(500).json(false);
        }
    });

    router.get('/network/list', async (req, res) => {
        try {
            const [rows] = await pool.execute(
                'SELECT id, ip, tags, created_at FROM network_ips ORDER BY created_at DESC'
            );
            const result = rows.map(row => ({
                id: row.id,
                ip: row.ip,
                tags: row.tags ? JSON.parse(row.tags) : [],
                createdAt: row.created_at
            }));
            res.json(result);
        } catch (error) {
            logger.error(`[network] /network/list 错误: ${error.message}`);
            res.status(500).json({ error: '无法加载网络名单' });
        }
    });

    router.post('/network', async (req, res) => {
        try {
            const { ip, tags } = req.body;
            if (!ip || !isValidIp(String(ip).trim())) {
                return res.status(400).json({ error: '无效的 IP 地址' });
            }
            const normalizedIp = String(ip).trim();
            const tagArray = Array.isArray(tags) ? tags.map(String).filter(Boolean) : (tags ? [String(tags).trim()] : []);

            await pool.execute(
                `INSERT INTO network_ips (ip, tags) VALUES (?, ?)
                 ON DUPLICATE KEY UPDATE tags = VALUES(tags)`,
                [normalizedIp, JSON.stringify(tagArray)]
            );

            res.json({ success: true });
        } catch (error) {
            logger.error(`[network] POST /network 错误: ${error.message}`);
            res.status(500).json({ error: '无法保存网络配置' });
        }
    });

    router.delete('/network/:id', async (req, res) => {
        try {
            const id = parseInt(req.params.id, 10);
            if (Number.isNaN(id)) {
                return res.status(400).json({ error: '无效的记录 ID' });
            }
            await pool.execute('DELETE FROM network_ips WHERE id = ?', [id]);
            res.json({ success: true });
        } catch (error) {
            logger.error(`[network] DELETE /network/${req.params.id} 错误: ${error.message}`);
            res.status(500).json({ error: '无法删除网络配置' });
        }
    });

    return router;
};