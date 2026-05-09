const express = require('express');

/**
 * 返回一个 Express Router，负责处理 /auth/check 等网络相关接口
 * @param {import('mysql2/promise').Pool} pool - 数据库连接池
 * @param {import('winston').Logger} logger - 日志记录器
 * @returns {express.Router}
 */
module.exports = function(pool, logger) {
    const router = express.Router();

    router.get('/auth/check', async (req, res) => {
        try {
            // 提取客户端 IP，处理 IPv6 映射前缀
            let ip = req.ip || req.connection.remoteAddress || '';
            ip = ip.replace(/^::ffff:/, '');

            logger.debug(`[network] 检查 IP: ${ip}`);

            // 查询 known_clients 表中是否存在该 IP
            const [rows] = await pool.execute(
                'SELECT 1 FROM known_clients WHERE ip = ? LIMIT 1',
                [ip]
            );

            const isValid = rows.length > 0;

            logger.debug(`[network] IP ${ip} 存在于已知客户端: ${isValid}`);

            res.json({isValid });
        } catch (error) {
            logger.error(`[network] /auth/check 错误: ${error.message}`);
            res.status(500).json({ valid: false, error: '服务器内部错误' });
        }
    });

    return router;
};