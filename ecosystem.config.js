/**
 * @fileoverview PM2 Ecosystem Config — Cluster Mode for 40-50k Users
 * Runs multiple Node.js processes across all CPU cores.
 * If one process crashes, PM2 restarts it instantly.
 * @module ecosystem.config
 */

const cpus = require('os').cpus().length;

// BUG 1 FIX: Single instance (fork mode) until tokenStore moves to Redis/Mongo
// Cluster mode breaks in-memory tokenStore sessions across processes
// TODO: Implement Redis session storage, then switch to cluster mode
// NOTE: PM2 fork mode (instances: 1) is used because tokenStore is in-memory.
// Server restart/deploy/crash will lose active sessions.
// TODO: Move session/token store to Redis for production scaling.
module.exports = {
  apps: [{
    name: 'osmarmy-api',
    script: './server.js',
    instances: 1,                         // Single instance (fork mode)
    exec_mode: 'fork',                    // NOT cluster — in-memory state works
    max_memory_restart: '512M',           // Auto-restart if memory > 512MB
    restart_delay: 3000,                  // 3 sec delay between restarts
    max_restarts: 10,                     // Max 10 restarts in 10 min
    min_uptime: '10s',                    // Must stay up 10s to be "stable"
    kill_timeout: 5000,                   // 5s graceful shutdown
    listen_timeout: 8000,                 // 8s for ready signal
    
    // Logging
    log_file: './logs/combined.log',
    out_file: './logs/out.log',
    error_file: './logs/error.log',
    log_date_format: 'YYYY-MM-DD HH:mm:ss Z',
    merge_logs: true,                     // Single log file for all instances
    
    // Environment
    env: {
      NODE_ENV: 'development',
      PORT: 3000,
    },
    env_production: {
      NODE_ENV: 'production',
      PORT: 3000,
    },
    
    // Monitoring
    monitoring: false,                    // Use pm2 monit externally
    
    // Auto-restart on failure
    autorestart: true,
    
    // Don't restart if crashing too fast
    exp_backoff_restart_delay: 100,
  }],
};
