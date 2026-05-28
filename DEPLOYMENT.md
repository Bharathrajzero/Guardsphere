# GuardSphere - Production Deployment Checklist

## 🚀 Pre-Deployment

### System Requirements
- [ ] Python 3.9+ installed
- [ ] 2GB+ RAM available
- [ ] 10GB+ disk space
- [ ] Port 8080 available (or custom port)
- [ ] SSL certificate ready (for HTTPS)

### Security Hardening
- [ ] Change default HOST from 127.0.0.1 to 0.0.0.0 in .env
- [ ] Set strong rate limits (default: 100/min)
- [ ] Configure max payload size limits
- [ ] Enable all detection features
- [ ] Set up reverse proxy (nginx/Caddy) with HTTPS
- [ ] Configure firewall rules (allow only 443/80)
- [ ] Disable directory listing on web server

### Configuration
- [ ] Review and update .env file
- [ ] Set APP_ENV=production
- [ ] Configure LOG_LEVEL=INFO (or WARNING for less verbosity)
- [ ] Set appropriate MAX_EVENTS limit
- [ ] Configure database path (ensure writable)

---

## 🔧 Deployment Steps

### Option 1: Systemd Service (Linux)

1. Create service file: `/etc/systemd/system/guardsphere.service`

```ini
[Unit]
Description=GuardSphere AI Firewall
After=network.target

[Service]
Type=simple
User=guardsphere
WorkingDirectory=/opt/guardsphere
Environment="PATH=/opt/guardsphere/venv/bin"
ExecStart=/opt/guardsphere/venv/bin/python main.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

2. Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable guardsphere
sudo systemctl start guardsphere
sudo systemctl status guardsphere
```

### Option 2: Docker Production

1. Build production image:
```bash
docker build -t guardsphere:production .
```

2. Run with production settings:
```bash
docker run -d \
  --name guardsphere \
  --restart unless-stopped \
  -p 8080:8080 \
  -v /opt/guardsphere/data:/app/data \
  -e APP_ENV=production \
  -e LOG_LEVEL=INFO \
  guardsphere:production
```

3. Set up log rotation:
```bash
docker run -d \
  --log-driver json-file \
  --log-opt max-size=10m \
  --log-opt max-file=3 \
  # ... rest of options
```

### Option 3: Docker Compose

```bash
# Production deployment
docker-compose -f docker-compose.yml up -d

# Check status
docker-compose ps

# View logs
docker-compose logs -f --tail=100
```

---

## 🔐 Reverse Proxy Setup

### nginx Configuration

```nginx
upstream guardsphere {
    server 127.0.0.1:8080;
    keepalive 32;
}

server {
    listen 80;
    server_name guardsphere.yourdomain.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name guardsphere.yourdomain.com;

    ssl_certificate /etc/ssl/certs/guardsphere.crt;
    ssl_certificate_key /etc/ssl/private/guardsphere.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;

    # Rate limiting
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
    limit_req zone=api burst=20 nodelay;

    location / {
        proxy_pass http://guardsphere;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_buffering off;
        proxy_request_buffering off;
    }

    # Health check endpoint (no auth)
    location /health {
        proxy_pass http://guardsphere;
        access_log off;
    }
}
```

### Caddy Configuration (Simpler Alternative)

```caddyfile
guardsphere.yourdomain.com {
    reverse_proxy localhost:8080
    
    header {
        Strict-Transport-Security "max-age=31536000"
        X-Frame-Options "SAMEORIGIN"
        X-Content-Type-Options "nosniff"
    }
    
    rate_limit {
        zone api {
            key {remote_host}
            events 100
            window 1m
        }
    }
}
```

---

## 📊 Monitoring Setup

### Health Check Monitoring

```bash
# Add to crontab for uptime monitoring
*/5 * * * * curl -f http://localhost:8080/health || echo "GuardSphere down!" | mail -s "Alert" admin@company.com
```

### Prometheus Metrics (Future)

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'guardsphere'
    static_configs:
      - targets: ['localhost:8080']
    metrics_path: '/metrics'
    scrape_interval: 30s
```

### Log Monitoring

```bash
# Monitor for critical events
tail -f guardsphere.log | grep -i "CRITICAL\|ERROR"

# Count blocked requests per hour
grep "BLOCKED" guardsphere.log | awk '{print $1" "$2}' | cut -d: -f1 | uniq -c
```

---

## 🔔 Alert Configuration

### Email Alerts

1. Navigate to Settings in dashboard
2. Set "Alert Email" to: `security@company.com`
3. Configure SMTP (requires custom integration)

### Webhook Alerts (Slack/Teams)

1. Create incoming webhook in Slack/Teams
2. Navigate to Settings in dashboard
3. Set "Webhook URL" to your webhook endpoint
4. Test with a blocked request

Example webhook payload:
```json
{
  "text": "🚨 GuardSphere Alert",
  "attachments": [{
    "color": "danger",
    "fields": [
      {"title": "Event", "value": "Prompt Injection Blocked"},
      {"title": "Severity", "value": "CRITICAL"},
      {"title": "IP", "value": "192.168.1.100"},
      {"title": "Rule", "value": "Instruction override"}
    ]
  }]
}
```

---

## 💾 Backup Strategy

### Database Backup

```bash
# Daily backup script
#!/bin/bash
BACKUP_DIR="/opt/guardsphere/backups"
DATE=$(date +%Y%m%d_%H%M%S)
cp /opt/guardsphere/guardsphere.db "$BACKUP_DIR/guardsphere_$DATE.db"

# Keep only last 30 days
find $BACKUP_DIR -name "guardsphere_*.db" -mtime +30 -delete
```

Add to crontab:
```bash
0 2 * * * /opt/guardsphere/backup.sh
```

### Configuration Backup

```bash
# Backup .env and custom rules
tar -czf guardsphere_config_$(date +%Y%m%d).tar.gz .env guardsphere.db
```

---

## 🔍 Performance Tuning

### Database Optimization

```bash
# Vacuum database monthly
sqlite3 guardsphere.db "VACUUM;"

# Analyze for query optimization
sqlite3 guardsphere.db "ANALYZE;"
```

### Application Tuning

```python
# In .env, adjust:
MAX_EVENTS=1000        # Increase for more history
LOG_LEVEL=WARNING      # Reduce logging overhead
```

### System Resources

```bash
# Increase file descriptors
ulimit -n 65536

# Monitor resource usage
htop
iotop
```

---

## 🧪 Post-Deployment Testing

### Run Test Suite

```bash
# Install test dependencies
pip install requests

# Run comprehensive tests
python test_api.py
```

### Manual Verification

1. [ ] Dashboard loads at https://yourdomain.com
2. [ ] All 6 navigation tabs work (Overview, Threat Intel, Analytics, Audit, Policy, Settings)
3. [ ] Test prompt gateway with injection sample
4. [ ] Verify event appears in Audit Ledger
5. [ ] Check metrics update in real-time
6. [ ] Export CSV/JSON from Audit Ledger
7. [ ] Create and delete test policy rule
8. [ ] Update settings and verify persistence
9. [ ] Test rate limiting (send 105+ requests)
10. [ ] Verify health endpoint: `curl https://yourdomain.com/health`

---

## 📈 Scaling Considerations

### Horizontal Scaling

For high-traffic deployments:

1. **Load Balancer**: Use nginx/HAProxy to distribute traffic
2. **Shared Database**: Migrate from SQLite to PostgreSQL
3. **Redis Cache**: Add Redis for rate limiting across instances
4. **Session Affinity**: Enable sticky sessions if needed

### Vertical Scaling

- Increase MAX_EVENTS for more history
- Add more CPU cores (FastAPI is async)
- Increase RAM for larger in-memory caches

---

## 🚨 Incident Response

### High CPU Usage

```bash
# Check process
top -p $(pgrep -f "python main.py")

# Review recent events
tail -100 guardsphere.log

# Restart if needed
systemctl restart guardsphere
```

### Database Corruption

```bash
# Backup current DB
cp guardsphere.db guardsphere.db.backup

# Check integrity
sqlite3 guardsphere.db "PRAGMA integrity_check;"

# If corrupted, restore from backup
cp /opt/guardsphere/backups/guardsphere_YYYYMMDD.db guardsphere.db
```

### Memory Leak

```bash
# Monitor memory over time
watch -n 5 'ps aux | grep "python main.py"'

# Restart service
systemctl restart guardsphere
```

---

## 📋 Maintenance Schedule

### Daily
- [ ] Check health endpoint
- [ ] Review critical logs
- [ ] Monitor disk space

### Weekly
- [ ] Review Threat Intelligence dashboard
- [ ] Analyze blocked patterns
- [ ] Update custom policy rules if needed
- [ ] Check backup integrity

### Monthly
- [ ] Vacuum database
- [ ] Review and rotate logs
- [ ] Update dependencies: `pip install -U -r requirements.txt`
- [ ] Review and adjust rate limits
- [ ] Export audit data for compliance

### Quarterly
- [ ] Security audit
- [ ] Performance review
- [ ] Capacity planning
- [ ] Update documentation

---

## 🆘 Support & Troubleshooting

### Common Issues

**Issue**: Dashboard not loading
- Check if service is running: `systemctl status guardsphere`
- Check logs: `tail -f guardsphere.log`
- Verify port is open: `netstat -tlnp | grep 8080`

**Issue**: High latency
- Check database size: `ls -lh guardsphere.db`
- Reduce MAX_EVENTS in .env
- Run VACUUM on database

**Issue**: Rate limiting too aggressive
- Navigate to Settings → Increase "Rate Limit"
- Or edit .env: `RATE_LIMIT=200`

### Getting Help

1. Check logs: `guardsphere.log`
2. Review health endpoint: `/health`
3. Run test suite: `python test_api.py`
4. Check GitHub Issues
5. Review README.md and QUICKSTART.md

---

## ✅ Go-Live Checklist

- [ ] All pre-deployment checks completed
- [ ] Application deployed and running
- [ ] Reverse proxy configured with HTTPS
- [ ] Health monitoring enabled
- [ ] Backups configured and tested
- [ ] Alerts configured (email/webhook)
- [ ] Test suite passes 100%
- [ ] Manual verification completed
- [ ] Documentation updated
- [ ] Team trained on dashboard usage
- [ ] Incident response plan documented
- [ ] Maintenance schedule established

---

**🎉 Congratulations! GuardSphere is production-ready!**

Monitor the dashboard regularly and review the Threat Intelligence section to stay ahead of emerging attack patterns.
