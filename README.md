# OWASP ZAP Security Scanner with Docker

This repository provides Docker Compose configurations to run OWASP ZAP (Zed Attack Proxy) security scans against web applications. It includes setups for both local testing with OWASP Juice Shop and scanning external websites.

## 🔗 GitHub Pages

This project is hosted on GitHub Pages: [https://absjabed.github.io/cyber-sec-101-owasp-zap](https://absjabed.github.io/cyber-sec-101-owasp-zap)

## 📋 Prerequisites

- Docker and Docker Compose installed
- Basic understanding of web security testing
- Terminal/Command line access

## 🚀 Quick Start

### Option 1: Scan OWASP Juice Shop (Local Testing)

Perfect for learning and testing ZAP capabilities on a vulnerable application.

1. **Clone this repository:**
   ```bash
   git clone https://github.com/absjabed/cyber-sec-101-owasp-zap.git
   cd cyber-sec-101-owasp-zap
   ```

2. **Run Juice Shop with ZAP scan:**
   ```bash
   # Use the juice-shop docker-compose file
   docker compose -f docker-compose-juiceshop.yml up
   ```

3. **Access reports:**
   - Reports will be generated in `./zap-reports/`
   - Open `zap-report.html` in your browser to view results

### Option 2: Scan Any External Website

Scan any publicly accessible website for security vulnerabilities.

1. **Make the script executable:**
   ```bash
   chmod +x run-zap-scan.sh
   ```

2. **Run a baseline scan (recommended for beginners):**
   ```bash
   ./run-zap-scan.sh https://example.com baseline
   ```

3. **Run a full scan (comprehensive but slower):**
   ```bash
   ./run-zap-scan.sh https://example.com full
   ```

## 📁 Project Structure

```
├── docker-compose.yml              # Main compose file for external scans
├── docker-compose-juiceshop.yml    # Compose file for Juice Shop testing
├── run-zap-scan.sh                 # Helper script for external scans
├── zap-reports/                    # Generated scan reports
│   ├── zap-report.html
│   ├── zap-report.md
│   └── zap-report.json
└── README.md                       # This file
```

## 🔧 Configuration Options

### Scan Types

- **Baseline Scan**: Fast, passive scanning with minimal false positives
- **Full Scan**: Comprehensive active scanning (may take longer and could impact target site)

### Environment Variables

| Variable | Description | Default | Example |
|----------|-------------|---------|---------|
| `TARGET_URL` | Website URL to scan | `https://example.com` | `https://dev-journal.netlify.app` |
| `SCAN_TYPE` | Type of scan to perform | `baseline` | `baseline` or `full` |

## 📊 Understanding Reports

ZAP generates three types of reports:

1. **HTML Report** (`zap-report.html`)
   - Web-friendly format with visual charts
   - Best for sharing with stakeholders

2. **Markdown Report** (`zap-report.md`)
   - Text-based format
   - Great for documentation and version control

3. **JSON Report** (`zap-report.json`)
   - Machine-readable format
   - Perfect for automation and CI/CD integration

### Vulnerability Levels

- 🔴 **High**: Critical security issues requiring immediate attention
- 🟡 **Medium**: Important security concerns that should be addressed
- 🔵 **Low**: Minor issues or best practice recommendations
- ℹ️ **Informational**: General information about the application

## 🛠️ Advanced Usage

### Manual Docker Commands

If you prefer not to use the helper script:

```bash
# Set environment variables
export TARGET_URL=https://your-website.com
export SCAN_TYPE=baseline

# Run the scan
docker compose up
```

### Custom Scan Parameters

You can modify the Docker Compose files to add additional ZAP parameters:

```yaml
# Example: Add custom timeout
command: |
  zap-baseline.py -t "$TARGET_URL" -r /zap/wrk/reports/zap-report.html -T 60
```

## 🔒 Security Considerations

⚠️ **Important**: Always ensure you have permission to scan target websites. Unauthorized security testing may be illegal.

### Best Practices:
- Only scan websites you own or have explicit permission to test
- Use baseline scans for production environments
- Schedule full scans during maintenance windows
- Review and understand all findings before taking action

## 🐛 Troubleshooting

### Common Issues:

1. **"Connection refused" error**
   - Ensure the target URL is accessible
   - Check if the website blocks automated tools

2. **Reports not generated**
   - Verify the `./zap-reports/` directory exists
   - Check Docker container logs: `docker logs zap-scanner`

3. **Slow scan performance**
   - Try baseline scan instead of full scan
   - Check your network connection
   - Consider target website's response time

### Getting Help:

```bash
# View ZAP help
docker run --rm ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -h

# Check container logs
docker logs zap-scanner
```

## 📚 Learning Resources

- [OWASP ZAP Documentation](https://www.zaproxy.org/docs/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Web Application Security Testing](https://owasp.org/www-project-web-security-testing-guide/)

## 🤝 Contributing

1. Fork this repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⭐ Acknowledgments

- [OWASP ZAP Team](https://www.zaproxy.org/) for the amazing security testing tool
- [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/) for providing a safe testing environment
- Docker community for containerization support

---

**Happy Security Testing! 🛡️**

> Remember: Security is not a destination, it's a journey. Regular scanning helps maintain a secure application.