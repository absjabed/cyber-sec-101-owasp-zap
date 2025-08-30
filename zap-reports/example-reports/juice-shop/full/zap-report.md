# ZAP Scanning Report

ZAP by [Checkmarx](https://checkmarx.com/).


## Summary of Alerts

| Risk Level | Number of Alerts |
| --- | --- |
| High | 0 |
| Medium | 6 |
| Low | 5 |
| Informational | 6 |




## Alerts

| Name | Risk Level | Number of Instances |
| --- | --- | --- |
| Backup File Disclosure | Medium | 31 |
| Bypassing 403 | Medium | 6 |
| CORS Misconfiguration | Medium | 95 |
| Content Security Policy (CSP) Header Not Set | Medium | 11 |
| Cross-Domain Misconfiguration | Medium | 14 |
| Hidden File Found | Medium | 4 |
| Cross-Domain JavaScript Source File Inclusion | Low | 10 |
| Dangerous JS Functions | Low | 2 |
| Deprecated Feature Policy Header Set | Low | 14 |
| Insufficient Site Isolation Against Spectre Vulnerability | Low | 10 |
| Timestamp Disclosure - Unix | Low | 9 |
| Information Disclosure - Suspicious Comments | Informational | 2 |
| Modern Web Application | Informational | 11 |
| Non-Storable Content | Informational | 1 |
| Storable and Cacheable Content | Informational | 1 |
| Storable but Non-Cacheable Content | Informational | 11 |
| User Agent Fuzzer | Informational | 24 |




## Alert Detail



### [ Backup File Disclosure ](https://www.zaproxy.org/docs/alerts/10095/)



##### Medium (Medium)

### Description

A backup of the file was disclosed by the web server.

* URL: http://juice-shop:3000/ftp/quarantine%2520-%2520Copy
  * Method: `GET`
  * Parameter: ``
  * Attack: `http://juice-shop:3000/ftp/quarantine%20-%20Copy`
  * Evidence: ``
  * Other Info: `A backup of [http://juice-shop:3000/ftp/quarantine] is available at [http://juice-shop:3000/ftp/quarantine%20-%20Copy]`
* URL: http://juice-shop:3000/ftp/quarantine%2520-%2520Copy%2520(2&29
  * Method: `GET`
  * Parameter: ``
  * Attack: `http://juice-shop:3000/ftp/quarantine%20-%20Copy%20(2)`
  * Evidence: ``
  * Other Info: `A backup of [http://juice-shop:3000/ftp/quarantine] is available at [http://juice-shop:3000/ftp/quarantine%20-%20Copy%20(2)]`
* URL: http://juice-shop:3000/ftp/quarantine%2520-%2520Copy%2520(2&29/juicy_malware_linux_amd_64.url
  * Method: `GET`
  * Parameter: ``
  * Attack: `http://juice-shop:3000/ftp/quarantine%20-%20Copy%20(2)/juicy_malware_linux_amd_64.url`
  * Evidence: ``
  * Other Info: `A backup of [http://juice-shop:3000/ftp/quarantine/juicy_malware_linux_amd_64.url] is available at [http://juice-shop:3000/ftp/quarantine%20-%20Copy%20(2)/juicy_malware_linux_amd_64.url]`
* URL: http://juice-shop:3000/ftp/quarantine%2520-%2520Copy%2520(2&29/juicy_malware_linux_arm_64.url
  * Method: `GET`
  * Parameter: ``
  * Attack: `http://juice-shop:3000/ftp/quarantine%20-%20Copy%20(2)/juicy_malware_linux_arm_64.url`
  * Evidence: ``
  * Other Info: `A backup of [http://juice-shop:3000/ftp/quarantine/juicy_malware_linux_arm_64.url] is available at [http://juice-shop:3000/ftp/quarantine%20-%20Copy%20(2)/juicy_malware_linux_arm_64.url]`
* URL: http://juice-shop:3000/ftp/quarantine%2520-%2520Copy%2520(2&29/juicy_malware_macos_64.url
  * Method: `GET`
  * Parameter: ``
  * Attack: `http://juice-shop:3000/ftp/quarantine%20-%20Copy%20(2)/juicy_malware_macos_64.url`
  * Evidence: ``
  * Other Info: `A backup of [http://juice-shop:3000/ftp/quarantine/juicy_malware_macos_64.url] is available at [http://juice-shop:3000/ftp/quarantine%20-%20Copy%20(2)/juicy_malware_macos_64.url]`
* URL: http://juice-shop:3000/ftp/quarantine%2520-%2520Copy%2520(2&29/juicy_malware_windows_64.exe.url
  * Method: `GET`
  * Parameter: ``
  * Attack: `http://juice-shop:3000/ftp/quarantine%20-%20Copy%20(2)/juicy_malware_windows_64.exe.url`
  * Evidence: ``
  * Other Info: `A backup of [http://juice-shop:3000/ftp/quarantine/juicy_malware_windows_64.exe.url] is available at [http://juice-shop:3000/ftp/quarantine%20-%20Copy%20(2)/juicy_malware_windows_64.exe.url]`
* URL: http://juice-shop:3000/ftp/quarantine%2520-%2520Copy%2520(3&29
  * Method: `GET`
  * Parameter: ``
  * Attack: `http://juice-shop:3000/ftp/quarantine%20-%20Copy%20(3)`
  * Evidence: ``
  * Other Info: `A backup of [http://juice-shop:3000/ftp/quarantine] is available at [http://juice-shop:3000/ftp/quarantine%20-%20Copy%20(3)]`
* URL: http://juice-shop:3000/ftp/quarantine%2520-%2520Copy%2520(3&29/juicy_malware_linux_amd_64.url
  * Method: `GET`
  * Parameter: ``
  * Attack: `http://juice-shop:3000/ftp/quarantine%20-%20Copy%20(3)/juicy_malware_linux_amd_64.url`
  * Evidence: ``
  * Other Info: `A backup of [http://juice-shop:3000/ftp/quarantine/juicy_malware_linux_amd_64.url] is available at [http://juice-shop:3000/ftp/quarantine%20-%20Copy%20(3)/juicy_malware_linux_amd_64.url]`
* URL: http://juice-shop:3000/ftp/quarantine%2520-%2520Copy%2520(3&29/juicy_malware_linux_arm_64.url
  * Method: `GET`
  * Parameter: ``
  * Attack: `http://juice-shop:3000/ftp/quarantine%20-%20Copy%20(3)/juicy_malware_linux_arm_64.url`
  * Evidence: ``
  * Other Info: `A backup of [http://juice-shop:3000/ftp/quarantine/juicy_malware_linux_arm_64.url] is available at [http://juice-shop:3000/ftp/quarantine%20-%20Copy%20(3)/juicy_malware_linux_arm_64.url]`
* URL: http://juice-shop:3000/ftp/quarantine%2520-%2520Copy%2520(3&29/juicy_malware_macos_64.url
  * Method: `GET`
  * Parameter: ``
  * Attack: `http://juice-shop:3000/ftp/quarantine%20-%20Copy%20(3)/juicy_malware_macos_64.url`
  * Evidence: ``
  * Other Info: `A backup of [http://juice-shop:3000/ftp/quarantine/juicy_malware_macos_64.url] is available at [http://juice-shop:3000/ftp/quarantine%20-%20Copy%20(3)/juicy_malware_macos_64.url]`
* URL: http://juice-shop:3000/ftp/quarantine%2520-%2520Copy%2520(3&29/juicy_malware_windows_64.exe.url
  * Method: `GET`
  * Parameter: ``
  * Attack: `http://juice-shop:3000/ftp/quarantine%20-%20Copy%20(3)/juicy_malware_windows_64.exe.url`
  * Evidence: ``
  * Other Info: `A backup of [http://juice-shop:3000/ftp/quarantine/juicy_malware_windows_64.exe.url] is available at [http://juice-shop:3000/ftp/quarantine%20-%20Copy%20(3)/juicy_malware_windows_64.exe.url]`
* URL: http://juice-shop:3000/ftp/quarantine%2520-%2520Copy/juicy_malware_linux_amd_64.url
  * Method: `GET`
  * Parameter: ``
  * Attack: `http://juice-shop:3000/ftp/quarantine%20-%20Copy/juicy_malware_linux_amd_64.url`
  * Evidence: ``
  * Other Info: `A backup of [http://juice-shop:3000/ftp/quarantine/juicy_malware_linux_amd_64.url] is available at [http://juice-shop:3000/ftp/quarantine%20-%20Copy/juicy_malware_linux_amd_64.url]`
* URL: http://juice-shop:3000/ftp/quarantine%2520-%2520Copy/juicy_malware_linux_arm_64.url
  * Method: `GET`
  * Parameter: ``
  * Attack: `http://juice-shop:3000/ftp/quarantine%20-%20Copy/juicy_malware_linux_arm_64.url`
  * Evidence: ``
  * Other Info: `A backup of [http://juice-shop:3000/ftp/quarantine/juicy_malware_linux_arm_64.url] is available at [http://juice-shop:3000/ftp/quarantine%20-%20Copy/juicy_malware_linux_arm_64.url]`
* URL: http://juice-shop:3000/ftp/quarantine%2520-%2520Copy/juicy_malware_macos_64.url
  * Method: `GET`
  * Parameter: ``
  * Attack: `http://juice-shop:3000/ftp/quarantine%20-%20Copy/juicy_malware_macos_64.url`
  * Evidence: ``
  * Other Info: `A backup of [http://juice-shop:3000/ftp/quarantine/juicy_malware_macos_64.url] is available at [http://juice-shop:3000/ftp/quarantine%20-%20Copy/juicy_malware_macos_64.url]`
* URL: http://juice-shop:3000/ftp/quarantine%2520-%2520Copy/juicy_malware_windows_64.exe.url
  * Method: `GET`
  * Parameter: ``
  * Attack: `http://juice-shop:3000/ftp/quarantine%20-%20Copy/juicy_malware_windows_64.exe.url`
  * Evidence: ``
  * Other Info: `A backup of [http://juice-shop:3000/ftp/quarantine/juicy_malware_windows_64.exe.url] is available at [http://juice-shop:3000/ftp/quarantine%20-%20Copy/juicy_malware_windows_64.exe.url]`
* URL: http://juice-shop:3000/ftp/quarantine.bac
  * Method: `GET`
  * Parameter: ``
  * Attack: `http://juice-shop:3000/ftp/quarantine.bac`
  * Evidence: ``
  * Other Info: `A backup of [http://juice-shop:3000/ftp/quarantine] is available at [http://juice-shop:3000/ftp/quarantine.bac]`
* URL: http://juice-shop:3000/ftp/quarantine.backup
  * Method: `GET`
  * Parameter: ``
  * Attack: `http://juice-shop:3000/ftp/quarantine.backup`
  * Evidence: ``
  * Other Info: `A backup of [http://juice-shop:3000/ftp/quarantine] is available at [http://juice-shop:3000/ftp/quarantine.backup]`
* URL: http://juice-shop:3000/ftp/quarantine.bak
  * Method: `GET`
  * Parameter: ``
  * Attack: `http://juice-shop:3000/ftp/quarantine.bak`
  * Evidence: ``
  * Other Info: `A backup of [http://juice-shop:3000/ftp/quarantine] is available at [http://juice-shop:3000/ftp/quarantine.bak]`
* URL: http://juice-shop:3000/ftp/quarantine.jar
  * Method: `GET`
  * Parameter: ``
  * Attack: `http://juice-shop:3000/ftp/quarantine.jar`
  * Evidence: ``
  * Other Info: `A backup of [http://juice-shop:3000/ftp/quarantine] is available at [http://juice-shop:3000/ftp/quarantine.jar]`
* URL: http://juice-shop:3000/ftp/quarantine.log
  * Method: `GET`
  * Parameter: ``
  * Attack: `http://juice-shop:3000/ftp/quarantine.log`
  * Evidence: ``
  * Other Info: `A backup of [http://juice-shop:3000/ftp/quarantine] is available at [http://juice-shop:3000/ftp/quarantine.log]`
* URL: http://juice-shop:3000/ftp/quarantine.old
  * Method: `GET`
  * Parameter: ``
  * Attack: `http://juice-shop:3000/ftp/quarantine.old`
  * Evidence: ``
  * Other Info: `A backup of [http://juice-shop:3000/ftp/quarantine] is available at [http://juice-shop:3000/ftp/quarantine.old]`
* URL: http://juice-shop:3000/ftp/quarantine.swp
  * Method: `GET`
  * Parameter: ``
  * Attack: `http://juice-shop:3000/ftp/quarantine.swp`
  * Evidence: ``
  * Other Info: `A backup of [http://juice-shop:3000/ftp/quarantine] is available at [http://juice-shop:3000/ftp/quarantine.swp]`
* URL: http://juice-shop:3000/ftp/quarantine.tar
  * Method: `GET`
  * Parameter: ``
  * Attack: `http://juice-shop:3000/ftp/quarantine.tar`
  * Evidence: ``
  * Other Info: `A backup of [http://juice-shop:3000/ftp/quarantine] is available at [http://juice-shop:3000/ftp/quarantine.tar]`
* URL: http://juice-shop:3000/ftp/quarantine.zip
  * Method: `GET`
  * Parameter: ``
  * Attack: `http://juice-shop:3000/ftp/quarantine.zip`
  * Evidence: ``
  * Other Info: `A backup of [http://juice-shop:3000/ftp/quarantine] is available at [http://juice-shop:3000/ftp/quarantine.zip]`
* URL: http://juice-shop:3000/ftp/quarantine.~bk
  * Method: `GET`
  * Parameter: ``
  * Attack: `http://juice-shop:3000/ftp/quarantine.~bk`
  * Evidence: ``
  * Other Info: `A backup of [http://juice-shop:3000/ftp/quarantine] is available at [http://juice-shop:3000/ftp/quarantine.~bk]`
* URL: http://juice-shop:3000/ftp/quarantinebackup
  * Method: `GET`
  * Parameter: ``
  * Attack: `http://juice-shop:3000/ftp/quarantinebackup`
  * Evidence: ``
  * Other Info: `A backup of [http://juice-shop:3000/ftp/quarantine] is available at [http://juice-shop:3000/ftp/quarantinebackup]`
* URL: http://juice-shop:3000/ftp/quarantinebackup/juicy_malware_linux_amd_64.url
  * Method: `GET`
  * Parameter: ``
  * Attack: `http://juice-shop:3000/ftp/quarantinebackup/juicy_malware_linux_amd_64.url`
  * Evidence: ``
  * Other Info: `A backup of [http://juice-shop:3000/ftp/quarantine/juicy_malware_linux_amd_64.url] is available at [http://juice-shop:3000/ftp/quarantinebackup/juicy_malware_linux_amd_64.url]`
* URL: http://juice-shop:3000/ftp/quarantinebackup/juicy_malware_linux_arm_64.url
  * Method: `GET`
  * Parameter: ``
  * Attack: `http://juice-shop:3000/ftp/quarantinebackup/juicy_malware_linux_arm_64.url`
  * Evidence: ``
  * Other Info: `A backup of [http://juice-shop:3000/ftp/quarantine/juicy_malware_linux_arm_64.url] is available at [http://juice-shop:3000/ftp/quarantinebackup/juicy_malware_linux_arm_64.url]`
* URL: http://juice-shop:3000/ftp/quarantinebackup/juicy_malware_macos_64.url
  * Method: `GET`
  * Parameter: ``
  * Attack: `http://juice-shop:3000/ftp/quarantinebackup/juicy_malware_macos_64.url`
  * Evidence: ``
  * Other Info: `A backup of [http://juice-shop:3000/ftp/quarantine/juicy_malware_macos_64.url] is available at [http://juice-shop:3000/ftp/quarantinebackup/juicy_malware_macos_64.url]`
* URL: http://juice-shop:3000/ftp/quarantinebackup/juicy_malware_windows_64.exe.url
  * Method: `GET`
  * Parameter: ``
  * Attack: `http://juice-shop:3000/ftp/quarantinebackup/juicy_malware_windows_64.exe.url`
  * Evidence: ``
  * Other Info: `A backup of [http://juice-shop:3000/ftp/quarantine/juicy_malware_windows_64.exe.url] is available at [http://juice-shop:3000/ftp/quarantinebackup/juicy_malware_windows_64.exe.url]`
* URL: http://juice-shop:3000/ftp/quarantine~
  * Method: `GET`
  * Parameter: ``
  * Attack: `http://juice-shop:3000/ftp/quarantine~`
  * Evidence: ``
  * Other Info: `A backup of [http://juice-shop:3000/ftp/quarantine] is available at [http://juice-shop:3000/ftp/quarantine~]`

Instances: 31

### Solution

Do not edit files in-situ on the web server, and ensure that un-necessary files (including hidden files) are removed from the web server.

### Reference


* [ https://cwe.mitre.org/data/definitions/530.html ](https://cwe.mitre.org/data/definitions/530.html)
* [ https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information.html ](https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information.html)


#### CWE Id: [ 530 ](https://cwe.mitre.org/data/definitions/530.html)


#### WASC Id: 34

#### Source ID: 1

### [ Bypassing 403 ](https://www.zaproxy.org/docs/alerts/40038/)



##### Medium (Medium)

### Description

Bypassing 403 endpoints may be possible, the scan rule sent a payload that caused the response to be accessible (status code 200).

* URL: http://juice-shop:3000/%252e/ftp/coupons_2013.md.bak
  * Method: `GET`
  * Parameter: ``
  * Attack: `/%2e/ftp/coupons_2013.md.bak`
  * Evidence: ``
  * Other Info: `http://juice-shop:3000/ftp/coupons_2013.md.bak`
* URL: http://juice-shop:3000/%252e/ftp/eastere.gg
  * Method: `GET`
  * Parameter: ``
  * Attack: `/%2e/ftp/eastere.gg`
  * Evidence: ``
  * Other Info: `http://juice-shop:3000/ftp/eastere.gg`
* URL: http://juice-shop:3000/%252e/ftp/encrypt.pyc
  * Method: `GET`
  * Parameter: ``
  * Attack: `/%2e/ftp/encrypt.pyc`
  * Evidence: ``
  * Other Info: `http://juice-shop:3000/ftp/encrypt.pyc`
* URL: http://juice-shop:3000/%252e/ftp/package-lock.json.bak
  * Method: `GET`
  * Parameter: ``
  * Attack: `/%2e/ftp/package-lock.json.bak`
  * Evidence: ``
  * Other Info: `http://juice-shop:3000/ftp/package-lock.json.bak`
* URL: http://juice-shop:3000/%252e/ftp/package.json.bak
  * Method: `GET`
  * Parameter: ``
  * Attack: `/%2e/ftp/package.json.bak`
  * Evidence: ``
  * Other Info: `http://juice-shop:3000/ftp/package.json.bak`
* URL: http://juice-shop:3000/%252e/ftp/suspicious_errors.yml
  * Method: `GET`
  * Parameter: ``
  * Attack: `/%2e/ftp/suspicious_errors.yml`
  * Evidence: ``
  * Other Info: `http://juice-shop:3000/ftp/suspicious_errors.yml`

Instances: 6

### Solution



### Reference


* [ https://www.acunetix.com/blog/articles/a-fresh-look-on-reverse-proxy-related-attacks/ ](https://www.acunetix.com/blog/articles/a-fresh-look-on-reverse-proxy-related-attacks/)
* [ https://i.blackhat.com/us-18/Wed-August-8/us-18-Orange-Tsai-Breaking-Parser-Logic-Take-Your-Path-Normalization-Off-And-Pop-0days-Out-2.pdf ](https://i.blackhat.com/us-18/Wed-August-8/us-18-Orange-Tsai-Breaking-Parser-Logic-Take-Your-Path-Normalization-Off-And-Pop-0days-Out-2.pdf)
* [ https://www.contextis.com/en/blog/server-technologies-reverse-proxy-bypass ](https://www.contextis.com/en/blog/server-technologies-reverse-proxy-bypass)



#### Source ID: 1

### [ CORS Misconfiguration ](https://www.zaproxy.org/docs/alerts/40040/)



##### Medium (High)

### Description

This CORS misconfiguration could allow an attacker to perform AJAX queries to the vulnerable website from a malicious page loaded by the victim's user agent.
In order to perform authenticated AJAX queries, the server must specify the header "Access-Control-Allow-Credentials: true" and the "Access-Control-Allow-Origin" header must be set to null or the malicious page's domain. Even if this misconfiguration doesn't allow authenticated AJAX requests, unauthenticated sensitive content can still be accessed (e.g intranet websites).
A malicious page can belong to a malicious website but also a trusted website with flaws (e.g XSS, support of HTTP without TLS allowing code injection through MITM, etc).

* URL: http://juice-shop:3000
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: http://08iOCBb5.com`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: http://08iOCBb5.com`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/assets
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: http://08iOCBb5.com`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/assets/public
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: http://08iOCBb5.com`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: http://08iOCBb5.com`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/ftp
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: http://08iOCBb5.com`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/ftp/
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: http://08iOCBb5.com`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/ftp/acquisitions.md
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: http://08iOCBb5.com`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/ftp/announcement_encrypted.md
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: http://08iOCBb5.com`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/ftp/coupons_2013.md.bak
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: http://08iOCBb5.com`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/ftp/eastere.gg
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: http://08iOCBb5.com`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/ftp/encrypt.pyc
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: http://08iOCBb5.com`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/ftp/incident-support.kdbx
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: http://08iOCBb5.com`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/ftp/legal.md
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: http://08iOCBb5.com`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/ftp/package-lock.json.bak
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: http://08iOCBb5.com`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/ftp/package.json.bak
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: http://08iOCBb5.com`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/ftp/quarantine
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: http://08iOCBb5.com`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/ftp/quarantine/juicy_malware_linux_amd_64.url
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: http://08iOCBb5.com`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/ftp/quarantine/juicy_malware_linux_arm_64.url
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: http://08iOCBb5.com`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/ftp/quarantine/juicy_malware_macos_64.url
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: http://08iOCBb5.com`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/ftp/quarantine/juicy_malware_windows_64.exe.url
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: http://08iOCBb5.com`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/ftp/suspicious_errors.yml
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: http://08iOCBb5.com`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/juice-shop
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: http://08iOCBb5.com`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/juice-shop/build
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: http://08iOCBb5.com`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/juice-shop/build/routes
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: http://08iOCBb5.com`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/juice-shop/build/routes/assets
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: http://08iOCBb5.com`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/juice-shop/build/routes/assets/public
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: http://08iOCBb5.com`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/juice-shop/build/routes/assets/public/assets
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: http://08iOCBb5.com`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/juice-shop/build/routes/assets/public/assets/public
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: http://08iOCBb5.com`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/juice-shop/build/routes/assets/public/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: http://08iOCBb5.com`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/juice-shop/build/routes/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: http://08iOCBb5.com`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/juice-shop/build/routes/assets/public/main.js
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: http://08iOCBb5.com`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/juice-shop/build/routes/assets/public/polyfills.js
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: http://08iOCBb5.com`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/juice-shop/build/routes/assets/public/runtime.js
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: http://08iOCBb5.com`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/juice-shop/build/routes/assets/public/styles.css
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: http://08iOCBb5.com`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/juice-shop/build/routes/assets/public/vendor.js
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: http://08iOCBb5.com`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/juice-shop/build/routes/fileServer.js:43:13
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: http://08iOCBb5.com`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/juice-shop/build/routes/fileServer.js:59:18
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: http://08iOCBb5.com`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/juice-shop/build/routes/main.js
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: http://08iOCBb5.com`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/juice-shop/build/routes/polyfills.js
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: http://08iOCBb5.com`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/juice-shop/build/routes/runtime.js
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: http://08iOCBb5.com`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/juice-shop/build/routes/styles.css
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: http://08iOCBb5.com`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/juice-shop/build/routes/vendor.js
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: http://08iOCBb5.com`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/juice-shop/node_modules
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: http://08iOCBb5.com`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/juice-shop/node_modules/express
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: http://08iOCBb5.com`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/juice-shop/node_modules/express/lib
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: http://08iOCBb5.com`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/juice-shop/node_modules/express/lib/router
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: http://08iOCBb5.com`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/juice-shop/node_modules/express/lib/router/assets
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: http://08iOCBb5.com`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/juice-shop/node_modules/express/lib/router/assets/public
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: http://08iOCBb5.com`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/juice-shop/node_modules/express/lib/router/assets/public/assets
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: http://08iOCBb5.com`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/juice-shop/node_modules/express/lib/router/assets/public/assets/public
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: http://08iOCBb5.com`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/juice-shop/node_modules/express/lib/router/assets/public/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: http://08iOCBb5.com`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/juice-shop/node_modules/express/lib/router/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: http://08iOCBb5.com`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/juice-shop/node_modules/express/lib/router/assets/public/main.js
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: http://08iOCBb5.com`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/juice-shop/node_modules/express/lib/router/assets/public/polyfills.js
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: http://08iOCBb5.com`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/juice-shop/node_modules/express/lib/router/assets/public/runtime.js
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: http://08iOCBb5.com`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/juice-shop/node_modules/express/lib/router/assets/public/styles.css
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: http://08iOCBb5.com`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/juice-shop/node_modules/express/lib/router/assets/public/vendor.js
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: http://08iOCBb5.com`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/juice-shop/node_modules/express/lib/router/index.js:280:10
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: http://08iOCBb5.com`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/juice-shop/node_modules/express/lib/router/index.js:286:9
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: http://08iOCBb5.com`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/juice-shop/node_modules/express/lib/router/index.js:328:13
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: http://08iOCBb5.com`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/juice-shop/node_modules/express/lib/router/index.js:365:14
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: http://08iOCBb5.com`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/juice-shop/node_modules/express/lib/router/index.js:376:14
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: http://08iOCBb5.com`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/juice-shop/node_modules/express/lib/router/index.js:421:3
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: http://08iOCBb5.com`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/juice-shop/node_modules/express/lib/router/layer.js:95:5
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: http://08iOCBb5.com`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/juice-shop/node_modules/express/lib/router/main.js
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: http://08iOCBb5.com`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/juice-shop/node_modules/express/lib/router/polyfills.js
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: http://08iOCBb5.com`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/juice-shop/node_modules/express/lib/router/runtime.js
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: http://08iOCBb5.com`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/juice-shop/node_modules/express/lib/router/styles.css
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: http://08iOCBb5.com`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/juice-shop/node_modules/express/lib/router/vendor.js
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: http://08iOCBb5.com`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/juice-shop/node_modules/serve-index
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: http://08iOCBb5.com`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/juice-shop/node_modules/serve-index/assets
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: http://08iOCBb5.com`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/juice-shop/node_modules/serve-index/assets/public
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: http://08iOCBb5.com`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/juice-shop/node_modules/serve-index/assets/public/assets
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: http://08iOCBb5.com`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/juice-shop/node_modules/serve-index/assets/public/assets/public
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: http://08iOCBb5.com`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/juice-shop/node_modules/serve-index/assets/public/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: http://08iOCBb5.com`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/juice-shop/node_modules/serve-index/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: http://08iOCBb5.com`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/juice-shop/node_modules/serve-index/assets/public/main.js
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: http://08iOCBb5.com`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/juice-shop/node_modules/serve-index/assets/public/polyfills.js
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: http://08iOCBb5.com`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/juice-shop/node_modules/serve-index/assets/public/runtime.js
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: http://08iOCBb5.com`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/juice-shop/node_modules/serve-index/assets/public/styles.css
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: http://08iOCBb5.com`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/juice-shop/node_modules/serve-index/assets/public/vendor.js
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: http://08iOCBb5.com`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/juice-shop/node_modules/serve-index/index.js:145:39
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: http://08iOCBb5.com`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/juice-shop/node_modules/serve-index/main.js
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: http://08iOCBb5.com`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/juice-shop/node_modules/serve-index/polyfills.js
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: http://08iOCBb5.com`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/juice-shop/node_modules/serve-index/runtime.js
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: http://08iOCBb5.com`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/juice-shop/node_modules/serve-index/styles.css
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: http://08iOCBb5.com`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/juice-shop/node_modules/serve-index/vendor.js
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: http://08iOCBb5.com`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/main.js
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: http://08iOCBb5.com`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/polyfills.js
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: http://08iOCBb5.com`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/robots.txt
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: http://08iOCBb5.com`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/runtime.js
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: http://08iOCBb5.com`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/sitemap.xml
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: http://08iOCBb5.com`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/styles.css
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: http://08iOCBb5.com`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/vendor.js
  * Method: `GET`
  * Parameter: ``
  * Attack: `origin: http://08iOCBb5.com`
  * Evidence: ``
  * Other Info: ``

Instances: 95

### Solution

If a web resource contains sensitive information, the origin should be properly specified in the Access-Control-Allow-Origin header. Only trusted websites needing this resource should be specified in this header, with the most secured protocol supported.

### Reference


* [ https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS ](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS)
* [ https://portswigger.net/web-security/cors ](https://portswigger.net/web-security/cors)


#### CWE Id: [ 942 ](https://cwe.mitre.org/data/definitions/942.html)


#### WASC Id: 14

#### Source ID: 1

### [ Content Security Policy (CSP) Header Not Set ](https://www.zaproxy.org/docs/alerts/10038/)



##### Medium (High)

### Description

Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.

* URL: http://juice-shop:3000
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/ftp
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/ftp/coupons_2013.md.bak
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/ftp/eastere.gg
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/ftp/encrypt.pyc
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/ftp/package-lock.json.bak
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/ftp/package.json.bak
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/ftp/suspicious_errors.yml
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/juice-shop/build/routes/fileServer.js:43:13
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/sitemap.xml
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``

Instances: 11

### Solution

Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.

### Reference


* [ https://developer.mozilla.org/en-US/docs/Web/Security/CSP/Introducing_Content_Security_Policy ](https://developer.mozilla.org/en-US/docs/Web/Security/CSP/Introducing_Content_Security_Policy)
* [ https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html ](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html)
* [ https://www.w3.org/TR/CSP/ ](https://www.w3.org/TR/CSP/)
* [ https://w3c.github.io/webappsec-csp/ ](https://w3c.github.io/webappsec-csp/)
* [ https://web.dev/articles/csp ](https://web.dev/articles/csp)
* [ https://caniuse.com/#feat=contentsecuritypolicy ](https://caniuse.com/#feat=contentsecuritypolicy)
* [ https://content-security-policy.com/ ](https://content-security-policy.com/)


#### CWE Id: [ 693 ](https://cwe.mitre.org/data/definitions/693.html)


#### WASC Id: 15

#### Source ID: 3

### [ Cross-Domain Misconfiguration ](https://www.zaproxy.org/docs/alerts/10098/)



##### Medium (Medium)

### Description

Web browser data loading may be possible, due to a Cross Origin Resource Sharing (CORS) misconfiguration on the web server.

* URL: http://juice-shop:3000
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: http://juice-shop:3000/
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: http://juice-shop:3000/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: http://juice-shop:3000/ftp
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: http://juice-shop:3000/ftp/acquisitions.md
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: http://juice-shop:3000/ftp/incident-support.kdbx
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: http://juice-shop:3000/ftp/legal.md
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: http://juice-shop:3000/main.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: http://juice-shop:3000/polyfills.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: http://juice-shop:3000/robots.txt
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: http://juice-shop:3000/runtime.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: http://juice-shop:3000/sitemap.xml
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: http://juice-shop:3000/styles.css
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`
* URL: http://juice-shop:3000/vendor.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Access-Control-Allow-Origin: *`
  * Other Info: `The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.`

Instances: 14

### Solution

Ensure that sensitive data is not available in an unauthenticated manner (using IP address white-listing, for instance).
Configure the "Access-Control-Allow-Origin" HTTP header to a more restrictive set of domains, or remove all CORS headers entirely, to allow the web browser to enforce the Same Origin Policy (SOP) in a more restrictive manner.

### Reference


* [ https://vulncat.fortify.com/en/detail?id=desc.config.dotnet.html5_overly_permissive_cors_policy ](https://vulncat.fortify.com/en/detail?id=desc.config.dotnet.html5_overly_permissive_cors_policy)


#### CWE Id: [ 264 ](https://cwe.mitre.org/data/definitions/264.html)


#### WASC Id: 14

#### Source ID: 3

### [ Hidden File Found ](https://www.zaproxy.org/docs/alerts/40035/)



##### Medium (Low)

### Description

A sensitive file was identified as accessible or available. This may leak administrative, configuration, or credential information which can be leveraged by a malicious individual to further attack the system or conduct social engineering efforts.

* URL: http://juice-shop:3000/._darcs
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `HTTP/1.1 200 OK`
  * Other Info: ``
* URL: http://juice-shop:3000/.bzr
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `HTTP/1.1 200 OK`
  * Other Info: ``
* URL: http://juice-shop:3000/.hg
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `HTTP/1.1 200 OK`
  * Other Info: ``
* URL: http://juice-shop:3000/BitKeeper
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `HTTP/1.1 200 OK`
  * Other Info: ``

Instances: 4

### Solution

Consider whether or not the component is actually required in production, if it isn't then disable it. If it is then ensure access to it requires appropriate authentication and authorization, or limit exposure to internal systems or specific source IPs, etc.

### Reference


* [ https://blog.hboeck.de/archives/892-Introducing-Snallygaster-a-Tool-to-Scan-for-Secrets-on-Web-Servers.html ](https://blog.hboeck.de/archives/892-Introducing-Snallygaster-a-Tool-to-Scan-for-Secrets-on-Web-Servers.html)


#### CWE Id: [ 538 ](https://cwe.mitre.org/data/definitions/538.html)


#### WASC Id: 13

#### Source ID: 1

### [ Cross-Domain JavaScript Source File Inclusion ](https://www.zaproxy.org/docs/alerts/10017/)



##### Low (Medium)

### Description

The page includes one or more script files from a third-party domain.

* URL: http://juice-shop:3000
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: ``
* URL: http://juice-shop:3000
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js"></script>`
  * Other Info: ``
* URL: http://juice-shop:3000/
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: ``
* URL: http://juice-shop:3000/
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js"></script>`
  * Other Info: ``
* URL: http://juice-shop:3000/juice-shop/build/routes/fileServer.js:43:13
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: ``
* URL: http://juice-shop:3000/juice-shop/build/routes/fileServer.js:43:13
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js"></script>`
  * Other Info: ``
* URL: http://juice-shop:3000/juice-shop/build/routes/runtime.js
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: ``
* URL: http://juice-shop:3000/juice-shop/build/routes/runtime.js
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js"></script>`
  * Other Info: ``
* URL: http://juice-shop:3000/sitemap.xml
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: ``
* URL: http://juice-shop:3000/sitemap.xml
  * Method: `GET`
  * Parameter: `//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js`
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js"></script>`
  * Other Info: ``

Instances: 10

### Solution

Ensure JavaScript source files are loaded from only trusted sources, and the sources can't be controlled by end users of the application.

### Reference



#### CWE Id: [ 829 ](https://cwe.mitre.org/data/definitions/829.html)


#### WASC Id: 15

#### Source ID: 3

### [ Dangerous JS Functions ](https://www.zaproxy.org/docs/alerts/10110/)



##### Low (Low)

### Description

A dangerous JS function seems to be in use that would leave the site vulnerable.

* URL: http://juice-shop:3000/main.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `bypassSecurityTrustHtml(`
  * Other Info: ``
* URL: http://juice-shop:3000/vendor.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `bypassSecurityTrustHtml(`
  * Other Info: ``

Instances: 2

### Solution

See the references for security advice on the use of these functions.

### Reference


* [ https://angular.io/guide/security ](https://angular.io/guide/security)


#### CWE Id: [ 749 ](https://cwe.mitre.org/data/definitions/749.html)


#### Source ID: 3

### [ Deprecated Feature Policy Header Set ](https://www.zaproxy.org/docs/alerts/10063/)



##### Low (Medium)

### Description

The header has now been renamed to Permissions-Policy.

* URL: http://juice-shop:3000
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Feature-Policy`
  * Other Info: ``
* URL: http://juice-shop:3000/
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Feature-Policy`
  * Other Info: ``
* URL: http://juice-shop:3000/ftp
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Feature-Policy`
  * Other Info: ``
* URL: http://juice-shop:3000/ftp/coupons_2013.md.bak
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Feature-Policy`
  * Other Info: ``
* URL: http://juice-shop:3000/ftp/eastere.gg
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Feature-Policy`
  * Other Info: ``
* URL: http://juice-shop:3000/ftp/encrypt.pyc
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Feature-Policy`
  * Other Info: ``
* URL: http://juice-shop:3000/ftp/package-lock.json.bak
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Feature-Policy`
  * Other Info: ``
* URL: http://juice-shop:3000/ftp/package.json.bak
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Feature-Policy`
  * Other Info: ``
* URL: http://juice-shop:3000/ftp/suspicious_errors.yml
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Feature-Policy`
  * Other Info: ``
* URL: http://juice-shop:3000/main.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Feature-Policy`
  * Other Info: ``
* URL: http://juice-shop:3000/polyfills.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Feature-Policy`
  * Other Info: ``
* URL: http://juice-shop:3000/runtime.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Feature-Policy`
  * Other Info: ``
* URL: http://juice-shop:3000/sitemap.xml
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Feature-Policy`
  * Other Info: ``
* URL: http://juice-shop:3000/vendor.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Feature-Policy`
  * Other Info: ``

Instances: 14

### Solution

Ensure that your web server, application server, load balancer, etc. is configured to set the Permissions-Policy header instead of the Feature-Policy header.

### Reference


* [ https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy ](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy)
* [ https://scotthelme.co.uk/goodbye-feature-policy-and-hello-permissions-policy/ ](https://scotthelme.co.uk/goodbye-feature-policy-and-hello-permissions-policy/)


#### CWE Id: [ 16 ](https://cwe.mitre.org/data/definitions/16.html)


#### WASC Id: 15

#### Source ID: 3

### [ Insufficient Site Isolation Against Spectre Vulnerability ](https://www.zaproxy.org/docs/alerts/90004/)



##### Low (Medium)

### Description

Cross-Origin-Embedder-Policy header is a response header that prevents a document from loading any cross-origin resources that don't explicitly grant the document permission (using CORP or CORS).

* URL: http://juice-shop:3000
  * Method: `GET`
  * Parameter: `Cross-Origin-Embedder-Policy`
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/
  * Method: `GET`
  * Parameter: `Cross-Origin-Embedder-Policy`
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/ftp
  * Method: `GET`
  * Parameter: `Cross-Origin-Embedder-Policy`
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/juice-shop/build/routes/fileServer.js:43:13
  * Method: `GET`
  * Parameter: `Cross-Origin-Embedder-Policy`
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/sitemap.xml
  * Method: `GET`
  * Parameter: `Cross-Origin-Embedder-Policy`
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000
  * Method: `GET`
  * Parameter: `Cross-Origin-Opener-Policy`
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/
  * Method: `GET`
  * Parameter: `Cross-Origin-Opener-Policy`
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/ftp
  * Method: `GET`
  * Parameter: `Cross-Origin-Opener-Policy`
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/juice-shop/build/routes/fileServer.js:43:13
  * Method: `GET`
  * Parameter: `Cross-Origin-Opener-Policy`
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/sitemap.xml
  * Method: `GET`
  * Parameter: `Cross-Origin-Opener-Policy`
  * Attack: ``
  * Evidence: ``
  * Other Info: ``

Instances: 10

### Solution

Ensure that the application/web server sets the Cross-Origin-Embedder-Policy header appropriately, and that it sets the Cross-Origin-Embedder-Policy header to 'require-corp' for documents.
If possible, ensure that the end user uses a standards-compliant and modern web browser that supports the Cross-Origin-Embedder-Policy header (https://caniuse.com/mdn-http_headers_cross-origin-embedder-policy).

### Reference


* [ https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Embedder-Policy ](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Embedder-Policy)


#### CWE Id: [ 693 ](https://cwe.mitre.org/data/definitions/693.html)


#### WASC Id: 14

#### Source ID: 3

### [ Timestamp Disclosure - Unix ](https://www.zaproxy.org/docs/alerts/10096/)



##### Low (Low)

### Description

A timestamp was disclosed by the application/web server. - Unix

* URL: http://juice-shop:3000
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1650485437`
  * Other Info: `1650485437, which evaluates to: 2022-04-20 20:10:37.`
* URL: http://juice-shop:3000
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1981395349`
  * Other Info: `1981395349, which evaluates to: 2032-10-14 19:35:49.`
* URL: http://juice-shop:3000
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `2038834951`
  * Other Info: `2038834951, which evaluates to: 2034-08-10 15:02:31.`
* URL: http://juice-shop:3000/
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1650485437`
  * Other Info: `1650485437, which evaluates to: 2022-04-20 20:10:37.`
* URL: http://juice-shop:3000/
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1981395349`
  * Other Info: `1981395349, which evaluates to: 2032-10-14 19:35:49.`
* URL: http://juice-shop:3000/
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `2038834951`
  * Other Info: `2038834951, which evaluates to: 2034-08-10 15:02:31.`
* URL: http://juice-shop:3000/sitemap.xml
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1650485437`
  * Other Info: `1650485437, which evaluates to: 2022-04-20 20:10:37.`
* URL: http://juice-shop:3000/sitemap.xml
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1981395349`
  * Other Info: `1981395349, which evaluates to: 2032-10-14 19:35:49.`
* URL: http://juice-shop:3000/sitemap.xml
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `2038834951`
  * Other Info: `2038834951, which evaluates to: 2034-08-10 15:02:31.`

Instances: 9

### Solution

Manually confirm that the timestamp data is not sensitive, and that the data cannot be aggregated to disclose exploitable patterns.

### Reference


* [ https://cwe.mitre.org/data/definitions/200.html ](https://cwe.mitre.org/data/definitions/200.html)


#### CWE Id: [ 497 ](https://cwe.mitre.org/data/definitions/497.html)


#### WASC Id: 13

#### Source ID: 3

### [ Information Disclosure - Suspicious Comments ](https://www.zaproxy.org/docs/alerts/10027/)



##### Informational (Low)

### Description

The response appears to contain suspicious comments which may help an attacker.

* URL: http://juice-shop:3000/main.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `query`
  * Other Info: `The following pattern was used: \bQUERY\b and was detected in likely comment: "//owasp.org' target='_blank'>Open Worldwide Application Security Project (OWASP)</a> and is developed and maintained by voluntee", see evidence field for the suspicious comment/snippet.`
* URL: http://juice-shop:3000/vendor.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Query`
  * Other Info: `The following pattern was used: \bQUERY\b and was detected in likely comment: "//www.w3.org/2000/svg" viewBox="0 0 512 512"><path d="M0 256C0 397.4 114.6 512 256 512s256-114.6 256-256S397.4 0 256 0S0 114.6 0", see evidence field for the suspicious comment/snippet.`

Instances: 2

### Solution

Remove all comments that return information that may help an attacker and fix any underlying problems they refer to.

### Reference



#### CWE Id: [ 615 ](https://cwe.mitre.org/data/definitions/615.html)


#### WASC Id: 13

#### Source ID: 3

### [ Modern Web Application ](https://www.zaproxy.org/docs/alerts/10109/)



##### Informational (Medium)

### Description

The application appears to be a modern web application. If you need to explore it automatically then the Ajax Spider may well be more effective than the standard one.

* URL: http://juice-shop:3000
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: `No links have been found while there are scripts, which is an indication that this is a modern web application.`
* URL: http://juice-shop:3000/
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: `No links have been found while there are scripts, which is an indication that this is a modern web application.`
* URL: http://juice-shop:3000/juice-shop/build/routes/fileServer.js:43:13
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: `No links have been found while there are scripts, which is an indication that this is a modern web application.`
* URL: http://juice-shop:3000/juice-shop/build/routes/polyfills.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: `No links have been found while there are scripts, which is an indication that this is a modern web application.`
* URL: http://juice-shop:3000/juice-shop/build/routes/runtime.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: `No links have been found while there are scripts, which is an indication that this is a modern web application.`
* URL: http://juice-shop:3000/juice-shop/build/routes/styles.css
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: `No links have been found while there are scripts, which is an indication that this is a modern web application.`
* URL: http://juice-shop:3000/juice-shop/node_modules/express/lib/router/index.js:280:10
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: `No links have been found while there are scripts, which is an indication that this is a modern web application.`
* URL: http://juice-shop:3000/juice-shop/node_modules/express/lib/router/index.js:365:14
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: `No links have been found while there are scripts, which is an indication that this is a modern web application.`
* URL: http://juice-shop:3000/juice-shop/node_modules/express/lib/router/index.js:376:14
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: `No links have been found while there are scripts, which is an indication that this is a modern web application.`
* URL: http://juice-shop:3000/juice-shop/node_modules/serve-index/index.js:145:39
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: `No links have been found while there are scripts, which is an indication that this is a modern web application.`
* URL: http://juice-shop:3000/sitemap.xml
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<script src="//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js"></script>`
  * Other Info: `No links have been found while there are scripts, which is an indication that this is a modern web application.`

Instances: 11

### Solution

This is an informational alert and so no changes are required.

### Reference




#### Source ID: 3

### [ Non-Storable Content ](https://www.zaproxy.org/docs/alerts/10049/)



##### Informational (Medium)

### Description

The response contents are not storable by caching components such as proxy servers. If the response does not contain sensitive, personal or user-specific information, it may benefit from being stored and cached, to improve performance.

* URL: http://juice-shop:3000/ftp/eastere.gg
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `403`
  * Other Info: ``

Instances: 1

### Solution

The content may be marked as storable by ensuring that the following conditions are satisfied:
The request method must be understood by the cache and defined as being cacheable ("GET", "HEAD", and "POST" are currently defined as cacheable)
The response status code must be understood by the cache (one of the 1XX, 2XX, 3XX, 4XX, or 5XX response classes are generally understood)
The "no-store" cache directive must not appear in the request or response header fields
For caching by "shared" caches such as "proxy" caches, the "private" response directive must not appear in the response
For caching by "shared" caches such as "proxy" caches, the "Authorization" header field must not appear in the request, unless the response explicitly allows it (using one of the "must-revalidate", "public", or "s-maxage" Cache-Control response directives)
In addition to the conditions above, at least one of the following conditions must also be satisfied by the response:
It must contain an "Expires" header field
It must contain a "max-age" response directive
For "shared" caches such as "proxy" caches, it must contain a "s-maxage" response directive
It must contain a "Cache Control Extension" that allows it to be cached
It must have a status code that is defined as cacheable by default (200, 203, 204, 206, 300, 301, 404, 405, 410, 414, 501).

### Reference


* [ https://datatracker.ietf.org/doc/html/rfc7234 ](https://datatracker.ietf.org/doc/html/rfc7234)
* [ https://datatracker.ietf.org/doc/html/rfc7231 ](https://datatracker.ietf.org/doc/html/rfc7231)
* [ https://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html ](https://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html)


#### CWE Id: [ 524 ](https://cwe.mitre.org/data/definitions/524.html)


#### WASC Id: 13

#### Source ID: 3

### [ Storable and Cacheable Content ](https://www.zaproxy.org/docs/alerts/10049/)



##### Informational (Medium)

### Description

The response contents are storable by caching components such as proxy servers, and may be retrieved directly from the cache, rather than from the origin server by the caching servers, in response to similar requests from other users. If the response data is sensitive, personal or user-specific, this may result in sensitive information being leaked. In some cases, this may even result in a user gaining complete control of the session of another user, depending on the configuration of the caching components in use in their environment. This is primarily an issue where "shared" caching servers such as "proxy" caches are configured on the local network. This configuration is typically found in corporate or educational environments, for instance.

* URL: http://juice-shop:3000/robots.txt
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `In the absence of an explicitly specified caching lifetime directive in the response, a liberal lifetime heuristic of 1 year was assumed. This is permitted by rfc7234.`

Instances: 1

### Solution

Validate that the response does not contain sensitive, personal or user-specific information. If it does, consider the use of the following HTTP response headers, to limit, or prevent the content being stored and retrieved from the cache by another user:
Cache-Control: no-cache, no-store, must-revalidate, private
Pragma: no-cache
Expires: 0
This configuration directs both HTTP 1.0 and HTTP 1.1 compliant caching servers to not store the response, and to not retrieve the response (without validation) from the cache, in response to a similar request.

### Reference


* [ https://datatracker.ietf.org/doc/html/rfc7234 ](https://datatracker.ietf.org/doc/html/rfc7234)
* [ https://datatracker.ietf.org/doc/html/rfc7231 ](https://datatracker.ietf.org/doc/html/rfc7231)
* [ https://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html ](https://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html)


#### CWE Id: [ 524 ](https://cwe.mitre.org/data/definitions/524.html)


#### WASC Id: 13

#### Source ID: 3

### [ Storable but Non-Cacheable Content ](https://www.zaproxy.org/docs/alerts/10049/)



##### Informational (Medium)

### Description

The response contents are storable by caching components such as proxy servers, but will not be retrieved directly from the cache, without validating the request upstream, in response to similar requests from other users.

* URL: http://juice-shop:3000
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `max-age=0`
  * Other Info: ``
* URL: http://juice-shop:3000/
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `max-age=0`
  * Other Info: ``
* URL: http://juice-shop:3000/assets/public/favicon_js.ico
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `max-age=0`
  * Other Info: ``
* URL: http://juice-shop:3000/ftp/acquisitions.md
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `max-age=0`
  * Other Info: ``
* URL: http://juice-shop:3000/ftp/incident-support.kdbx
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `max-age=0`
  * Other Info: ``
* URL: http://juice-shop:3000/main.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `max-age=0`
  * Other Info: ``
* URL: http://juice-shop:3000/polyfills.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `max-age=0`
  * Other Info: ``
* URL: http://juice-shop:3000/runtime.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `max-age=0`
  * Other Info: ``
* URL: http://juice-shop:3000/sitemap.xml
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `max-age=0`
  * Other Info: ``
* URL: http://juice-shop:3000/styles.css
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `max-age=0`
  * Other Info: ``
* URL: http://juice-shop:3000/vendor.js
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `max-age=0`
  * Other Info: ``

Instances: 11

### Solution



### Reference


* [ https://datatracker.ietf.org/doc/html/rfc7234 ](https://datatracker.ietf.org/doc/html/rfc7234)
* [ https://datatracker.ietf.org/doc/html/rfc7231 ](https://datatracker.ietf.org/doc/html/rfc7231)
* [ https://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html ](https://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html)


#### CWE Id: [ 524 ](https://cwe.mitre.org/data/definitions/524.html)


#### WASC Id: 13

#### Source ID: 3

### [ User Agent Fuzzer ](https://www.zaproxy.org/docs/alerts/10104/)



##### Informational (Medium)

### Description

Check for differences in response based on fuzzed User Agent (eg. mobile sites, access as a Search Engine Crawler). Compares the response statuscode and the hashcode of the response body with the original response.

* URL: http://juice-shop:3000/assets
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/assets
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/assets
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/assets
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/assets
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/assets
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/assets
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/assets
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/assets
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/assets
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/assets
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/assets
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `msnbot/1.1 (+http://search.msn.com/msnbot.htm)`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/assets/public
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/assets/public
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/assets/public
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/assets/public
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/assets/public
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/assets/public
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/assets/public
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/assets/public
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/assets/public
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/assets/public
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/assets/public
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16`
  * Evidence: ``
  * Other Info: ``
* URL: http://juice-shop:3000/assets/public
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `msnbot/1.1 (+http://search.msn.com/msnbot.htm)`
  * Evidence: ``
  * Other Info: ``

Instances: 24

### Solution



### Reference


* [ https://owasp.org/wstg ](https://owasp.org/wstg)



#### Source ID: 1


