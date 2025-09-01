# XSS Scan Report for https://0ad600b7048085ee8109f48c00dd00a2.web-security-academy.net/

**Scan Start Time:** 2025-09-01 20:09:07
**Scan End Time:** 2025-09-01 20:18:58
**Total URLs Visited:** 6
**Potential XSS Vulnerabilities Found:** 1

## Visited URLs
- https://0ad600b7048085ee8109f48c00dd00a2.web-security-academy.net/
- https://0ad600b7048085ee8109f48c00dd00a2.web-security-academy.net/post?postId=1
- https://0ad600b7048085ee8109f48c00dd00a2.web-security-academy.net/post?postId=2
- https://0ad600b7048085ee8109f48c00dd00a2.web-security-academy.net/post?postId=3
- https://0ad600b7048085ee8109f48c00dd00a2.web-security-academy.net/post?postId=4
- https://0ad600b7048085ee8109f48c00dd00a2.web-security-academy.net/post?postId=5

## Potential XSS Vulnerabilities
### Vulnerability 1
- **URL:** `https://0ad600b7048085ee8109f48c00dd00a2.web-security-academy.net/?search=%27%3Balert%28String.fromCharCode%2888%2C83%2C83%29%29%2F%2F`
- **Affected Field:** `search`
- **Payload Used:** `';alert(String.fromCharCode(88,83,83))//`
- **Detection Method:** String Reflection (Potential XSS)
- **Screenshot:** [Link to Screenshot](xss_vuln_20250901200934_1.png)


## Scan Summary
- **Total Pages Visited:** 6
- **Total Potential Vulnerabilities Found:** 1
- **Scan Duration:** 0:09:51
