# Website Security Checker - Node.js Implementation Guide

## Connection Security (25 points)

- [ ] **HTTPS Implementation** (5 points)

  - _Basic:_ Website uses encrypted connections
  - _Technical:_ Site uses HTTPS protocol
  - _Implementation:_ `isHttps(url)` function already exists in your code

- [ ] **Valid SSL Certificate** (5 points)

  - _Basic:_ Security certificate is valid and trusted by browsers
  - _Technical:_ SSL certificate validation check
  - _Implementation:_ Use `sslChecker(domain)` and check `sslInfo.valid`

- [ ] **Certificate-Domain Match** (5 points)

  - _Basic:_ Security certificate belongs to this specific website
  - _Technical:_ SSL certificate domain name match check
  - _Implementation:_ Compare `domain.includes(sslInfo.issuer.cn)` or check SANs

- [ ] **Current Certificate** (5 points)

  - _Basic:_ Security certificate is not expired or near expiration
  - _Technical:_ SSL certificate expiration check
  - _Implementation:_ Check `sslInfo.daysRemaining > 30`

- [ ] **Secure HTTPS Response** (5 points)
  - _Basic:_ Website successfully serves content over HTTPS
  - _Technical:_ Can connect and retrieve content via HTTPS
  - _Implementation:_ Successful `axios.get(formattedUrl)` with HTTPS URL

## Domain Security (20 points)

- [ ] **Domain Age** (5 points)

  - _Basic:_ Website domain is established, not newly created
  - _Technical:_ Domain age verification
  - _Implementation:_ Calculate age from `whoisData.creationDate`

- [ ] **Non-Suspicious TLD** (5 points)

  - _Basic:_ Website uses common domain endings
  - _Technical:_ Domain not using TLDs commonly associated with abuse
  - _Implementation:_ `hasSuspiciousTLD(domain)` function already exists

- [ ] **Clean Domain Name** (5 points)

  - _Basic:_ Website address uses normal spelling without excessive special characters
  - _Technical:_ Domain name pattern analysis
  - _Implementation:_ `hasExcessiveSpecialChars(domain)` function already exists

- [ ] **Complete Registration Information** (5 points)
  - _Basic:_ Domain ownership information is available
  - _Technical:_ WHOIS data completeness check
  - _Implementation:_ Check `whoisData.registrar` existence

## Security Headers & Configuration (20 points)

- [ ] **Content Security Policy** (5 points)

  - _Basic:_ Website controls what resources can load
  - _Technical:_ CSP header implementation check
  - _Implementation:_ Check response headers for `content-security-policy`

- [ ] **Cross-Site Protections** (5 points)

  - _Basic:_ Website prevents cross-site attacks
  - _Technical:_ X-Frame-Options and XSS protection headers
  - _Implementation:_ Check response headers for `x-frame-options` and `x-xss-protection`

- [ ] **HSTS Implementation** (5 points)

  - _Basic:_ Website forces secure connections
  - _Technical:_ HSTS header check
  - _Implementation:_ Check response headers for `strict-transport-security`

- [ ] **Safe Cookie Configuration** (5 points)
  - _Basic:_ Website protects stored user information
  - _Technical:_ Secure cookie attributes check
  - _Implementation:_ Parse `set-cookie` headers for `Secure;`, `HttpOnly;`, and `SameSite=`

## Content Safety (20 points)

- [ ] **No Suspicious Redirects** (5 points)

  - _Basic:_ Website doesn't automatically send visitors elsewhere
  - _Technical:_ No immediate redirects to different domains
  - _Implementation:_ Track redirects in axios response and check final URL domain

- [ ] **Privacy Policy Presence** (5 points)

  - _Basic:_ Website explains how it handles user data
  - _Technical:_ Privacy policy page detection
  - _Implementation:_ Search for privacy policy links as in your original code

- [ ] **Contact Information Available** (5 points)

  - _Basic:_ Website provides ways to contact the owners
  - _Technical:_ Contact information detection
  - _Implementation:_ Check for contact links, email patterns, phone patterns as in your code

- [ ] **No Excessive Popups/Ads** (5 points)
  - _Basic:_ Website doesn't bombard users with popups
  - _Technical:_ Analyze page for popup scripts and excessive ad elements
  - _Implementation:_ Count `window.open`, modal elements, and ad-related scripts
