---
name: tls-health
description: "Invoke this skill when a task needs to check the HTTPS / TLS setup of authorized services: certificate expiry, hostname match and chain, old protocols (SSLv3, TLS 1.0, TLS 1.1), weak cipher suites, HTTP to HTTPS redirect, HSTS and the browser security headers. Fits router, NAS and self-hosted web UIs on a home or lab network as well as public sites in scope. Uses testssl.sh when it is installed, otherwise nmap NSE scripts, openssl and curl."
---

# tls-health: HTTPS and TLS configuration check

Read-only checks of how a service does TLS. Nothing here sends exploit payloads;
every probe is a normal handshake or a single HTTP request, so it is safe to run
against your own devices. Stay inside the task's authorized scope.

## 1. Pick the tool set

Check what is installed first (the prompt's tool list says it too):

```bash
for t in testssl.sh testssl nmap openssl curl; do command -v "$t" >/dev/null && echo "have $t"; done
```

- **testssl.sh / testssl installed**: use it for protocols, ciphers and the
  named TLS weaknesses (section 3a), then still do sections 4 and 5 with curl.
- **Otherwise**: nmap (`ssl-enum-ciphers`, `ssl-cert`) plus openssl and curl
  (section 3b). Do not try to install tools; work with what exists.

## 2. Find the TLS services

If the task gives hosts but no ports, look for TLS on the usual web and admin
ports and let version detection mark the ones that speak TLS:

```bash
nmap -Pn -sV --open -p 443,8443,9443,4443,10443,8006,5001,8080,8000,8888,9090,631 <host> -oN tls-ports.txt
```

Treat any service nmap labels `ssl/...` or `https` as in scope for the checks
below. Mail ports (465, 587, 993, 995) count too when the host serves mail.

## 3a. Protocols and ciphers with testssl

```bash
testssl.sh --quiet --color 0 --warnings off --jsonfile-pretty tls-<host>-<port>.json <host>:<port>
```

Read the JSON (`jq '.scanResult[0]'`) rather than the console output. The
sections that matter: `protocols`, `ciphers`, `serverDefaults` (certificate),
`vulnerabilities` and `headerResponse`. A `severity` of `HIGH` or `CRITICAL` in
`vulnerabilities` is a real finding; `LOW`/`INFO` is context.

## 3b. Protocols and ciphers without testssl

```bash
nmap -Pn -p <port> --script ssl-enum-ciphers,ssl-cert <host> -oN tls-<host>-<port>.txt
```

`ssl-enum-ciphers` lists every protocol the server accepts with its ciphers and
grades each cipher A to F; the line `least strength: X` is the overall grade.
Confirm an old protocol directly before reporting it (OpenSSL 3 needs the lower
security level to even try TLS 1.0/1.1):

```bash
for p in tls1 tls1_1 tls1_2 tls1_3; do
  if echo | openssl s_client -connect <host>:<port> -servername <host> -$p -cipher 'DEFAULT:@SECLEVEL=0' >/dev/null 2>&1; then echo "$p accepted"; else echo "$p refused"; fi
done
```

SSLv3 cannot be tested with a modern openssl; rely on the nmap output for it.

## 4. Certificate

```bash
echo | openssl s_client -connect <host>:<port> -servername <host> -showcerts 2>/dev/null > chain.pem
openssl x509 -in chain.pem -noout -subject -issuer -dates -ext subjectAltName
openssl x509 -in chain.pem -noout -checkend $((30*86400)) || echo "expires within 30 days"
echo | openssl s_client -connect <host>:<port> -servername <host> -verify_return_error 2>&1 | grep -E 'Verify return code|verify error'
```

Check: days until `notAfter`, whether the name you connect with is in the
subjectAltName list, whether the chain verifies, the key size
(`openssl x509 -in chain.pem -noout -text | grep 'Public-Key'`) and the
signature algorithm (SHA-1 or MD5 is weak).

## 5. Redirect and security headers

```bash
curl -sk -o /dev/null -D - --max-time 10 http://<host>/ | head -20     # plain HTTP: should redirect to https
curl -sk -o /dev/null -D - --max-time 10 https://<host>:<port>/ | head -40
```

Look for `Strict-Transport-Security` (and its `max-age`),
`Content-Security-Policy`, `X-Frame-Options` or a CSP `frame-ancestors`,
`X-Content-Type-Options: nosniff`, `Referrer-Policy`, and cookies without
`Secure`/`HttpOnly` (`Set-Cookie` lines). Note a `Server` or `X-Powered-By`
header that gives an exact version.

## 6. Rating

Rate for where the service is reachable. A LAN-only admin page is not a public
bank site; say which one it is in the finding.

| Observation | Internet-facing | LAN only |
|---|---|---|
| Certificate expired, or expires within 7 days | High | Medium |
| SSLv3 or export / NULL / anonymous ciphers accepted | High | Medium |
| Admin login served over plain HTTP with no redirect | High | Medium |
| TLS 1.0 / 1.1 accepted, RC4 or 3DES offered, cipher grade C or worse | Medium | Low |
| Hostname mismatch, untrusted chain, RSA key under 2048 bits, SHA-1 signature | Medium | Low |
| Self-signed certificate on a home device | Low | Info |
| Missing HSTS on HTTPS, missing CSP / X-Frame-Options / nosniff, cookies without Secure or HttpOnly | Low | Info |
| Certificate expires within 30 days | Low | Low |
| Exact server version in headers | Info | Info |

Report one finding per issue per service, with the exact command and the lines
of output that show it, and a one-line fix (for example "disable TLS 1.0 and
1.1 in the web server config", "renew the certificate", "add
`Strict-Transport-Security: max-age=31536000`"). Do not report a weakness from
the cipher list alone when a direct handshake test refused it.
