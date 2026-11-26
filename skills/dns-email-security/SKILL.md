---
name: dns-email-security
description: "Invoke this skill when a task needs to check the DNS and email security of an authorized domain or DNS server: SPF, DMARC and DKIM records, MX and CAA, DNSSEC, zone transfer (AXFR) on the domain's nameservers, and whether a DNS server (a home resolver, Pi-hole, a router, an authoritative server) answers recursive queries for anyone or leaks its version. Uses dig, with nmap NSE scripts where they help."
---

# dns-email-security: DNS and mail-domain hygiene

Every check here is a normal DNS query. Only a zone transfer request and a
recursion test touch the target's DNS servers, and both are single queries.
Stay inside the task's authorized scope: the domain must be the operator's,
and a DNS server must be one they run.

Use `dig +short` for values and full `dig` output as evidence. If `dig` is
missing, `nslookup -type=TXT <name>` and `host -t TXT <name>` give the same
data; `python3 -c 'import dns.resolver'` works only when dnspython is installed.

## 1. Domain records

```bash
D=<domain>
dig +short NS $D
dig +short MX $D
dig +short TXT $D | grep -i 'v=spf1'
dig +short TXT _dmarc.$D
dig +short CAA $D
```

### SPF (from the TXT record starting `v=spf1`)
- No SPF record on a domain that sends or receives mail: Medium. On a domain
  with no MX and no mail use, the right record is `v=spf1 -all`; its absence is Low.
- More than one `v=spf1` record: Medium (receivers treat it as a permanent error).
- Ends in `+all`: High (anyone may send as the domain). `?all`: Medium.
  `~all` is common and acceptable while DMARC enforces; `-all` is strict.
- Count the DNS lookups (`include:`, `a`, `mx`, `ptr`, `exists:`, `redirect=`,
  recursively through each include). More than 10 is a permanent error: Medium.
  `ptr` is deprecated: Info.

### DMARC (TXT at `_dmarc.<domain>`)
- Missing on a mail domain: Medium.
- `p=none`: Low (monitoring only, nothing is rejected). `p=quarantine` or
  `p=reject` is enforcing. `pct` below 100 weakens it: Info.
- No `rua=` address means nobody receives reports: Info.
- `sp=none` while `p` enforces leaves subdomains spoofable: Low.

### DKIM
The selector name is not discoverable from DNS. Try common ones and report a
missing DKIM only as unconfirmed:

```bash
for s in default google selector1 selector2 k1 k2 mail dkim s1 s2 smtp mandrill mxvault; do
  r=$(dig +short TXT $s._domainkey.$D); [ -n "$r" ] && echo "$s: $r"
done
```

A found key of 1024 bits or less (`p=` value shorter than about 220 base64
characters) is Low.

### CAA and DNSSEC
- No CAA record: Info (any public CA may issue certificates for the domain).
- DNSSEC: `dig +dnssec +multi $D SOA` shows `RRSIG` when the zone is signed,
  and `dig +short DS $D` shows the delegation. Unsigned: Info. Signed zone
  whose answer lacks the `ad` flag through a validating resolver
  (`dig @1.1.1.1 $D SOA +dnssec | grep flags`), or `delv $D` failing: Medium,
  because validating resolvers will refuse the domain.

## 2. Zone transfer on each nameserver

```bash
for ns in $(dig +short NS $D); do echo "== $ns"; dig AXFR $D @$ns +time=5 +tries=1 | head -50; done
```

`Transfer failed` or a timeout is the expected result. Any listing of records
is High: the whole zone, including internal host names, is public. Keep only
the first lines as evidence, not the full zone. For a local DNS server that
hosts a private zone (`home.arpa`, `lan`, `internal`), run the same against its
IP with that zone name.

## 3. DNS servers the operator runs

For each resolver or DNS server in scope (router, Pi-hole, AdGuard, unbound,
bind, dnsmasq):

```bash
S=<server-ip>
dig @$S example.com A +short +time=3 +tries=1     # does it resolve names it does not own?
dig @$S version.bind CH TXT +short +time=3         # version disclosure
dig @$S hostname.bind CH TXT +short +time=3
nmap -sU -p 53 --script dns-recursion,dns-nsid $S
```

- Answering recursive queries is expected for LAN clients. It is a finding
  only when the server is reachable from the internet: check whether UDP/TCP 53
  is open on the public address (if the task gives one, or the router forwards
  port 53). An open resolver on the internet: High (used for DDoS
  amplification). Recursion offered only on the LAN: Info.
- An authoritative-only server that also answers recursive queries: Medium.
- `version.bind` returning an exact version: Low, Medium if that version has
  known vulnerabilities (search the version string before saying so).

## 4. Reporting

One finding per issue, with the exact `dig` command, the relevant answer lines
and a one-line fix, for example:
- "Publish `v=spf1 include:<your mail provider> -all` and remove the second SPF record."
- "Publish `_dmarc` with `p=quarantine; rua=mailto:<address>` after a week of `p=none` reports."
- "Restrict zone transfers to the secondary nameservers (`allow-transfer`)."
- "Bind the resolver to the LAN interface, or set `allow-recursion` to the LAN range."
- "Hide the version (`version \"none\";` in bind, `hide-version: yes` in unbound)."

Say what was not checked: DKIM with an unknown selector, internet reachability
of a resolver when no public address is known.
