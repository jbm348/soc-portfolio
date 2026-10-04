# Investigation: Joomla Admin Brute-Force & Compromise — BOTS v1 (imreallynotbatman.com)

## Scenario
Investigating suspicious HTTP traffic against `imreallynotbatman.com`, captured in Splunk's Boss of the SOC (BOTS) v1 dataset. The goal was to identify whether the site was attacked, how, and whether the attacker succeeded.

## Environment
- Splunk Enterprise (local lab install)
- Dataset: Splunk BOTS v1 (`stream:http` sourcetype)

## Methodology

### 1. Identify high-volume source IPs
```spl
index=botsv1 sourcetype=stream:http imreallynotbatman.com
| stats count by src_ip
| sort -count
```
Two IPs stood out with abnormally high request counts: `23.22.63.114` (~12,350 requests) and `40.80.148.42` (~17,480 requests). High request volume against a single site from one IP is a strong indicator of automated/scripted activity rather than normal user traffic.

### 2. Inspect request pattern and client signature
```spl
index="botsv1" sourcetype="stream:http" src_ip="23.22.63.114"
| table _time, uri_path, http_user_agent
| head 10
```
Findings:
- Every request targeted the same endpoint: `/joomla/administrator/index.php` — the Joomla admin login page.
- `http_user_agent` was `Python-urllib/2.7` — not a browser, confirming a scripted client.
- Timestamps were milliseconds apart, consistent with an automated brute-force tool, not a human typing.

### 3. Check HTTP status codes for the login attempts
```spl
index="botsv1" sourcetype="stream:http" src_ip="23.22.63.114" uri_path="/joomla/administrator/index.php"
| stats count by status
```
Result: mostly `200`, with some `303` responses. A `303` after a login POST typically signals the server is redirecting the client — in Joomla, this happens on *both* success and failure, so status code alone wasn't enough to isolate the successful attempt.

### 4. Isolate the successful login using response size
Since every attempt returned `303`, the differentiator used was response size (`bytes`):
```spl
index="botsv1" sourcetype="stream:http" src_ip="23.22.63.114" uri_path="/joomla/administrator/index.php" status=303
| stats count by bytes
```
Five byte-size values (852–856) repeated dozens to hundreds of times — these were the failed attempts, all rendering the same login page. One value, `857`, appeared exactly **once** — a clear outlier.

### 5. Extract the successful credential
```spl
index="botsv1" sourcetype="stream:http" src_ip="23.22.63.114" uri_path="/joomla/administrator/index.php" status=303 bytes=857
| table _time, form_data
```

## Findings
| Field | Value |
|---|---|
| Attacker IP | `23.22.63.114` |
| Target | `imreallynotbatman.com` — Joomla admin panel |
| Technique | HTTP brute-force login (scripted, `Python-urllib/2.7`) |
| Username used | `admin` |
| Successful password | `123456789` |
| Time of compromise | `2016-08-11 03:15:25.299` |

## Indicators of Compromise (IOCs)
- Source IP: `23.22.63.114`
- User-Agent: `Python-urllib/2.7`
- Target endpoint: `/joomla/administrator/index.php`
- Credential pair: `admin:123456789`

## Detection Idea
A production SOC should alert on:
- High-frequency POST requests to a single login URI from one source IP within a short window (e.g. >20 requests/minute).
- Non-browser `User-Agent` strings hitting authentication endpoints.
- A successful auth response (differing response size/status) immediately following a burst of failed attempts from the same IP — a classic brute-force-then-success pattern.

## Lessons Learned
- HTTP status codes aren't always a reliable success/failure indicator for application-layer auth flows — response size or response body content can be a better signal.
- Weak, common passwords (`123456789`) remain effective against admin panels with no lockout or rate-limiting in place — this is as much a hardening gap as a detection gap.

---
*Part of a personal SOC analyst home-lab portfolio, built on Splunk Enterprise using the Splunk BOTS v1 dataset.*
