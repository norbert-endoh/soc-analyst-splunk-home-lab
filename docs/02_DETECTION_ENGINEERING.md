# Detection Use Case 01: Repeated Failed Windows Logons

**Goal:** Detect 3 or more failed Windows logons for the same user within 5 minutes (Windows Security Event ID 4625), then turn the detection into a tuned, scheduled Splunk alert.

The aim was not to label every failed logon as malicious. It was to prove the telemetry path, detect the behavior reliably, and operationalize the rule the way a SOC would.

**MITRE ATT&CK:** T1110 – Brute Force

```text
Baseline -> Controlled test -> Validate ingestion -> Build SPL -> Refine & generalize
         -> Schedule alert -> Verify firing -> Tune suppression
```

---

## 1. Establish a baseline
Before generating any test activity, I counted existing Event ID 4625 records on the endpoint. **Result: 3 events.** Having a clean before-state means new activity can be separated from historical data.

![Baseline count](../images/01_baseline_failed_logon_count.png)

## 2. Generate controlled failed logons
On the Windows 10 VM, I entered an incorrect password for the lab account `labuser` three times. The activity was intentional, known and timestamped.

![Controlled failed logon](../images/02_controlled_failed_logons.png)

## 3. Validate ingestion
Re-running the same count returned **6 events (3 → 6)**: exactly three new failures had travelled endpoint → forwarder → TCP 9997 → Splunk index.

![Count after test](../images/03_failed_logon_count_after_test.png)

## 4. Isolate and inspect the new events
I sorted the 4625 events newest-first and checked the key triage fields. All three matched the test: `labuser`, Logon Type 2 (interactive), source `127.0.0.1`, workstation `DESKTOP-4AMTH10`, reason "Unknown user name or bad password".

![Event details](../images/04_failed_logon_event_details.png)

## 5. Build the first threshold detection
I grouped failures into 5-minute buckets and kept results with 3 or more. The rule fired, but it exposed a **multivalue `Account_Name` field**: Windows records both the machine account and the user account.

![Initial detection](../images/05_initial_detection.png)

## 6. Fix the field-quality issue
I created a clean `target_user` field with `mvindex(Account_Name,-1)`, so the alert names the intended account.

![Refined target_user](../images/06_refined_target_user.png)

## 7. Generalize beyond the test account
I removed the hard-coded `labuser` filter and excluded empty values and machine accounts (names ending in `$`), so the rule monitors every user.

![Generalized detection](../images/07_generalized_detection.png)

## 8. Move to an operational time window
Switching from *All time* to *Last 15 minutes* returned zero results. That was a timing issue, not a broken rule: the earlier test events were outside the window.

![No results in 15-minute window](../images/08_operational_window_no_results.png)

## 9. Re-validate with fresh activity
I generated three new failures and ran the rule over the last 15 minutes. It returned `labuser`, 3 failures, source `127.0.0.1`.

![Validated in operational window](../images/09_operational_window_validated.png)

## 10. Operationalize as a scheduled alert

| Setting | Value |
|---|---|
| Alert name | Repeated Failed Windows Logons – 3 in 5 Minutes |
| Schedule | Cron `*/5 * * * *` (every 5 minutes) |
| Search window | Last 15 minutes |
| Trigger | Number of results > 0, once |
| Action | Add to Triggered Alerts |
| Severity | Medium (raised to High at final validation) |

![Alert configuration](../images/10_alert_configuration.png)
![Alert saved](../images/11_alert_saved.png)

## 11. Verify automatic firing
After generating fresh failures, I waited for the 5-minute cron boundary. Trigger History recorded automatic firings, and the results showed `target_user=labuser`, `failed_logons=3`.

![Trigger history](../images/12_alert_trigger_history.png)
![Triggered results](../images/13_triggered_alert_results.png)

## 12. Tune duplicate alerts
Because a 15-minute window is searched every 5 minutes, the same activity could alert up to three times. I enabled **throttling by `target_user` for 15 minutes**, then confirmed no duplicate trigger entries appeared during the suppression period.

![Throttle configuration](../images/14_alert_suppression_throttle.png)
![Suppression validated](../images/15_suppression_validated.png)

---

## Final Detection

```spl
index=* host="DESKTOP-4AMTH10" sourcetype="WinEventLog:Security" EventCode=4625
| eval target_user=mvindex(Account_Name,-1)
| where isnotnull(target_user) AND target_user!="" AND NOT match(target_user,"\$$")
| bin _time span=5m
| stats count as failed_logons
        values(Source_Network_Address) as source
        values(Workstation_Name) as workstation
        by _time target_user
| where failed_logons>=3
```

**Skills shown:** SPL, Windows Event ID 4625 analysis, baselining, ingestion validation, multivalue field normalization, threshold detection, detection generalization, relative-time search design, cron scheduling, alert validation, and noise reduction through per-user suppression.

[← Back to project overview](../README.md)
