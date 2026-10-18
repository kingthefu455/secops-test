# CrowdStrikeSync – Google SecOps custom integration

One job that closes CrowdStrike Falcon detections when the SecOps case they belong to is closed. It is the CrowdStrike counterpart of the WizEnrichment **Sync Closed Cases To Wiz** job.

```
CrowdStrikeSync/
  Managers/FalconManager.py                 # Falcon OAuth2 + Alerts API client (IDE "Manager")
  Jobs/SyncClosedCasesToCrowdStrike.py      # IDE job "Sync Closed Cases To CrowdStrike"
```

## How it works

Each run:

1. Calls `get_cases_ids_by_filter(status="CLOSE", close_time_from/to=...)` for cases closed in the last **Lookback Minutes** (default 10).
2. Loads each case with `_get_case_by_id` and loops over `cyber_alerts`. Alerts are skipped if `IsTestCase` is `True`, or if **Product Name** is set and the alert's `DeviceProduct` doesn't contain it.
3. Reads the detection ID from the first field in **Detection ID Fields** that holds one. It checks `additional_properties` first, then the alert itself. An ID counts only if it looks like a Falcon composite ID (`<32-hex CID>:<product>:...`, for example `<cid>:ind:<aid>:<detection id>`), so Wiz UUIDs and other IDs are ignored.
4. Reads the detection with `POST /alerts/entities/alerts/v2`. If its status is already `closed`, it's skipped. Otherwise the job sends `PATCH /alerts/entities/alerts/v3` with `update_status=closed` and `append_comment=<Close Comment>`.
5. If any case or detection fails, the job logs it, finishes the rest, then raises an error so the run shows as failed in the job history.

### Why the Alerts API, not the Detects API

CrowdStrike decommissioned the Detects API (`/detects/entities/detects/v2`) on 2025-09-30. Detections are now Alerts, addressed by **composite ID**. Legacy detection IDs (`ldt:<aid>:<id>`) can't be updated any more. If the job finds one, it logs an error and counts it as a failure instead of skipping it silently.

## Prerequisites in CrowdStrike

Create an API client (**Support and resources → API clients and keys**) with the **Alerts: Read** and **Alerts: Write** scopes. Note the Client ID, the secret, and your cloud's API base URL:

| Cloud | API Root |
|---|---|
| US-1 | `https://api.crowdstrike.com` |
| US-2 | `https://api.us-2.crowdstrike.com` |
| EU-1 | `https://api.eu-1.crowdstrike.com` |
| US-GOV-1 | `https://api.laggar.gcw.crowdstrike.com` |

## Deploy to Google SecOps

You can't add jobs to the marketplace CrowdStrike Falcon integration, so this is a separate custom integration.

1. **Response → IDE** → **+** → **Integration**, name it **`CrowdStrikeSync`**.
2. **+** → **Manager**, name it **`FalconManager`**, paste `Managers/FalconManager.py`, save.
3. **+** → **Job**, name it **`Sync Closed Cases To CrowdStrike`**, paste `Jobs/SyncClosedCasesToCrowdStrike.py`, and add these parameters:

   | Parameter | Type | Mandatory | Default | Notes |
   |---|---|---|---|---|
   | `API Root` | String | Yes | `https://api.crowdstrike.com` | See the table above |
   | `Client ID` | String | Yes | | |
   | `Client Secret` | Password | Yes | | |
   | `Verify SSL` | Boolean | No | `true` | |
   | `Lookback Minutes` | String | No | `10` | |
   | `Detection ID Fields` | String | No | `TicketId,ThreadId,SourceGroupingIdentifier` | Alert fields to read the composite ID from, in order |
   | `Product Name` | String | No | *(empty)* | Matched against the alert's `DeviceProduct`. Empty = all alerts; the composite-ID format already filters |
   | `Close Comment` | String | No | `Closed via Google SecOps case {case_id}` | Added to the Falcon alert. `{case_id}` is replaced |

4. **Response → Job Scheduler**: add the job and run it **every 10 minutes or less** (no longer than *Lookback Minutes*). Overlapping windows are safe, because detections that are already closed are skipped.

Before scheduling it, open a closed CrowdStrike case in SecOps and check which alert field holds the detection's composite ID. Make sure that field is in **Detection ID Fields**.

## Known limitations

- The Falcon endpoints and request bodies match CrowdStrike's FalconPy SDK (`get_alerts_v2`, `update_alerts_v3`), but the job has **not been run against a live tenant**. Test it once and check the job log.
- The job uses a fixed lookback window, not a saved timestamp. If the scheduler is down for longer than *Lookback Minutes*, cases closed in that gap aren't synced. Raise *Lookback Minutes* for a one-off catch-up run.
- The job closes a detection as soon as one SecOps case containing it is closed. It doesn't check whether other open cases reference the same detection.
- Only `closed` is set. SecOps close reasons (for example false positive) aren't mapped to Falcon tags or statuses, but the case ID is in the comment.
