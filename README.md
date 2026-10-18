# WizEnrichment – Google SecOps custom integration

A Google SecOps (SOAR) custom integration with two actions and one job:

| Action | What it does |
|---|---|
| **Ping** | Authenticates to Wiz and runs a one-row graph search to check credentials and scopes. |
| **Enrich Hostname** | For every `Hostname` entity in scope, searches the Wiz Security Graph by name, enriches the SecOps entity with `Wiz_*` properties, optionally adds open-issue counts and an entity insight, and returns the full Wiz data as JSON. |
| **Sync Closed Cases To Wiz** (job) | Finds SecOps cases closed in the last N minutes (default 10), reads the Wiz issue ID from every Wiz alert in each case, and resolves/rejects the matching Wiz issue. |

```
WizEnrichment/
  Managers/WizManager.py          # Wiz OAuth + GraphQL client (IDE "Manager")
  ActionsScripts/Ping.py          # IDE action "Ping"
  ActionsScripts/EnrichHostname.py # IDE action "Enrich Hostname"
  Jobs/SyncClosedCasesToWiz.py    # IDE job "Sync Closed Cases To Wiz"
tests/                            # unit tests with stubbed SecOps SDK + mocked Wiz API
```

## How the lookup works

1. Gets an OAuth token from Wiz with the client-credentials grant (`audience=wiz-api`, or `beyond-api` for legacy `auth.wiz.io` tenants). The token is cached for the whole run.
2. Runs a `graphSearch` GraphQL query for the configured Wiz entity types (default `VIRTUAL_MACHINE`) with a `name` filter.
   - **Exact** (default): `EQUALS` on the identifier, its lower-case form, and the short name (`WEB-01.CORP.LOCAL` → also `WEB-01` / `web-01`), because SecOps upper-cases entity identifiers. Results are then filtered case-insensitively.
   - **Contains**: `CONTAINS` on the lower-cased identifier.
3. Enriches the entity with the first match: `Wiz_id`, `Wiz_name`, `Wiz_type`, `Wiz_match_count`, plus every scalar or list field in the Wiz `properties` (for example `Wiz_cloudPlatform`, `Wiz_region`). Nested-object properties appear only in the JSON result.
4. If **Include Open Issues** is on, runs `issuesV2` filtered by `relatedEntity.id` and status `OPEN`/`IN_PROGRESS`, and adds `Wiz_open_issues` and `Wiz_open_issues_<severity>` counts. If that query fails, the entity is still enriched and the failure appears in the output message.

## Prerequisites in Wiz

Create a **Service Account** (Settings → Service Accounts) of type *Custom Integration (GraphQL API)* with the scopes:

- `read:resources` (graph search)
- `read:issues` (open-issue counts, and the job's issue status check)
- `write:issues` (only needed for the Sync Closed Cases To Wiz job)

Note the **Client ID** and **Client Secret**, and copy your tenant's **API Endpoint URL** from User Settings → Tenant (for example `https://api.us17.app.wiz.io/graphql`).

## Deploy to Google SecOps

You need a SecOps role with IDE access.

1. **Create the integration.** Go to **Response → IDE**, click **+**, and choose **Integration**. Name it exactly **`WizEnrichment`**, because the scripts look up configuration under this name (`INTEGRATION_NAME`).
2. **Add integration parameters.** Open the integration's settings in the IDE and add:

   | Parameter | Type | Mandatory | Default |
   |---|---|---|---|
   | `API URL` | String | Yes | `https://api.<region>.app.wiz.io/graphql` |
   | `Auth URL` | String | No | `https://auth.app.wiz.io/oauth/token` |
   | `Client ID` | String | Yes | |
   | `Client Secret` | Password | Yes | |
   | `Verify SSL` | Boolean | No | `true` |

3. **Add the manager.** In the integration, click **+** → **Manager**, name it **`WizManager`**, paste `WizEnrichment/Managers/WizManager.py`, and save. The actions import it with `from WizManager import WizManager`.
4. **Add the actions.**
   - **+** → **Action**, name it **`Ping`**, paste `ActionsScripts/Ping.py`, and save. No parameters.
   - **+** → **Action**, name it **`Enrich Hostname`**, paste `ActionsScripts/EnrichHostname.py`, and add these action parameters:

     | Parameter | Type | Mandatory | Default | Notes |
     |---|---|---|---|---|
     | `Wiz Entity Types` | String | No | `VIRTUAL_MACHINE` | Comma-separated Wiz graph types to search |
     | `Match Type` | DDL (`Exact`, `Contains`) | No | `Exact` | |
     | `Include Open Issues` | Boolean | No | `true` | Needs the `read:issues` scope |
     | `Create Insight` | Boolean | No | `true` | |
     | `Max Results Per Hostname` | String | No | `10` | |

     Set the action's supported entity type to **Hostname**, then save.
   - Turn on both actions with the toggle in the IDE.
5. **Configure an instance.** Go to **Marketplace → Response Integrations** (or **Settings → Integrations**, depending on your SecOps version), find `WizEnrichment`, add an instance in the right environment, fill in the credentials, and click **Test**. This runs Ping.
6. **Use it.** Add **WizEnrichment – Enrich Hostname** to a playbook, or run it manually from a case. Enriched fields show up on the entity as `Wiz_*`. Downstream playbook steps can read the JSON result as `[WizEnrichment_Enrich Hostname_1.JsonResult]`.

`requests` is already in the SecOps Python environment. If your instance reports it missing, add it under the integration's **Dependencies**.

## Sync closed cases to Wiz (job)

`Jobs/SyncClosedCasesToWiz.py` keeps Wiz in step when analysts close cases in SecOps. Each run:

1. Calls `get_cases_ids_by_filter(status="CLOSE", close_time_from/to=...)` for cases closed in the last **Lookback Minutes**.
2. Loads each case with `_get_case_by_id` and loops over `cyber_alerts`. Alerts are skipped if `IsTestCase` is `True` or `DeviceProduct` doesn't contain **Wiz Product Name**.
3. Reads the Wiz issue ID from the first field in **Wiz Issue ID Fields** that holds a UUID. It checks `additional_properties` first, then the alert itself. Values like `wiz_<uuid>` are reduced to the UUID.
4. Queries the issue in Wiz. Issues already `RESOLVED` or `REJECTED` are skipped. Every other issue is updated with the `updateIssue` mutation to **Wiz Close Status**, **Resolution Reason**, and **Resolution Note**.
5. If any case or issue fails, the job logs it, finishes the rest, then raises an error so the run shows as failed in the job history.

### Deploy

In the IDE: **+** → **Job**, name it **`Sync Closed Cases To Wiz`**, paste `Jobs/SyncClosedCasesToWiz.py`, and add these parameters:

| Parameter | Type | Mandatory | Default | Notes |
|---|---|---|---|---|
| `API URL` | String | Yes | | Same as the integration |
| `Auth URL` | String | No | `https://auth.app.wiz.io/oauth/token` | |
| `Client ID` | String | Yes | | Service account needs `read:issues` and `write:issues` |
| `Client Secret` | Password | Yes | | |
| `Verify SSL` | Boolean | No | `true` | |
| `Lookback Minutes` | String | No | `10` | |
| `Wiz Issue ID Fields` | String | No | `ThreadId,SourceGroupingIdentifier,security_result_threat_id` | Alert fields to read the Wiz issue ID from, in order |
| `Wiz Product Name` | String | No | `Wiz` | Matched against the alert's `DeviceProduct`. Empty = all alerts |
| `Wiz Close Status` | String | No | `RESOLVED` | `RESOLVED` or `REJECTED` |
| `Resolution Reason` | String | No | `INCONCLUSIVE_THREAT` | Wiz enum. RESOLVED: `MALICIOUS_THREAT`, `NOT_MALICIOUS_THREAT`, `SECURITY_TEST_THREAT`, `PLANNED_ACTION_THREAT`, `INCONCLUSIVE_THREAT`. REJECTED: `FALSE_POSITIVE`, `EXCEPTION`, `WONT_FIX` |
| `Resolution Note` | String | No | `Closed via Google SecOps case {case_id}` | `{case_id}` is replaced |

Then go to **Response → Job Scheduler**, add the job, and schedule it to run **every 10 minutes or less** (no longer than *Lookback Minutes*), otherwise cases closed between runs are missed. Overlapping windows are safe, because already-closed issues are skipped.

Before scheduling it, open a closed Wiz case, check which alert field holds the Wiz issue ID, and make sure it's listed in **Wiz Issue ID Fields**.

## Run the tests locally

```bash
python3 -m unittest discover -s tests -v
```

The tests replace the SecOps SDK with the stubs in `tests/stubs` and mock the Wiz API. They don't call a real Wiz tenant.

## Known limitations

- The GraphQL query shapes (`graphSearch` with `where.name.EQUALS/CONTAINS`, and `issuesV2` with `relatedEntity.id`) follow Wiz's public API conventions but have **not been tested against a live tenant**. Run Ping, then one manual Enrich Hostname on a host you know exists, before using it in a playbook. If your tenant's schema differs, change the queries in `WizManager.py` only.
- Only the first match is used for enrichment. All matches, up to *Max Results Per Hostname*, are in the JSON result.
- Open-issue counts are taken from at most the first 100 issues returned. `Wiz_open_issues` is Wiz's `totalCount`.
- The job's SecOps calls (`get_cases_ids_by_filter`, `_get_case_by_id`) and Wiz calls (`issue`, `updateIssue`) match Google's own marketplace Wiz/sync jobs, but the job has **not been run against a live tenant**. Test it once with a short schedule and check the job log.
- The job uses a fixed lookback window, not a saved timestamp. If the scheduler is down for longer than *Lookback Minutes*, cases closed in that gap aren't synced. Raise *Lookback Minutes* for a one-off catch-up run.
- The job closes a Wiz issue as soon as one SecOps case containing it is closed. It does not check whether other open cases reference the same issue.
- Wiz only lets you set some issue types to `RESOLVED` manually (for example threat-detection issues). For others, use `REJECTED`. Failed updates appear in the job log and fail the run.
