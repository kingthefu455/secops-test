# WizEnrichment – Google SecOps custom integration

A Google SecOps (SOAR) custom integration with two actions:

| Action | What it does |
|---|---|
| **Ping** | Authenticates to Wiz and runs a one-row graph search to check credentials and scopes. |
| **Enrich Hostname** | For every `Hostname` entity in scope, searches the Wiz Security Graph by name, enriches the SecOps entity with `Wiz_*` properties, optionally adds open-issue counts and an entity insight, and returns the full Wiz data as JSON. |

```
WizEnrichment/
  Managers/WizManager.py          # Wiz OAuth + GraphQL client (IDE "Manager")
  ActionsScripts/Ping.py          # IDE action "Ping"
  ActionsScripts/EnrichHostname.py # IDE action "Enrich Hostname"
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
- `read:issues` (only needed for open-issue counts)

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

## Run the tests locally

```bash
python3 -m unittest discover -s tests -v
```

The tests replace the SecOps SDK with the stubs in `tests/stubs` and mock the Wiz API. They don't call a real Wiz tenant.

## Known limitations

- The GraphQL query shapes (`graphSearch` with `where.name.EQUALS/CONTAINS`, and `issuesV2` with `relatedEntity.id`) follow Wiz's public API conventions but have **not been tested against a live tenant**. Run Ping, then one manual Enrich Hostname on a host you know exists, before using it in a playbook. If your tenant's schema differs, change the queries in `WizManager.py` only.
- Only the first match is used for enrichment. All matches, up to *Max Results Per Hostname*, are in the JSON result.
- Open-issue counts are taken from at most the first 100 issues returned. `Wiz_open_issues` is Wiz's `totalCount`.
