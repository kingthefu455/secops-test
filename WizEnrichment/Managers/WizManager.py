"""Thin client for the Wiz GraphQL API, used by the WizEnrichment SecOps integration."""

import time
from urllib.parse import urlparse

import requests

DEFAULT_AUTH_URL = "https://auth.app.wiz.io/oauth/token"
# Wiz tenants on the legacy Auth0 provider (auth.wiz.io) use a different audience.
LEGACY_AUTH_HOST = "auth.wiz.io"
AUDIENCE_COGNITO = "wiz-api"
AUDIENCE_AUTH0 = "beyond-api"

TOKEN_EXPIRY_BUFFER_SECONDS = 60
DEFAULT_TIMEOUT_SECONDS = 60

GRAPH_SEARCH_QUERY = """
query GraphSearch($query: GraphEntityQueryInput, $projectId: String!, $first: Int, $after: String, $quick: Boolean = true) {
  graphSearch(query: $query, projectId: $projectId, first: $first, after: $after, quick: $quick) {
    pageInfo {
      endCursor
      hasNextPage
    }
    nodes {
      entities {
        id
        name
        type
        properties
      }
    }
  }
}
"""

ISSUES_QUERY = """
query EntityIssues($filterBy: IssueFilters, $first: Int) {
  issuesV2(filterBy: $filterBy, first: $first) {
    totalCount
    nodes {
      id
      severity
      status
      createdAt
    }
  }
}
"""

GET_ISSUE_QUERY = """
query GetIssue($id: ID!) {
  issue(id: $id) {
    id
    status
  }
}
"""

UPDATE_ISSUE_MUTATION = """
mutation UpdateIssue($issueId: ID!, $patch: UpdateIssuePatch) {
  updateIssue(input: {id: $issueId, patch: $patch}) {
    issue {
      id
      status
      resolutionReason
    }
  }
}
"""

OPEN_ISSUE_STATUSES = ["OPEN", "IN_PROGRESS"]
CLOSED_ISSUE_STATUSES = ["RESOLVED", "REJECTED"]
SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]


class WizManagerError(Exception):
    pass


class WizManager(object):
    def __init__(self, api_url, client_id, client_secret, auth_url=DEFAULT_AUTH_URL,
                 verify_ssl=True, timeout=DEFAULT_TIMEOUT_SECONDS, logger=None):
        self.api_url = api_url.strip().rstrip("/")
        self.auth_url = (auth_url or DEFAULT_AUTH_URL).strip()
        self.client_id = client_id
        self.client_secret = client_secret
        self.timeout = timeout
        self.logger = logger
        self.session = requests.Session()
        self.session.verify = verify_ssl
        self._token = None
        self._token_expires_at = 0

    @property
    def audience(self):
        return AUDIENCE_AUTH0 if urlparse(self.auth_url).hostname == LEGACY_AUTH_HOST else AUDIENCE_COGNITO

    def _get_token(self):
        if self._token and time.time() < self._token_expires_at - TOKEN_EXPIRY_BUFFER_SECONDS:
            return self._token

        response = self.session.post(
            self.auth_url,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data={
                "grant_type": "client_credentials",
                "audience": self.audience,
                "client_id": self.client_id,
                "client_secret": self.client_secret,
            },
            timeout=self.timeout,
        )
        if response.status_code != 200:
            raise WizManagerError(
                "Wiz authentication failed (HTTP {}): {}".format(response.status_code, response.text[:500]))

        payload = response.json()
        token = payload.get("access_token")
        if not token:
            raise WizManagerError("Wiz authentication response did not contain an access_token")

        self._token = token
        self._token_expires_at = time.time() + int(payload.get("expires_in", 3600))
        return token

    def _graphql(self, query, variables):
        response = self.session.post(
            self.api_url,
            headers={
                "Authorization": "Bearer {}".format(self._get_token()),
                "Content-Type": "application/json",
            },
            json={"query": query, "variables": variables},
            timeout=self.timeout,
        )
        if response.status_code != 200:
            raise WizManagerError(
                "Wiz API request failed (HTTP {}): {}".format(response.status_code, response.text[:500]))

        payload = response.json()
        if payload.get("errors"):
            messages = "; ".join(e.get("message", str(e)) for e in payload["errors"])
            raise WizManagerError("Wiz API returned errors: {}".format(messages))
        return payload.get("data") or {}

    def test_connectivity(self):
        self._graphql(GRAPH_SEARCH_QUERY, {
            "quick": True,
            "first": 1,
            "projectId": "*",
            "query": {"type": ["VIRTUAL_MACHINE"], "select": True},
        })
        return True

    @staticmethod
    def hostname_variants(hostname):
        """SecOps upper-cases entity identifiers, so search the original, lower-case and short-name forms."""
        hostname = hostname.strip()
        variants = [hostname, hostname.lower()]
        short_name = hostname.split(".", 1)[0]
        if short_name != hostname:
            variants.extend([short_name, short_name.lower()])
        seen = set()
        return [v for v in variants if not (v in seen or seen.add(v))]

    def search_hosts(self, hostname, entity_types, exact_match=True, limit=10):
        """Return Wiz graph entities whose name matches the hostname."""
        if exact_match:
            name_filter = {"EQUALS": self.hostname_variants(hostname)}
        else:
            name_filter = {"CONTAINS": [hostname.strip().lower()]}

        data = self._graphql(GRAPH_SEARCH_QUERY, {
            "quick": True,
            "first": limit,
            "projectId": "*",
            "query": {
                "type": entity_types,
                "select": True,
                "where": {"name": name_filter},
            },
        })

        results = []
        for node in (data.get("graphSearch") or {}).get("nodes") or []:
            for entity in node.get("entities") or []:
                if entity:
                    results.append(entity)

        if exact_match:
            wanted = {v.lower() for v in self.hostname_variants(hostname)}
            results = [e for e in results if (e.get("name") or "").lower() in wanted]
        return results[:limit]

    def get_open_issue_summary(self, entity_id, limit=100):
        data = self._graphql(ISSUES_QUERY, {
            "first": limit,
            "filterBy": {
                "relatedEntity": {"id": entity_id},
                "status": OPEN_ISSUE_STATUSES,
            },
        })
        issues = data.get("issuesV2") or {}
        counts = dict((severity, 0) for severity in SEVERITIES)
        for issue in issues.get("nodes") or []:
            severity = (issue.get("severity") or "").upper()
            if severity in counts:
                counts[severity] += 1
        return {
            "total_open": issues.get("totalCount", 0),
            "by_severity": counts,
            "issues": issues.get("nodes") or [],
        }

    def get_issue(self, issue_id):
        data = self._graphql(GET_ISSUE_QUERY, {"id": issue_id})
        issue = data.get("issue")
        if not issue:
            raise WizManagerError("Wiz issue {} was not found".format(issue_id))
        return issue

    def close_issue(self, issue_id, status="RESOLVED", resolution_reason=None, note=None):
        """Set an issue to RESOLVED or REJECTED. Wiz stores the note as resolutionNote for RESOLVED and note for REJECTED."""
        status = status.upper()
        if status not in CLOSED_ISSUE_STATUSES:
            raise WizManagerError("Unsupported close status {}, expected one of {}".format(
                status, ", ".join(CLOSED_ISSUE_STATUSES)))
        patch = {"status": status}
        if resolution_reason:
            patch["resolutionReason"] = resolution_reason
        if note:
            patch["resolutionNote" if status == "RESOLVED" else "note"] = note
        data = self._graphql(UPDATE_ISSUE_MUTATION, {"issueId": issue_id, "patch": patch})
        return ((data.get("updateIssue") or {}).get("issue")) or {}
