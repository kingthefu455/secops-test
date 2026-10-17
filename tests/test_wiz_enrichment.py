import importlib
import os
import sys
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path[:0] = [
    os.path.join(ROOT, "tests", "stubs"),
    os.path.join(ROOT, "WizEnrichment", "Managers"),
    os.path.join(ROOT, "WizEnrichment", "ActionsScripts"),
]

import WizManager  # noqa: E402
from SiemplifyAction import SiemplifyAction  # noqa: E402
from SiemplifyDataModel import Entity, EntityTypes  # noqa: E402
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED  # noqa: E402

VM = {
    "id": "vm-123",
    "name": "web-01",
    "type": "VIRTUAL_MACHINE",
    "properties": {
        "cloudPlatform": "AWS",
        "region": "us-east-1",
        "operatingSystem": "Linux",
        "tags": {"env": "prod"},
        "ipAddresses": ["10.0.0.5", "54.1.2.3"],
    },
}


class FakeResponse(object):
    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code
        self.text = str(payload)

    def json(self):
        return self._payload


class FakeWiz(object):
    """Routes token and GraphQL calls to canned responses and records requests."""

    def __init__(self, graph_entities, issues=None, issues_error=None):
        self.graph_entities = graph_entities
        self.issues = issues if issues is not None else []
        self.issues_error = issues_error
        self.graphql_calls = []
        self.token_calls = []

    def post(self, url, headers=None, data=None, json=None, timeout=None):
        if url.endswith("/oauth/token"):
            self.token_calls.append(data)
            return FakeResponse({"access_token": "tok", "expires_in": 3600})
        self.graphql_calls.append(json)
        if "issuesV2" in json["query"]:
            if self.issues_error:
                return FakeResponse({"errors": [{"message": self.issues_error}]})
            return FakeResponse({"data": {"issuesV2": {"totalCount": len(self.issues), "nodes": self.issues}}})
        return FakeResponse({"data": {"graphSearch": {
            "pageInfo": {"hasNextPage": False},
            "nodes": [{"entities": [e]} for e in self.graph_entities],
        }}})


def make_manager(fake):
    manager = WizManager.WizManager("https://api.us17.app.wiz.io/graphql", "id", "secret")
    manager.session.post = fake.post
    return manager


class WizManagerTests(unittest.TestCase):
    def test_audience_selection(self):
        self.assertEqual(WizManager.WizManager("u", "i", "s").audience, "wiz-api")
        legacy = WizManager.WizManager("u", "i", "s", auth_url="https://auth.wiz.io/oauth/token")
        self.assertEqual(legacy.audience, "beyond-api")

    def test_hostname_variants(self):
        self.assertEqual(WizManager.WizManager.hostname_variants("WEB-01.CORP.LOCAL"),
                         ["WEB-01.CORP.LOCAL", "web-01.corp.local", "WEB-01", "web-01"])

    def test_search_hosts_exact_filters_case_insensitively(self):
        fake = FakeWiz([VM, dict(VM, id="vm-999", name="web-01-old")])
        results = make_manager(fake).search_hosts("WEB-01", ["VIRTUAL_MACHINE"])
        self.assertEqual([r["id"] for r in results], ["vm-123"])
        where = fake.graphql_calls[0]["variables"]["query"]["where"]
        self.assertEqual(where, {"name": {"EQUALS": ["WEB-01", "web-01"]}})

    def test_token_is_cached(self):
        fake = FakeWiz([VM])
        manager = make_manager(fake)
        manager.search_hosts("web-01", ["VIRTUAL_MACHINE"])
        manager.search_hosts("web-01", ["VIRTUAL_MACHINE"])
        self.assertEqual(len(fake.token_calls), 1)

    def test_graphql_errors_raise(self):
        fake = FakeWiz([])
        fake.post = lambda *a, **k: FakeResponse({"errors": [{"message": "boom"}]}) \
            if not a[0].endswith("/oauth/token") else FakeResponse({"access_token": "t"})
        with self.assertRaises(WizManager.WizManagerError):
            make_manager(fake).search_hosts("x", ["VIRTUAL_MACHINE"])

    def test_issue_summary_counts(self):
        fake = FakeWiz([], issues=[{"id": "1", "severity": "CRITICAL"}, {"id": "2", "severity": "HIGH"},
                                   {"id": "3", "severity": "HIGH"}])
        summary = make_manager(fake).get_open_issue_summary("vm-123")
        self.assertEqual(summary["total_open"], 3)
        self.assertEqual(summary["by_severity"]["HIGH"], 2)
        self.assertEqual(fake.graphql_calls[0]["variables"]["filterBy"]["relatedEntity"], {"id": "vm-123"})


class EnrichHostnameActionTests(unittest.TestCase):
    def run_action(self, fake, entities, params=None):
        SiemplifyAction.config = {"API URL": "https://api.us17.app.wiz.io/graphql", "Client ID": "id",
                                  "Client Secret": "secret", "Verify SSL": "true"}
        SiemplifyAction.params = params or {}
        SiemplifyAction.entities = entities
        action = importlib.import_module("EnrichHostname")
        with mock.patch.object(WizManager.requests.Session, "post", lambda self, *a, **k: fake.post(*a, **k)):
            action.main()
        return SiemplifyAction.last

    def test_enriches_found_hostname(self):
        host = Entity("WEB-01", EntityTypes.HOSTNAME)
        ip = Entity("10.0.0.5", EntityTypes.ADDRESS)
        fake = FakeWiz([VM], issues=[{"id": "1", "severity": "CRITICAL"}])
        siemplify = self.run_action(fake, [host, ip])

        message, result, status = siemplify.ended
        self.assertEqual(status, EXECUTION_STATE_COMPLETED)
        self.assertTrue(result)
        self.assertTrue(host.is_enriched)
        self.assertFalse(ip.is_enriched)
        props = host.additional_properties
        self.assertEqual(props["Wiz_id"], "vm-123")
        self.assertEqual(props["Wiz_cloudPlatform"], "AWS")
        self.assertEqual(props["Wiz_ipAddresses"], "10.0.0.5, 54.1.2.3")
        self.assertEqual(props["Wiz_open_issues_critical"], "1")
        self.assertNotIn("Wiz_tags", props)
        self.assertEqual(siemplify.updated_entities, [host])
        self.assertIn("WEB-01", siemplify.result.entity_tables)
        self.assertEqual(siemplify.result.result_json[0]["Entity"], "WEB-01")
        self.assertEqual(len(siemplify.insights), 1)

    def test_not_found_and_issue_failure_are_reported(self):
        host = Entity("WEB-01", EntityTypes.HOSTNAME)
        missing = Entity("NOPE", EntityTypes.HOSTNAME)
        fake = FakeWiz([VM], issues_error="field not found")
        fake_post = fake.post

        def post(url, **kwargs):
            json_body = kwargs.get("json")
            if json_body and "graphSearch" in json_body["query"] and \
                    "NOPE" in json_body["variables"]["query"]["where"]["name"]["EQUALS"]:
                return FakeResponse({"data": {"graphSearch": {"nodes": []}}})
            return fake_post(url, **kwargs)
        fake.post = post

        siemplify = self.run_action(fake, [host, missing], {"Create Insight": "false"})
        message, result, status = siemplify.ended
        self.assertEqual(status, EXECUTION_STATE_COMPLETED)
        self.assertIn("Not found in Wiz: NOPE", message)
        self.assertIn("Open-issue lookup failed for: WEB-01", message)
        self.assertTrue(host.is_enriched)
        self.assertNotIn("Wiz_open_issues", host.additional_properties)
        self.assertEqual(siemplify.insights, [])

    def test_auth_failure_fails_action(self):
        host = Entity("WEB-01", EntityTypes.HOSTNAME)
        fake = FakeWiz([VM])
        fake.post = lambda url, **k: FakeResponse({"error": "access_denied"}, status_code=401)
        siemplify = self.run_action(fake, [host])
        message, result, status = siemplify.ended
        self.assertEqual(status, EXECUTION_STATE_FAILED)
        self.assertIn("Failed to enrich: WEB-01", message)


if __name__ == "__main__":
    unittest.main()
