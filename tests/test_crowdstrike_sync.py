import importlib
import os
import sys
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path[:0] = [
    os.path.join(ROOT, "tests", "stubs"),
    os.path.join(ROOT, "CrowdStrikeSync", "Managers"),
    os.path.join(ROOT, "CrowdStrikeSync", "Jobs"),
]

import FalconManager  # noqa: E402
from SiemplifyJob import SiemplifyJob  # noqa: E402

CID = "0123456789abcdef0123456789abcdef"
AID = "fedcba9876543210fedcba9876543210"
DET_A = "{}:ind:{}:11111111111-10148-1".format(CID, AID)
DET_B = "{}:ind:{}:22222222222-10148-2".format(CID, AID)
LEGACY = "ldt:{}:12345678901".format(AID)


class FakeResponse(object):
    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code
        self.text = str(payload)

    def json(self):
        return self._payload


class FakeFalcon(object):
    """Answers token, alert lookup and alert update calls, recording the updates."""

    def __init__(self, statuses, fail_update=()):
        self.statuses = statuses
        self.fail_update = fail_update
        self.token_calls = []
        self.updates = []

    def post(self, url, headers=None, data=None, timeout=None, **kwargs):
        self.token_calls.append(data)
        return FakeResponse({"access_token": "tok", "expires_in": 1799}, status_code=201)

    def request(self, method, url, headers=None, json=None, timeout=None):
        composite_id = json["composite_ids"][0]
        if method == "PATCH" and url.endswith("/alerts/entities/alerts/v3"):
            if composite_id in self.fail_update:
                return FakeResponse({"errors": [{"code": 403, "message": "access denied"}]}, status_code=403)
            self.updates.append(json)
            return FakeResponse({"errors": [], "resources": []})
        if method == "POST" and url.endswith("/alerts/entities/alerts/v2"):
            if composite_id not in self.statuses:
                return FakeResponse({"errors": [{"code": 404, "message": "not found"}], "resources": []},
                                    status_code=404)
            return FakeResponse({"errors": [], "resources": [
                {"composite_id": composite_id, "status": self.statuses[composite_id]}]})
        raise AssertionError("unexpected request {} {}".format(method, url))


def cs_alert(detection_id, field="TicketId", product="CrowdStrike Falcon", test_case="False"):
    return {"identifier": "alert-" + detection_id[-6:],
            "additional_properties": {field: detection_id, "DeviceProduct": product, "IsTestCase": test_case}}


def make_manager(fake):
    manager = FalconManager.FalconManager("https://api.eu-1.crowdstrike.com/", "id", "secret")
    manager.session.post = fake.post
    manager.session.request = fake.request
    return manager


class FalconManagerTests(unittest.TestCase):
    def test_close_alert_payload_and_token_cache(self):
        fake = FakeFalcon({DET_A: "new"})
        manager = make_manager(fake)
        self.assertEqual(manager.get_alert(DET_A)["status"], "new")
        manager.close_alert(DET_A, comment="done")
        self.assertEqual(len(fake.token_calls), 1)
        self.assertEqual(fake.updates, [{"composite_ids": [DET_A], "action_parameters": [
            {"name": "update_status", "value": "closed"}, {"name": "append_comment", "value": "done"}]}])

    def test_api_errors_raise(self):
        manager = make_manager(FakeFalcon({}))
        with self.assertRaises(FalconManager.FalconManagerError):
            manager.get_alert(DET_A)


class SyncClosedCasesJobTests(unittest.TestCase):
    def run_job(self, fake, cases, params=None):
        SiemplifyJob.params = dict({"API Root": "https://api.crowdstrike.com", "Client ID": "id",
                                    "Client Secret": "secret"}, **(params or {}))
        SiemplifyJob.case_ids = list(cases)
        SiemplifyJob.cases = cases
        job = importlib.import_module("SyncClosedCasesToCrowdStrike")
        with mock.patch.object(FalconManager.requests.Session, "post",
                               lambda self, *a, **k: fake.post(*a, **k)), \
                mock.patch.object(FalconManager.requests.Session, "request",
                                  lambda self, *a, **k: fake.request(*a, **k)):
            job.main()
        return SiemplifyJob.last

    def test_closes_open_detections_from_recently_closed_cases(self):
        fake = FakeFalcon({DET_A: "new", DET_B: "closed"})
        cases = {
            "1": {"cyber_alerts": [cs_alert(DET_A), cs_alert(DET_A), cs_alert(DET_B)]},
            "2": {"cyber_alerts": [cs_alert("prefix " + DET_B, field="SourceGroupingIdentifier")]},
        }
        siemplify = self.run_job(fake, cases)

        self.assertTrue(siemplify.ended)
        self.assertEqual(siemplify.case_filter["status"], "CLOSE")
        window = siemplify.case_filter["close_time_to_unix_time_in_ms"] - \
            siemplify.case_filter["close_time_from_unix_time_in_ms"]
        self.assertEqual(window, 10 * 60 * 1000)
        self.assertEqual(fake.updates, [{"composite_ids": [DET_A], "action_parameters": [
            {"name": "update_status", "value": "closed"},
            {"name": "append_comment", "value": "Closed via Google SecOps case 1"}]}])

    def test_skips_test_cases_other_products_and_id_less_alerts(self):
        fake = FakeFalcon({DET_A: "new"})
        cases = {"1": {"cyber_alerts": [
            cs_alert(DET_A, product="Wiz"),
            cs_alert(DET_A, test_case="True"),
            cs_alert("11111111-2222-3333-4444-555555555555"),
            {"identifier": "no-props"},
        ]}}
        siemplify = self.run_job(fake, cases, {"Product Name": "CrowdStrike"})
        self.assertTrue(siemplify.ended)
        self.assertEqual(fake.updates, [])

    def test_legacy_ids_and_api_failures_fail_the_job_after_processing_everything(self):
        fake = FakeFalcon({DET_A: "in_progress", DET_B: "new"}, fail_update=(DET_A,))
        cases = {"1": {"cyber_alerts": [cs_alert(DET_A), cs_alert(LEGACY), cs_alert(DET_B)]}}
        with self.assertRaises(Exception) as ctx:
            self.run_job(fake, cases, {"Lookback Minutes": "5"})
        self.assertIn(DET_A, str(ctx.exception))
        self.assertIn(LEGACY, str(ctx.exception))
        self.assertEqual([u["composite_ids"] for u in fake.updates], [[DET_B]])
        self.assertFalse(SiemplifyJob.last.ended)
        window = SiemplifyJob.last.case_filter["close_time_to_unix_time_in_ms"] - \
            SiemplifyJob.last.case_filter["close_time_from_unix_time_in_ms"]
        self.assertEqual(window, 5 * 60 * 1000)


if __name__ == "__main__":
    unittest.main()
