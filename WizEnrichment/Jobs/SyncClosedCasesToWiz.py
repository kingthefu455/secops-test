import json
import re

from SiemplifyJob import SiemplifyJob
from SiemplifyUtils import output_handler, unix_now

from WizManager import WizManager, CLOSED_ISSUE_STATUSES

SCRIPT_NAME = "WizEnrichment - Sync Closed Cases To Wiz"
DEFAULT_LOOKBACK_MINUTES = 10
DEFAULT_ISSUE_ID_FIELDS = "ThreadId,SourceGroupingIdentifier,security_result_threat_id"
DEFAULT_PRODUCT = "Wiz"
DEFAULT_CLOSE_STATUS = "RESOLVED"
DEFAULT_RESOLUTION_REASON = "INCONCLUSIVE_THREAT"
DEFAULT_NOTE = "Closed via Google SecOps case {case_id}"
MAX_CASES = 1000
UUID_PATTERN = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.IGNORECASE)


def to_bool(value, default=False):
    if value is None or value == "":
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("true", "1", "yes")


def split_csv(value):
    return [v.strip() for v in (value or "").split(",") if v.strip()]


def alert_properties(alert):
    """additional_properties is a dict in _get_case_by_id payloads but a JSON string in some SDK versions."""
    props = alert.get("additional_properties") or {}
    if isinstance(props, str):
        try:
            props = json.loads(props)
        except ValueError:
            return {}
    return props if isinstance(props, dict) else {}


def lookup(alert, props, field):
    for source in (props, alert):
        for key in (field, field[:1].lower() + field[1:], field[:1].upper() + field[1:]):
            if source.get(key):
                return str(source[key])
    return None


def extract_issue_id(alert, props, fields):
    """Return the Wiz issue UUID from the first configured alert field that has one.

    Values like "wiz_<uuid>" are reduced to the UUID, matching Google's Wiz sync job.
    """
    for field in fields:
        value = lookup(alert, props, field)
        if value:
            matches = UUID_PATTERN.findall(value)
            if matches:
                return matches[-1].lower()
    return None


def is_wiz_alert(props, product):
    if not product:
        return True
    return product.lower() in (props.get("DeviceProduct") or "").lower()


def collect_issue_ids(case, issue_id_fields, product):
    issue_ids = []
    for alert in case.get("cyber_alerts") or []:
        props = alert_properties(alert)
        if str(props.get("IsTestCase", "")).lower() == "true" or not is_wiz_alert(props, product):
            continue
        issue_id = extract_issue_id(alert, props, issue_id_fields)
        if issue_id and issue_id not in issue_ids:
            issue_ids.append(issue_id)
    return issue_ids


@output_handler
def main():
    siemplify = SiemplifyJob()
    siemplify.script_name = SCRIPT_NAME
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    api_url = siemplify.extract_job_param(param_name="API URL", is_mandatory=True, print_value=True)
    auth_url = siemplify.extract_job_param(param_name="Auth URL", print_value=True)
    client_id = siemplify.extract_job_param(param_name="Client ID", is_mandatory=True, print_value=True)
    client_secret = siemplify.extract_job_param(param_name="Client Secret", is_mandatory=True)
    verify_ssl = to_bool(siemplify.extract_job_param(param_name="Verify SSL", print_value=True), default=True)
    lookback_minutes = int(siemplify.extract_job_param(
        param_name="Lookback Minutes", default_value=DEFAULT_LOOKBACK_MINUTES, print_value=True)
        or DEFAULT_LOOKBACK_MINUTES)
    issue_id_fields = split_csv(siemplify.extract_job_param(
        param_name="Wiz Issue ID Fields", default_value=DEFAULT_ISSUE_ID_FIELDS, print_value=True)
        or DEFAULT_ISSUE_ID_FIELDS)
    product = siemplify.extract_job_param(param_name="Wiz Product Name", default_value=DEFAULT_PRODUCT,
                                          print_value=True)
    product = DEFAULT_PRODUCT if product is None else product.strip()
    close_status = (siemplify.extract_job_param(param_name="Wiz Close Status", default_value=DEFAULT_CLOSE_STATUS,
                                                print_value=True) or DEFAULT_CLOSE_STATUS).strip().upper()
    resolution_reason = (siemplify.extract_job_param(
        param_name="Resolution Reason", default_value=DEFAULT_RESOLUTION_REASON, print_value=True)
        or "").strip().upper() or None
    note_template = siemplify.extract_job_param(param_name="Resolution Note", default_value=DEFAULT_NOTE,
                                                print_value=True) or DEFAULT_NOTE

    siemplify.LOGGER.info("----------------- Main - Started -----------------")
    if lookback_minutes < 1:
        raise ValueError("Lookback Minutes must be at least 1")
    if close_status not in CLOSED_ISSUE_STATUSES:
        raise ValueError("Wiz Close Status must be one of {}".format(", ".join(CLOSED_ISSUE_STATUSES)))

    manager = WizManager(api_url, client_id, client_secret, auth_url=auth_url,
                         verify_ssl=verify_ssl, logger=siemplify.LOGGER)

    now_ms = unix_now()
    case_ids = siemplify.get_cases_ids_by_filter(
        status="CLOSE",
        close_time_from_unix_time_in_ms=now_ms - lookback_minutes * 60 * 1000,
        close_time_to_unix_time_in_ms=now_ms,
        sort_by="UPDATE_TIME",
        sort_order="ASC",
        max_results=MAX_CASES,
    ) or []
    siemplify.LOGGER.info("Found {} case(s) closed in the last {} minute(s)".format(len(case_ids), lookback_minutes))

    closed, already_closed, failed = [], [], []
    for case_id in case_ids:
        try:
            case = siemplify._get_case_by_id(str(case_id))
        except Exception as e:
            siemplify.LOGGER.error("Failed to load case {}: {}".format(case_id, e))
            siemplify.LOGGER.exception(e)
            failed.append("case {}".format(case_id))
            continue

        issue_ids = collect_issue_ids(case, issue_id_fields, product)
        if not issue_ids:
            siemplify.LOGGER.info("Case {}: no Wiz issue IDs found in its alerts, skipping".format(case_id))
            continue

        for issue_id in issue_ids:
            try:
                status = (manager.get_issue(issue_id).get("status") or "").upper()
                if status in CLOSED_ISSUE_STATUSES:
                    siemplify.LOGGER.info("Case {}: Wiz issue {} is already {}".format(case_id, issue_id, status))
                    already_closed.append(issue_id)
                    continue
                manager.close_issue(issue_id, status=close_status, resolution_reason=resolution_reason,
                                    note=note_template.format(case_id=case_id))
                siemplify.LOGGER.info("Case {}: set Wiz issue {} to {}".format(case_id, issue_id, close_status))
                closed.append(issue_id)
            except Exception as e:
                siemplify.LOGGER.error("Case {}: failed to close Wiz issue {}: {}".format(case_id, issue_id, e))
                siemplify.LOGGER.exception(e)
                failed.append(issue_id)

    siemplify.LOGGER.info("Closed: {}; already closed: {}; failed: {}".format(
        len(closed), len(already_closed), len(failed)))
    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    if failed:
        # Fail the run so a broken SecOps -> Wiz sync shows up in the job history.
        raise Exception("Failed to sync {} item(s) to Wiz: {}".format(len(failed), ", ".join(failed)))
    siemplify.end_script()


if __name__ == "__main__":
    main()
