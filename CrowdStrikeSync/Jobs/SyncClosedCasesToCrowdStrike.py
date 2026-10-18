import json
import re

from SiemplifyJob import SiemplifyJob
from SiemplifyUtils import output_handler, unix_now

from FalconManager import FalconManager, CLOSED_STATUS

SCRIPT_NAME = "CrowdStrikeSync - Sync Closed Cases To CrowdStrike"
DEFAULT_LOOKBACK_MINUTES = 10
DEFAULT_ID_FIELDS = "TicketId,ThreadId,SourceGroupingIdentifier"
DEFAULT_COMMENT = "Closed via Google SecOps case {case_id}"
MAX_CASES = 1000
# <cid>:<product>:..., e.g. "<32 hex cid>:ind:<32 hex aid>:<detection id>" for endpoint detections.
COMPOSITE_ID_PATTERN = re.compile(r"[0-9a-f]{32}:[a-z][a-z0-9_-]*:[^\s,;\"']+", re.IGNORECASE)
LEGACY_ID_PATTERN = re.compile(r"ldt:[0-9a-f]{32}:\d+", re.IGNORECASE)


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


def extract_detection_id(alert, props, fields):
    """Return (composite_id, legacy_id) from the first configured alert field that holds either."""
    for field in fields:
        value = lookup(alert, props, field)
        if not value:
            continue
        match = COMPOSITE_ID_PATTERN.search(value)
        if match:
            return match.group(0), None
        match = LEGACY_ID_PATTERN.search(value)
        if match:
            return None, match.group(0)
    return None, None


def is_product_alert(props, product):
    if not product:
        return True
    return product.lower() in (props.get("DeviceProduct") or "").lower()


def collect_detection_ids(case, id_fields, product):
    composite_ids, legacy_ids = [], []
    for alert in case.get("cyber_alerts") or []:
        props = alert_properties(alert)
        if str(props.get("IsTestCase", "")).lower() == "true" or not is_product_alert(props, product):
            continue
        composite_id, legacy_id = extract_detection_id(alert, props, id_fields)
        if composite_id and composite_id not in composite_ids:
            composite_ids.append(composite_id)
        if legacy_id and legacy_id not in legacy_ids:
            legacy_ids.append(legacy_id)
    return composite_ids, legacy_ids


@output_handler
def main():
    siemplify = SiemplifyJob()
    siemplify.script_name = SCRIPT_NAME
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    api_root = siemplify.extract_job_param(param_name="API Root", is_mandatory=True, print_value=True)
    client_id = siemplify.extract_job_param(param_name="Client ID", is_mandatory=True, print_value=True)
    client_secret = siemplify.extract_job_param(param_name="Client Secret", is_mandatory=True)
    verify_ssl = to_bool(siemplify.extract_job_param(param_name="Verify SSL", print_value=True), default=True)
    lookback_minutes = int(siemplify.extract_job_param(
        param_name="Lookback Minutes", default_value=DEFAULT_LOOKBACK_MINUTES, print_value=True)
        or DEFAULT_LOOKBACK_MINUTES)
    id_fields = split_csv(siemplify.extract_job_param(
        param_name="Detection ID Fields", default_value=DEFAULT_ID_FIELDS, print_value=True)
        or DEFAULT_ID_FIELDS)
    product = (siemplify.extract_job_param(param_name="Product Name", print_value=True) or "").strip()
    comment_template = siemplify.extract_job_param(param_name="Close Comment", default_value=DEFAULT_COMMENT,
                                                   print_value=True) or DEFAULT_COMMENT

    siemplify.LOGGER.info("----------------- Main - Started -----------------")
    if lookback_minutes < 1:
        raise ValueError("Lookback Minutes must be at least 1")

    manager = FalconManager(api_root, client_id, client_secret, verify_ssl=verify_ssl, logger=siemplify.LOGGER)

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

        composite_ids, legacy_ids = collect_detection_ids(case, id_fields, product)
        for legacy_id in legacy_ids:
            siemplify.LOGGER.error(
                "Case {}: {} is a legacy detection ID. The CrowdStrike Detects API is decommissioned, "
                "so only Alerts API composite IDs can be closed".format(case_id, legacy_id))
            failed.append(legacy_id)
        if not composite_ids and not legacy_ids:
            siemplify.LOGGER.info("Case {}: no CrowdStrike detection IDs found in its alerts, skipping".format(case_id))
            continue

        for composite_id in composite_ids:
            try:
                status = (manager.get_alert(composite_id).get("status") or "").lower()
                if status == CLOSED_STATUS:
                    siemplify.LOGGER.info("Case {}: CrowdStrike detection {} is already closed".format(
                        case_id, composite_id))
                    already_closed.append(composite_id)
                    continue
                manager.close_alert(composite_id, comment=comment_template.format(case_id=case_id))
                siemplify.LOGGER.info("Case {}: closed CrowdStrike detection {}".format(case_id, composite_id))
                closed.append(composite_id)
            except Exception as e:
                siemplify.LOGGER.error("Case {}: failed to close CrowdStrike detection {}: {}".format(
                    case_id, composite_id, e))
                siemplify.LOGGER.exception(e)
                failed.append(composite_id)

    siemplify.LOGGER.info("Closed: {}; already closed: {}; failed: {}".format(
        len(closed), len(already_closed), len(failed)))
    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    if failed:
        # Fail the run so a broken SecOps -> CrowdStrike sync shows up in the job history.
        raise Exception("Failed to sync {} item(s) to CrowdStrike: {}".format(len(failed), ", ".join(failed)))
    siemplify.end_script()


if __name__ == "__main__":
    main()
