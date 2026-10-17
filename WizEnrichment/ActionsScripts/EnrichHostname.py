import json

from SiemplifyAction import SiemplifyAction
from SiemplifyDataModel import EntityTypes
from SiemplifyUtils import output_handler, unix_now, flat_dict_to_csv
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED, EXECUTION_STATE_TIMEDOUT

from WizManager import WizManager

INTEGRATION_NAME = "WizEnrichment"
SCRIPT_NAME = "WizEnrichment - Enrich Hostname"
ENRICHMENT_PREFIX = "Wiz_"
DEFAULT_ENTITY_TYPES = "VIRTUAL_MACHINE"
# Stop this many ms before the action deadline so siemplify.end() still runs.
TIMEOUT_BUFFER_MS = 30 * 1000


def to_bool(value, default=False):
    if value is None or value == "":
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("true", "1", "yes")


def flatten_value(value):
    if isinstance(value, (list, tuple)):
        return ", ".join(flatten_value(v) for v in value)
    if isinstance(value, dict):
        return json.dumps(value, sort_keys=True)
    return "" if value is None else str(value)


def build_enrichment(wiz_entity, match_count, issue_summary=None):
    enrichment = {
        "id": wiz_entity.get("id"),
        "name": wiz_entity.get("name"),
        "type": wiz_entity.get("type"),
        "match_count": match_count,
    }
    for key, value in sorted((wiz_entity.get("properties") or {}).items()):
        # Properties holding nested objects add noise to the entity; they stay in the JSON result.
        if isinstance(value, dict):
            continue
        enrichment[key] = flatten_value(value)

    if issue_summary is not None:
        enrichment["open_issues"] = issue_summary["total_open"]
        for severity, count in issue_summary["by_severity"].items():
            enrichment["open_issues_{}".format(severity.lower())] = count

    return dict(("{}{}".format(ENRICHMENT_PREFIX, k), flatten_value(v)) for k, v in enrichment.items()
                if v not in (None, ""))


def build_insight(hostname, wiz_entity, issue_summary):
    properties = wiz_entity.get("properties") or {}
    lines = [
        "<b>Wiz {}:</b> {}".format(wiz_entity.get("type"), wiz_entity.get("name")),
        "Cloud: {} / Region: {}".format(properties.get("cloudPlatform", "N/A"), properties.get("region", "N/A")),
    ]
    if issue_summary is not None:
        counts = issue_summary["by_severity"]
        lines.append("Open issues: {} (Critical: {}, High: {})".format(
            issue_summary["total_open"], counts.get("CRITICAL", 0), counts.get("HIGH", 0)))
    return "<br>".join(lines)


def deadline_reached(siemplify):
    deadline = getattr(siemplify, "execution_deadline_unix_time_ms", None)
    return bool(deadline) and unix_now() >= deadline - TIMEOUT_BUFFER_MS


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    api_url = siemplify.extract_configuration_param(INTEGRATION_NAME, "API URL")
    auth_url = siemplify.extract_configuration_param(INTEGRATION_NAME, "Auth URL")
    client_id = siemplify.extract_configuration_param(INTEGRATION_NAME, "Client ID")
    client_secret = siemplify.extract_configuration_param(INTEGRATION_NAME, "Client Secret")
    verify_ssl = to_bool(siemplify.extract_configuration_param(INTEGRATION_NAME, "Verify SSL"), default=True)

    entity_types_param = siemplify.extract_action_param("Wiz Entity Types") or DEFAULT_ENTITY_TYPES
    entity_types = [t.strip().upper() for t in entity_types_param.split(",") if t.strip()]
    exact_match = (siemplify.extract_action_param("Match Type") or "Exact").strip().lower() == "exact"
    include_issues = to_bool(siemplify.extract_action_param("Include Open Issues"), default=True)
    create_insight = to_bool(siemplify.extract_action_param("Create Insight"), default=True)
    max_results = int(siemplify.extract_action_param("Max Results Per Hostname") or 10)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    hostnames = [e for e in siemplify.target_entities if e.entity_type == EntityTypes.HOSTNAME]
    enriched_entities = []
    not_found = []
    failed = []
    issue_lookup_failed = []
    json_results = []
    status = EXECUTION_STATE_COMPLETED

    try:
        manager = WizManager(api_url, client_id, client_secret, auth_url=auth_url,
                             verify_ssl=verify_ssl, logger=siemplify.LOGGER)

        for entity in hostnames:
            if deadline_reached(siemplify):
                siemplify.LOGGER.error("Approaching action timeout, stopping before {}".format(entity.identifier))
                status = EXECUTION_STATE_TIMEDOUT
                break

            siemplify.LOGGER.info("Looking up {} in Wiz".format(entity.identifier))
            try:
                matches = manager.search_hosts(entity.identifier, entity_types,
                                               exact_match=exact_match, limit=max_results)
                if not matches:
                    not_found.append(entity.identifier)
                    continue

                best = matches[0]
                issue_summary = None
                if include_issues:
                    try:
                        issue_summary = manager.get_open_issue_summary(best["id"])
                    except Exception as e:
                        siemplify.LOGGER.error("Issue lookup failed for {}: {}".format(entity.identifier, e))
                        issue_lookup_failed.append(entity.identifier)

                enrichment = build_enrichment(best, len(matches), issue_summary)
                entity.additional_properties.update(enrichment)
                entity.is_enriched = True
                enriched_entities.append(entity)

                siemplify.result.add_entity_table(entity.identifier, flat_dict_to_csv(enrichment))
                if create_insight:
                    siemplify.add_entity_insight(entity, build_insight(entity.identifier, best, issue_summary),
                                                 triggered_by=INTEGRATION_NAME)

                json_results.append({
                    "Entity": entity.identifier,
                    "EntityResult": {"matches": matches, "open_issues": issue_summary},
                })
            except Exception as e:
                siemplify.LOGGER.error("Failed to enrich {}: {}".format(entity.identifier, e))
                siemplify.LOGGER.exception(e)
                failed.append(entity.identifier)

        if enriched_entities:
            siemplify.update_entities(enriched_entities)
        siemplify.result.add_result_json(json_results)

        messages = []
        if enriched_entities:
            messages.append("Enriched from Wiz: {}".format(", ".join(e.identifier for e in enriched_entities)))
        if not_found:
            messages.append("Not found in Wiz: {}".format(", ".join(not_found)))
        if issue_lookup_failed:
            messages.append("Open-issue lookup failed for: {}".format(", ".join(issue_lookup_failed)))
        if failed:
            messages.append("Failed to enrich: {}".format(", ".join(failed)))
        if not hostnames:
            messages.append("No Hostname entities in scope.")
        if status == EXECUTION_STATE_TIMEDOUT:
            messages.append("Action stopped early because it was about to time out.")
        output_message = "\n".join(messages)
        result_value = bool(enriched_entities)

        if failed and not enriched_entities and not not_found:
            status = EXECUTION_STATE_FAILED
    except Exception as e:
        siemplify.LOGGER.error("Error executing {}: {}".format(SCRIPT_NAME, e))
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False
        output_message = "Error executing action \"Enrich Hostname\". Reason: {}".format(e)

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info("Status: {}, Result: {}, Output: {}".format(status, result_value, output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
