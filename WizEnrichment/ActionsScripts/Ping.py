from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED

from WizManager import WizManager

INTEGRATION_NAME = "WizEnrichment"
SCRIPT_NAME = "WizEnrichment - Ping"


def to_bool(value, default=False):
    if value is None or value == "":
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("true", "1", "yes")


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME
    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    api_url = siemplify.extract_configuration_param(INTEGRATION_NAME, "API URL")
    auth_url = siemplify.extract_configuration_param(INTEGRATION_NAME, "Auth URL")
    client_id = siemplify.extract_configuration_param(INTEGRATION_NAME, "Client ID")
    client_secret = siemplify.extract_configuration_param(INTEGRATION_NAME, "Client Secret")
    verify_ssl = to_bool(siemplify.extract_configuration_param(INTEGRATION_NAME, "Verify SSL"), default=True)

    try:
        manager = WizManager(api_url, client_id, client_secret, auth_url=auth_url,
                             verify_ssl=verify_ssl, logger=siemplify.LOGGER)
        manager.test_connectivity()
        status = EXECUTION_STATE_COMPLETED
        result_value = True
        output_message = "Successfully connected to Wiz."
    except Exception as e:
        siemplify.LOGGER.error("Failed to connect to Wiz: {}".format(e))
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False
        output_message = "Failed to connect to Wiz. Error: {}".format(e)

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
