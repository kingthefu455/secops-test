"""Minimal stand-in for the Google SecOps SOAR SDK, for local tests only."""

import logging


class _Result(object):
    def __init__(self):
        self.entity_tables = {}
        self.result_json = None

    def add_entity_table(self, entity_identifier, data_table):
        self.entity_tables[entity_identifier] = data_table

    def add_result_json(self, json_data):
        self.result_json = json_data


class SiemplifyAction(object):
    # Tests set these before calling main().
    config = {}
    params = {}
    entities = []
    last = None

    def __init__(self):
        self.LOGGER = logging.getLogger("siemplify-test")
        self.result = _Result()
        self.target_entities = list(SiemplifyAction.entities)
        self.updated_entities = []
        self.insights = []
        self.ended = None
        self.execution_deadline_unix_time_ms = None
        SiemplifyAction.last = self

    def extract_configuration_param(self, provider_name, param_name, **kwargs):
        return SiemplifyAction.config.get(param_name)

    def extract_action_param(self, param_name, **kwargs):
        return SiemplifyAction.params.get(param_name)

    def update_entities(self, entities):
        self.updated_entities.extend(entities)

    def add_entity_insight(self, entity, message, triggered_by=None):
        self.insights.append((entity.identifier, message, triggered_by))

    def end(self, message, result_value, status):
        self.ended = (message, result_value, status)
