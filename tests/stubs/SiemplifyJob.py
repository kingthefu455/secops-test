"""Minimal stand-in for the Google SecOps SOAR SiemplifyJob, for local tests only."""

import logging


class SiemplifyJob(object):
    # Tests set these before calling main().
    params = {}
    case_ids = []
    cases = {}
    last = None

    def __init__(self):
        self.LOGGER = logging.getLogger("siemplify-job-test")
        self.case_filter = None
        self.ended = False
        SiemplifyJob.last = self

    def extract_job_param(self, param_name, default_value=None, **kwargs):
        value = SiemplifyJob.params.get(param_name)
        return default_value if value is None else value

    def get_cases_ids_by_filter(self, **kwargs):
        self.case_filter = kwargs
        return list(SiemplifyJob.case_ids)

    def _get_case_by_id(self, case_id):
        return SiemplifyJob.cases[str(case_id)]

    def end_script(self):
        self.ended = True
