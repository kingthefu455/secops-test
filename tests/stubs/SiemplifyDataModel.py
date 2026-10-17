class EntityTypes(object):
    HOSTNAME = "HOSTNAME"
    ADDRESS = "ADDRESS"


class Entity(object):
    def __init__(self, identifier, entity_type):
        self.identifier = identifier
        self.entity_type = entity_type
        self.additional_properties = {}
        self.is_enriched = False
