import copy
import unittest

import device_config_update_agent


BASE_DOCUMENT = {
    "schema_version": 1,
    "config_revision": 1,
    "config_version": "field-settings-r1",
    "settings": {
        "timezone": "America/Guayaquil",
        "reporting_times": ["12:48", "18:00"],
        "time_antenna_power_on_minutes": 10,
        "antenna_rest_time_minutes": 5,
        "reporting_time_on_minutes": 10,
        "voltage_turn_off": 11.8,
        "starlink_connection_timeout_seconds": 420,
        "starlink_connection_check_interval_seconds": 60,
    },
}


class AntennaSettingTests(unittest.TestCase):
    def test_legacy_configuration_without_antenna_type_remains_valid(self):
        self.assertEqual(
            device_config_update_agent.validate_document(copy.deepcopy(BASE_DOCUMENT)),
            BASE_DOCUMENT,
        )

    def test_starlink_and_ubiquiti_are_valid_selections(self):
        for antenna_type in ("starlink", "ubiquiti"):
            with self.subTest(antenna_type=antenna_type):
                document = copy.deepcopy(BASE_DOCUMENT)
                document["settings"]["antenna_type"] = antenna_type
                device_config_update_agent.validate_document(document)

    def test_unknown_antenna_type_is_rejected(self):
        document = copy.deepcopy(BASE_DOCUMENT)
        document["settings"]["antenna_type"] = "unknown"
        with self.assertRaisesRegex(ValueError, "antenna_type"):
            device_config_update_agent.validate_document(document)


if __name__ == "__main__":
    unittest.main()
