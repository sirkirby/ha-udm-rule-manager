import pytest
from unittest.mock import Mock, patch
from homeassistant.core import HomeAssistant

@pytest.fixture
def hass(event_loop):
    """Fixture to provide a test instance of Home Assistant."""
    hass = HomeAssistant()
    hass.config.components.add("unifi_network_rules")
    return hass

@pytest.fixture
def mock_udmapi():
    """Fixture to provide a mocked UDMAPI instance."""
    with patch('custom_components.unifi_network_rules.udm_api.UDMAPI') as mock_api:
        api = mock_api.return_value
        api.login.return_value = (True, None)
        api.get_traffic_rules.return_value = (True, [{"_id": "1", "enabled": True, "description": "Test Traffic Rule"}], None)
        api.get_firewall_rules.return_value = (True, [{"_id": "2", "enabled": False, "description": "Test Firewall Rule"}], None)
        yield api

@pytest.fixture
def mock_config_entry():
    """Fixture to provide a mocked config entry."""
    return Mock(
        data={
            "host": "192.168.1.1",
            "username": "admin",
            "password": "password",
            "max_retries": 3,
            "retry_delay": 1
        },
        entry_id="test_entry_id"
    )