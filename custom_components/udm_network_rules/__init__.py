import asyncio
import logging
from datetime import timedelta
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.const import CONF_HOST, CONF_USERNAME, CONF_PASSWORD
from homeassistant.helpers.typing import ConfigType
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator

from .const import DOMAIN
from .udm_api import UDMAPI

_LOGGER = logging.getLogger(__name__)

PLATFORMS: list[str] = ["switch"]
UPDATE_INTERVAL = timedelta(minutes=5)

async def async_setup(hass: HomeAssistant, config: ConfigType) -> bool:
    """Set up the UDM Rule Manager component."""
    hass.data.setdefault(DOMAIN, {})
    return True

async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up UDM Rule Manager from a config entry."""
    host = entry.data[CONF_HOST]
    username = entry.data[CONF_USERNAME]
    password = entry.data[CONF_PASSWORD]

    api = UDMAPI(host, username, password)
    
    # Test the connection
    if not await api.login():
        _LOGGER.error("Failed to connect to UDM. Please check your configuration.")
        return False

    async def async_update_data():
        """Fetch data from API."""
        try:
            traffic_rules = await api.get_traffic_rules()
            firewall_rules = await api.get_firewall_rules()
            return {"traffic_rules": traffic_rules, "firewall_rules": firewall_rules}
        except Exception as e:
            _LOGGER.error(f"Error updating data: {str(e)}")
            raise

    coordinator = DataUpdateCoordinator(
        hass,
        _LOGGER,
        name="udm_rule_manager",
        update_method=async_update_data,
        update_interval=UPDATE_INTERVAL,
    )

    # Fetch initial data
    await coordinator.async_config_entry_first_refresh()

    hass.data[DOMAIN][entry.entry_id] = {
        'api': api,
        'coordinator': coordinator
    }

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    return True

async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unload_ok:
        hass.data[DOMAIN].pop(entry.entry_id)

    return unload_ok