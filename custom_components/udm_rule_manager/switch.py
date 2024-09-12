import logging
from homeassistant.components.switch import SwitchEntity
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.config_entries import ConfigEntry
from homeassistant.exceptions import HomeAssistantError

from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)

async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback):
    """Set up the UDM Rule Manager switches."""
    api = hass.data[DOMAIN][entry.entry_id]['api']

    traffic_rules = await api.get_traffic_rules()
    firewall_rules = await api.get_firewall_rules()

    entities = []

    if traffic_rules:
        for rule in traffic_rules:
            entities.append(UDMTrafficRuleSwitch(api, rule))

    if firewall_rules:
        for rule in firewall_rules:
            entities.append(UDMFirewallRuleSwitch(api, rule))

    async_add_entities(entities, True)

class UDMRuleSwitch(SwitchEntity):
    """Representation of a UDM Rule Switch."""

    def __init__(self, api, rule, rule_type):
        """Initialize the UDM Rule Switch."""
        self._api = api
        self._rule = rule
        self._rule_type = rule_type
        self._attr_unique_id = f"{rule_type}_{rule['_id']}"
        self._attr_name = f"{rule_type.capitalize()} Rule: {rule.get('description', rule.get('name', 'Unnamed'))}"

    @property
    def is_on(self):
        """Return true if the switch is on."""
        return self._rule['enabled']

    async def async_turn_on(self, **kwargs):
        """Turn the switch on."""
        await self._toggle(True)

    async def async_turn_off(self, **kwargs):
        """Turn the switch off."""
        await self._toggle(False)

    async def _toggle(self, new_state):
        """Toggle the rule state."""
        _LOGGER.debug(f"Attempting to set {self._rule_type} rule {self._rule['_id']} to {'on' if new_state else 'off'}")
        
        try:
            if self._rule_type == 'traffic':
                success, error_message = await self._api.toggle_traffic_rule(self._rule['_id'], new_state)
            else:
                success, error_message = await self._api.toggle_firewall_rule(self._rule['_id'], new_state)

            if success:
                self._rule['enabled'] = new_state
                _LOGGER.info(f"Successfully set {self._rule_type} rule {self._rule['_id']} to {'on' if new_state else 'off'}")
            else:
                _LOGGER.error(f"Failed to set {self._rule_type} rule {self._rule['_id']} to {'on' if new_state else 'off'}. Error: {error_message}")
                raise HomeAssistantError(f"Failed to toggle {self._rule_type} rule: {error_message}")
        
        except Exception as e:
            _LOGGER.error(f"Error toggling {self._rule_type} rule {self._rule['_id']}: {str(e)}")
            raise HomeAssistantError(f"Error toggling {self._rule_type} rule: {str(e)}")
        
        self.async_write_ha_state()

    async def async_update(self):
        """Fetch new state data for the sensor."""
        _LOGGER.debug(f"Updating state for {self._rule_type} rule {self._rule['_id']}")
        try:
            if self._rule_type == 'traffic':
                rules = await self._api.get_traffic_rules()
            else:
                rules = await self._api.get_firewall_rules()
            
            if rules:
                for rule in rules:
                    if rule['_id'] == self._rule['_id']:
                        self._rule = rule
                        break
            else:
                _LOGGER.error(f"Failed to fetch updated rules for {self._rule_type}")
        except Exception as e:
            _LOGGER.error(f"Error updating {self._rule_type} rule {self._rule['_id']}: {str(e)}")

class UDMTrafficRuleSwitch(UDMRuleSwitch):
    """Representation of a UDM Traffic Rule Switch."""

    def __init__(self, api, rule):
        """Initialize the UDM Traffic Rule Switch."""
        super().__init__(api, rule, 'traffic')

class UDMFirewallRuleSwitch(UDMRuleSwitch):
    """Representation of a UDM Firewall Rule Switch."""

    def __init__(self, api, rule):
        """Initialize the UDM Firewall Rule Switch."""
        super().__init__(api, rule, 'firewall')