import logging
from homeassistant.components.switch import SwitchEntity
from homeassistant.core import callback
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.config_entries import ConfigEntry
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)

async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback):
    """Set up the UDM Rule Manager switches."""
    coordinator = hass.data[DOMAIN][entry.entry_id]['coordinator']
    api = hass.data[DOMAIN][entry.entry_id]['api']

    entities = []

    if coordinator.data['traffic_rules']:
        for rule in coordinator.data['traffic_rules']:
            entities.append(UDMTrafficRuleSwitch(coordinator, api, rule))

    if coordinator.data['firewall_rules']:
        for rule in coordinator.data['firewall_rules']:
            entities.append(UDMFirewallRuleSwitch(coordinator, api, rule))

    async_add_entities(entities, True)

class UDMRuleSwitch(CoordinatorEntity, SwitchEntity):
    """Representation of a UDM Rule Switch."""

    def __init__(self, coordinator, api, rule, rule_type):
        """Initialize the UDM Rule Switch."""
        super().__init__(coordinator)
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
                await self.coordinator.async_request_refresh()
            else:
                _LOGGER.error(f"Failed to set {self._rule_type} rule {self._rule['_id']} to {'on' if new_state else 'off'}. Error: {error_message}")
                raise HomeAssistantError(f"Failed to toggle {self._rule_type} rule: {error_message}")
        
        except Exception as e:
            _LOGGER.error(f"Error toggling {self._rule_type} rule {self._rule['_id']}: {str(e)}")
            raise HomeAssistantError(f"Error toggling {self._rule_type} rule: {str(e)}")
        
        self.async_write_ha_state()

    @property
    def available(self):
        """Return if entity is available."""
        return self.coordinator.last_update_success

    async def async_added_to_hass(self):
        """When entity is added to hass."""
        await super().async_added_to_hass()
        self._handle_coordinator_update()

    @callback
    def _handle_coordinator_update(self):
        """Handle updated data from the coordinator."""
        rules = self.coordinator.data[f'{self._rule_type}_rules']
        for rule in rules:
            if rule['_id'] == self._rule['_id']:
                self._rule = rule
                self.async_write_ha_state()
                break

class UDMTrafficRuleSwitch(UDMRuleSwitch):
    """Representation of a UDM Traffic Rule Switch."""

    def __init__(self, coordinator, api, rule):
        """Initialize the UDM Traffic Rule Switch."""
        super().__init__(coordinator, api, rule, 'traffic')

class UDMFirewallRuleSwitch(UDMRuleSwitch):
    """Representation of a UDM Firewall Rule Switch."""

    def __init__(self, coordinator, api, rule):
        """Initialize the UDM Firewall Rule Switch."""
        super().__init__(coordinator, api, rule, 'firewall')