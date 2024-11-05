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

    if coordinator.data.get('traffic_rules'):
        for rule in coordinator.data['traffic_rules']:
            entities.append(UDMTrafficRuleSwitch(coordinator, api, rule))

    if coordinator.data.get('firewall_rules'):
        for rule in coordinator.data['firewall_rules']:
            entities.append(UDMFirewallRuleSwitch(coordinator, api, rule))

    if coordinator.data.get('traffic_routes'):
        for route in coordinator.data['traffic_routes']:
            entities.append(UDMTrafficRouteSwitch(coordinator, api, route))

    async_add_entities(entities, True)

class UDMRuleSwitch(CoordinatorEntity, SwitchEntity):
    """Representation of a UDM Rule Switch."""

    def __init__(self, coordinator, api, rule, rule_type):
        """Initialize the UDM Rule Switch."""
        super().__init__(coordinator)
        self._api = api
        self._rule_type = rule_type
        self._attr_unique_id = f"{rule_type}_{rule['_id']}"
        self._attr_name = f"{rule_type.capitalize()} Rule: {rule.get('description', rule.get('name', 'Unnamed'))}"

    @property
    def is_on(self):
        """Return true if the switch is on."""
        rule = self._get_rule()
        return rule['enabled'] if rule else False

    async def async_turn_on(self, **kwargs):
        """Turn the switch on."""
        await self._toggle(True)

    async def async_turn_off(self, **kwargs):
        """Turn the switch off."""
        await self._toggle(False)

    async def _toggle(self, new_state):
        """Toggle the rule state."""
        rule = self._get_rule()
        if not rule:
            raise HomeAssistantError(f"{self._rule_type.capitalize()} rule not found")

        _LOGGER.debug(f"Attempting to set {self._rule_type} rule {rule['_id']} to {'on' if new_state else 'off'}")
        
        try:
            if self._rule_type == 'traffic':
                success, error_message = await self._api.toggle_traffic_rule(rule['_id'], new_state)
            else:
                success, error_message = await self._api.toggle_firewall_rule(rule['_id'], new_state)

            if success:
                _LOGGER.info(f"Successfully set {self._rule_type} rule {rule['_id']} to {'on' if new_state else 'off'}")
                await self.coordinator.async_request_refresh()
            else:
                _LOGGER.error(f"Failed to set {self._rule_type} rule {rule['_id']} to {'on' if new_state else 'off'}. Error: {error_message}")
                raise HomeAssistantError(f"Failed to toggle {self._rule_type} rule: {error_message}")
        
        except Exception as e:
            _LOGGER.error(f"Error toggling {self._rule_type} rule {rule['_id']}: {str(e)}")
            raise HomeAssistantError(f"Error toggling {self._rule_type} rule: {str(e)}")

    def _get_rule(self):
        """Get the current rule from the coordinator data."""
        rules = self.coordinator.data.get(f'{self._rule_type}_rules', [])
        for rule in rules:
            if rule['_id'] == self._attr_unique_id.split('_')[1]:
                return rule
        return None

    @callback
    def _handle_coordinator_update(self):
        """Handle updated data from the coordinator."""
        self.async_write_ha_state()

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

class UDMTrafficRouteSwitch(CoordinatorEntity, SwitchEntity):
    """Representation of a UDM Traffic Route Switch."""

    def __init__(self, coordinator, api, route):
        """Initialize the UDM Traffic Route Switch."""
        super().__init__(coordinator)
        self._api = api
        self._attr_unique_id = f"traffic_route_{route['_id']}"
        self._attr_name = f"Traffic Route: {route.get('description', 'Unnamed')}"
        
        # Store route details for device info
        self._route = route

    @property
    def is_on(self):
        """Return true if the switch is on."""
        route = self._get_route()
        return route['enabled'] if route else False

    @property
    def device_info(self):
        """Return device info for this traffic route."""
        return {
            "identifiers": {(DOMAIN, self._attr_unique_id)},
            "name": self._attr_name,
            "manufacturer": "Ubiquiti",
            "model": "Traffic Route",
            "sw_version": None,
        }

    async def async_turn_on(self, **kwargs):
        """Turn the switch on."""
        await self._toggle(True)

    async def async_turn_off(self, **kwargs):
        """Turn the switch off."""
        await self._toggle(False)

    async def _toggle(self, new_state):
        """Toggle the route state."""
        route = self._get_route()
        if not route:
            raise HomeAssistantError("Traffic route not found")

        _LOGGER.debug(f"Attempting to set traffic route {route['_id']} to {'on' if new_state else 'off'}")
        
        try:
            success, error_message = await self._api.toggle_traffic_route(route['_id'], new_state)
            if success:
                _LOGGER.info(f"Successfully set traffic route {route['_id']} to {'on' if new_state else 'off'}")
                await self.coordinator.async_request_refresh()
            else:
                _LOGGER.error(f"Failed to set traffic route {route['_id']} to {'on' if new_state else 'off'}. Error: {error_message}")
                raise HomeAssistantError(f"Failed to toggle traffic route: {error_message}")
        
        except Exception as e:
            _LOGGER.error(f"Error toggling traffic route {route['_id']}: {str(e)}")
            raise HomeAssistantError(f"Error toggling traffic route: {str(e)}")

    def _get_route(self):
        """Get the current route from the coordinator data."""
        routes = self.coordinator.data.get('traffic_routes', [])
        route_id = self._attr_unique_id.split('_')[-1]
        for route in routes:
            if route['_id'] == route_id:
                return route
        return None

    @property
    def extra_state_attributes(self):
        """Return additional state attributes."""
        route = self._get_route()
        if not route:
            return {}

        attributes = {
            "description": route.get("description", ""),
            "matching_target": route.get("matching_target", ""),
            "network_id": route.get("network_id", ""),
            "kill_switch_enabled": route.get("kill_switch_enabled", False),
        }

        # Add domain information if available
        if route.get("domains"):
            attributes["domains"] = [d.get("domain") for d in route["domains"]]

        # Add target devices information
        if route.get("target_devices"):
            devices = []
            for device in route["target_devices"]:
                if device.get("type") == "ALL_CLIENTS":
                    devices.append("ALL_CLIENTS")
                elif device.get("type") == "NETWORK":
                    devices.append(f"NETWORK: {device.get('network_id')}")
                else:
                    devices.append(device.get("client_mac", ""))
            attributes["target_devices"] = devices

        return attributes