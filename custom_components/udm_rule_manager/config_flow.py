import voluptuous as vol
from homeassistant import config_entries
from homeassistant.core import HomeAssistant
from homeassistant.const import CONF_HOST, CONF_USERNAME, CONF_PASSWORD

from .const import DOMAIN
from .udm_api import UDMAPI

class UDMRuleManagerConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for UDM Rule Manager."""

    VERSION = 1

    async def async_step_user(self, user_input=None):
        """Handle the initial step."""
        errors = {}

        if user_input is not None:
            api = UDMAPI(user_input[CONF_HOST], user_input[CONF_USERNAME], user_input[CONF_PASSWORD])
            if await api.login():
                return self.async_create_entry(title="UDM Rule Manager", data=user_input)
            else:
                errors["base"] = "cannot_connect"

        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_HOST): str,
                    vol.Required(CONF_USERNAME): str,
                    vol.Required(CONF_PASSWORD): str,
                }
            ),
            errors=errors,
        )

    async def async_step_import(self, import_config):
        """Handle import from configuration.yaml."""
        return await self.async_step_user(import_config)