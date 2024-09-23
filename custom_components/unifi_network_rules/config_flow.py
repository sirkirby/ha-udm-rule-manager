import voluptuous as vol
from homeassistant import config_entries
from homeassistant.core import HomeAssistant
from homeassistant.const import CONF_HOST, CONF_USERNAME, CONF_PASSWORD
from homeassistant.helpers import config_validation as cv

from .const import DOMAIN, CONF_MAX_RETRIES, CONF_RETRY_DELAY, DEFAULT_MAX_RETRIES, DEFAULT_RETRY_DELAY
from .udm_api import UDMAPI

class UDMRuleManagerConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Unifi Network Rules."""

    VERSION = 1

    async def async_step_user(self, user_input=None):
        """Handle the initial step."""
        errors = {}

        if user_input is not None:
            api = UDMAPI(
                user_input[CONF_HOST],
                user_input[CONF_USERNAME],
                user_input[CONF_PASSWORD],
                max_retries=user_input.get(CONF_MAX_RETRIES, DEFAULT_MAX_RETRIES),
                retry_delay=user_input.get(CONF_RETRY_DELAY, DEFAULT_RETRY_DELAY)
            )
            success, error_message = await api.login()
            if success:
                return self.async_create_entry(title="Unifi Network Rules", data=user_input)
            else:
                errors["base"] = "cannot_connect"
                if error_message:
                    errors["base_info"] = error_message

        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_HOST): str,
                    vol.Required(CONF_USERNAME): str,
                    vol.Required(CONF_PASSWORD): str,
                    vol.Optional(CONF_MAX_RETRIES, default=DEFAULT_MAX_RETRIES): vol.All(
                        vol.Coerce(int), vol.Range(min=1, max=10)
                    ),
                    vol.Optional(CONF_RETRY_DELAY, default=DEFAULT_RETRY_DELAY): vol.All(
                        vol.Coerce(int), vol.Range(min=1, max=60)
                    ),
                }
            ),
            errors=errors,
        )

    async def async_step_import(self, import_config):
        """Handle import from configuration.yaml."""
        return await self.async_step_user(import_config)