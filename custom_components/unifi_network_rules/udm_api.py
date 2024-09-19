import aiohttp
import asyncio
import logging
from datetime import datetime, timedelta

_LOGGER = logging.getLogger(__name__)

class UDMAPI:
    def __init__(self, host, username, password):
        self.host = host
        self.username = username
        self.password = password
        self.cookies = None
        self.csrf_token = None
        self.last_login = None
        self.session_timeout = timedelta(hours=1)  # Adjust this value based on UDM's session timeout

    async def ensure_logged_in(self):
        """Ensure the API is logged in, refreshing the session if necessary."""
        if not self.cookies or not self.csrf_token or self._is_session_expired():
            return await self.login()
        return True

    def _is_session_expired(self):
        """Check if the current session has expired."""
        if not self.last_login:
            return True
        return datetime.now() - self.last_login > self.session_timeout

    async def login(self):
        """Log in to the UDM and obtain necessary tokens."""
        url = f"https://{self.host}/api/auth/login"
        data = {"username": self.username, "password": self.password}
        async with aiohttp.ClientSession() as session:
            try:
                async with session.post(url, json=data, ssl=True, verify_ssl=False) as response:
                    if response.status == 200:
                        self.cookies = response.cookies
                        self.csrf_token = response.headers.get('x-csrf-token')
                        self.last_login = datetime.now()
                        _LOGGER.info("Successfully logged in to UDM")
                        return True
                    else:
                        _LOGGER.error(f"Failed to log in to UDM. Status: {response.status}")
                        return False
            except aiohttp.ClientError as e:
                _LOGGER.error(f"Error during login: {str(e)}")
                return False

    async def get_traffic_rules(self):
        if not await self.ensure_logged_in():
            return None

        url = f"https://{self.host}/proxy/network/v2/api/site/default/trafficrules"
        headers = {'x-csrf-token': self.csrf_token, 'Accept': 'application/json'}
        async with aiohttp.ClientSession(cookies=self.cookies) as session:
            try:
                async with session.get(url, headers=headers, ssl=True, verify_ssl=False) as response:
                    if response.status == 200:
                        _LOGGER.debug("Successfully fetched traffic rules")
                        return await response.json()
                    else:
                        _LOGGER.error(f"Failed to fetch traffic rules. Status: {response.status}")
                        return None
            except aiohttp.ClientError as e:
                _LOGGER.error(f"Error fetching traffic rules: {str(e)}")
                return None

    async def get_firewall_rules(self):
        if not await self.ensure_logged_in():
            return None

        url = f"https://{self.host}/proxy/network/api/s/default/rest/firewallrule"
        headers = {'x-csrf-token': self.csrf_token, 'Accept': 'application/json'}
        async with aiohttp.ClientSession(cookies=self.cookies) as session:
            try:
                async with session.get(url, headers=headers, ssl=True, verify_ssl=False) as response:
                    if response.status == 200:
                        data = await response.json()
                        _LOGGER.debug("Successfully fetched firewall rules")
                        return data.get('data', [])
                    else:
                        _LOGGER.error(f"Failed to fetch firewall rules. Status: {response.status}")
                        return None
            except aiohttp.ClientError as e:
                _LOGGER.error(f"Error fetching firewall rules: {str(e)}")
                return None

    async def toggle_traffic_rule(self, rule_id, enabled):
        if not await self.ensure_logged_in():
            return False, "Failed to login"

        url_get = f"https://{self.host}/proxy/network/v2/api/site/default/trafficrule/{rule_id}"
        url_put = f"https://{self.host}/proxy/network/v2/api/site/default/trafficrules/{rule_id}"
        headers = {
            'x-csrf-token': self.csrf_token,
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }
        
        # First, get the current rule data
        async with aiohttp.ClientSession(cookies=self.cookies) as session:
            try:
                async with session.get(url_get, headers=headers, ssl=True, verify_ssl=False) as response:
                    if response.status == 200:
                        rule_data = await response.json()
                    else:
                        error_text = await response.text()
                        _LOGGER.error(f"Failed to fetch traffic rule {rule_id}. Status: {response.status}, Response: {error_text}")
                        return False, f"Failed to fetch rule: Status {response.status}"
            except aiohttp.ClientError as e:
                _LOGGER.error(f"Error fetching traffic rule {rule_id}: {str(e)}")
                return False, f"Error fetching rule: {str(e)}"

        # Update only the 'enabled' field
        rule_data['enabled'] = enabled

        # Now, send the PUT request with the updated data
        async with aiohttp.ClientSession(cookies=self.cookies) as session:
            try:
                async with session.put(url_put, headers=headers, json=rule_data, ssl=True, verify_ssl=False) as response:
                    if response.status == 200:
                        _LOGGER.info(f"Successfully toggled traffic rule {rule_id} to {'on' if enabled else 'off'}")
                        return True, None
                    else:
                        error_text = await response.text()
                        _LOGGER.error(f"Failed to toggle traffic rule {rule_id}. Status: {response.status}, Response: {error_text}")
                        return False, f"Failed to toggle rule: Status {response.status}, Response: {error_text}"
            except aiohttp.ClientError as e:
                _LOGGER.error(f"Error toggling traffic rule {rule_id}: {str(e)}")
                return False, f"Error toggling rule: {str(e)}"

    async def toggle_firewall_rule(self, rule_id, enabled):
        if not await self.ensure_logged_in():
            return False, "Failed to login"

        url = f"https://{self.host}/proxy/network/api/s/default/rest/firewallrule/{rule_id}"
        headers = {
            'x-csrf-token': self.csrf_token,
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }

        # First, get the current rule data
        async with aiohttp.ClientSession(cookies=self.cookies) as session:
            try:
                async with session.get(url, headers=headers, ssl=True, verify_ssl=False) as response:
                    if response.status == 200:
                        data = await response.json()
                        rule_data = data.get('data', [])[0]
                        _LOGGER.debug(f"firewall rule retrieved: {rule_data}")
                    else:
                        _LOGGER.error(f"Failed to fetch firewall rule {rule_id}. Status: {response.status}")
                        return False, f"Failed to fetch rule: Status {response.status}"
            except aiohttp.ClientError as e:
                _LOGGER.error(f"Error fetching firewall rule {rule_id}: {str(e)}")
                return False, f"Error fetching rule: {str(e)}"

        # Update only the 'enabled' field
        rule_data['enabled'] = enabled

        # Now, send the PUT request with the updated data
        async with aiohttp.ClientSession(cookies=self.cookies) as session:
            try:
                async with session.put(url, headers=headers, json=rule_data, ssl=True, verify_ssl=False) as response:
                    if response.status == 200:
                        _LOGGER.info(f"Successfully toggled firewall rule {rule_id} to {'on' if enabled else 'off'}")
                        return True, None
                    else:
                        error_text = await response.text()
                        _LOGGER.error(f"Failed to toggle firewall rule {rule_id}. Status: {response.status}, Response: {error_text}")
                        return False, f"Failed to toggle rule: Status {response.status}, Response: {error_text}"
            except aiohttp.ClientError as e:
                _LOGGER.error(f"Error toggling firewall rule {rule_id}: {str(e)}")
                return False, f"Error toggling rule: {str(e)}"