import aiohttp
import asyncio
import logging
from typing import Any, Dict, List, Tuple, Optional
from datetime import datetime, timedelta

_LOGGER = logging.getLogger(__name__)

class UDMAPI:
    def __init__(self, host, username, password, max_retries=3, retry_delay=1):
        self.host = host
        self.username = username
        self.password = password
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.cookies = None
        self.csrf_token = None
        self.last_login = None
        self.session_timeout = timedelta(hours=1)  # Adjust this value based on UDM's session timeout

    async def ensure_logged_in(self) -> bool:
        """Ensure the API is logged in, refreshing the session if necessary."""
        if not self.cookies or not self.csrf_token or self._is_session_expired():
            success, error = await self.login()
            if not success:
                _LOGGER.error(f"Failed to log in: {error}")
                return False
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
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(url, json=data, ssl=True, verify_ssl=False) as response:
                    if response.status == 200:
                        self.cookies = response.cookies
                        self.csrf_token = response.headers.get('x-csrf-token')
                        self.last_login = datetime.now()
                        _LOGGER.info("Successfully logged in to UDM")
                        return True, None
                    else:
                        error_message = f"Failed to log in to UDM. Status: {response.status}"
                        _LOGGER.error(error_message)
                        return False, error_message
        except aiohttp.ClientResponseError as e:
            error_message = f"Failed to log in to UDM: {e.status}, message='{e.message}'"
            _LOGGER.error(error_message)
            return False, error_message
        except Exception as e:
            error_message = f"Unexpected error during login: {str(e)}"
            _LOGGER.exception(error_message)
            return False, error_message

    async def _make_authenticated_request(self, method: str, url: str, headers: Dict[str, str], json_data: Optional[Dict[str, Any]] = None) -> Tuple[bool, Any, Optional[str]]:
        """Make an authenticated request to the UDM API with retry logic."""
        for attempt in range(self.max_retries):
            if not await self.ensure_logged_in():
                return False, None, "Failed to login"

            headers['x-csrf-token'] = self.csrf_token
            async with aiohttp.ClientSession(cookies=self.cookies) as session:
                try:
                    async with getattr(session, method)(url, headers=headers, json=json_data, ssl=True, verify_ssl=False) as response:
                        if response.status == 200:
                            return True, await response.json(), None
                        elif response.status == 401 and attempt < self.max_retries - 1:
                            _LOGGER.warning(f"Authentication failed, attempting to re-login (attempt {attempt + 1})")
                            self.cookies = None
                            self.csrf_token = None
                            await asyncio.sleep(self.retry_delay)
                            continue
                        else:
                            error_message = f"Request failed. Status: {response.status}, Response: {await response.text()}"
                            _LOGGER.error(error_message)
                            return False, None, error_message
                except aiohttp.ClientError as e:
                    error_message = f"Client error during request: {str(e)}"
                    _LOGGER.error(error_message)
                    if attempt < self.max_retries - 1:
                        await asyncio.sleep(self.retry_delay)
                        continue
                    return False, None, error_message
                except asyncio.TimeoutError:
                    error_message = "Request timed out"
                    _LOGGER.error(error_message)
                    if attempt < self.max_retries - 1:
                        await asyncio.sleep(self.retry_delay)
                        continue
                    return False, None, error_message
                except Exception as e:
                    error_message = f"Unexpected error during request: {str(e)}"
                    _LOGGER.exception(error_message)
                    return False, None, error_message

        return False, None, "Max retries reached"

    async def get_traffic_routes(self) -> Tuple[bool, Optional[List[Dict[str, Any]]], Optional[str]]:
        """Fetch traffic routes from the UDM."""
        url = f"https://{self.host}/proxy/network/v2/api/site/default/trafficroutes"
        headers = {'Accept': 'application/json'}
        
        success, data, error = await self._make_authenticated_request('get', url, headers)
        if success:
            _LOGGER.debug("Successfully fetched traffic routes")
            return True, data, None
        else:
            _LOGGER.error(f"Failed to fetch traffic routes: {error}")
            return False, None, error

    async def toggle_traffic_route(self, route_id: str, enabled: bool) -> Tuple[bool, Optional[str]]:
        """Toggle a traffic route on or off."""
        url = f"https://{self.host}/proxy/network/v2/api/site/default/trafficroutes/{route_id}"
        headers = {'Accept': 'application/json', 'Content-Type': 'application/json'}

        # First get all routes and find the one we want to modify
        success, routes, error = await self.get_traffic_routes()
        if not success:
            return False, f"Failed to fetch routes: {error}"

        route_data = next((route for route in routes if route['_id'] == route_id), None)
        if not route_data:
            return False, f"Route with id {route_id} not found"

        # Update the 'enabled' field
        route_data['enabled'] = enabled

        # Send the PUT request with the updated data
        success, _, error = await self._make_authenticated_request('put', url, headers, route_data)
        if success:
            _LOGGER.info(f"Successfully toggled traffic route {route_id} to {'on' if enabled else 'off'}")
            return True, None
        else:
            _LOGGER.error(f"Failed to toggle traffic route {route_id}: {error}")
            return False, f"Failed to toggle route: {error}"
    
    async def get_firewall_policies(self) -> Tuple[bool, Optional[List[Dict[str, Any]]], Optional[str]]:
        """Fetch all firewall policies from the UDM."""
        url = f"https://{self.host}/proxy/network/v2/api/site/default/firewall-policies"
        headers = {'Accept': 'application/json'}
        
        success, data, error = await self._make_authenticated_request('get', url, headers)
        if success:
            _LOGGER.debug("Successfully fetched firewall policies")
            return True, data, None
        else:
            _LOGGER.error(f"Failed to fetch firewall policies: {error}")
            return False, None, error

    async def get_firewall_policy(self, policy_id: str) -> Tuple[bool, Optional[Dict[str, Any]], Optional[str]]:
        """Fetch a single firewall policy from the UDM."""
        url = f"https://{self.host}/proxy/network/v2/api/site/default/firewall-policies/{policy_id}"
        headers = {'Accept': 'application/json'}
        
        success, data, error = await self._make_authenticated_request('get', url, headers)
        if success:
            return True, data, None
        else:
            _LOGGER.error(f"Failed to fetch firewall policy {policy_id}: {error}")
            return False, None, error

    async def toggle_firewall_policy(self, policy_id: str, enabled: bool) -> Tuple[bool, Optional[str]]:
        """Toggle a firewall policy on or off."""
        success, policy, error = await self.get_firewall_policy(policy_id)
        if not success:
            return False, f"Failed to fetch policy: {error}"

        policy['enabled'] = enabled

        url = f"https://{self.host}/proxy/network/v2/api/site/default/firewall-policies/{policy_id}"
        headers = {'Accept': 'application/json', 'Content-Type': 'application/json'}

        success, _, error = await self._make_authenticated_request('put', url, headers, policy)
        if success:
            _LOGGER.info(f"Successfully toggled firewall policy {policy_id} to {'on' if enabled else 'off'}")
            return True, None
        else:
            return False, f"Failed to toggle policy: {error}"