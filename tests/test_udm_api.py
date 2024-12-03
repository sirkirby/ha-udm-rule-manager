import pytest
import asyncio
from unittest.mock import patch, Mock, AsyncMock
from aiohttp import ClientResponseError, ClientError
from freezegun import freeze_time
from datetime import datetime, timedelta
from custom_components.unifi_network_rules.udm_api import UDMAPI

@pytest.fixture
def udm_api():
   return UDMAPI("192.168.1.1", "admin", "password")

@pytest.mark.asyncio
async def test_login_success(udm_api):
   with patch('aiohttp.ClientSession.post') as mock_post:
       mock_response = Mock()
       mock_response.status = 200
       mock_response.cookies = {'cookie': 'value'}
       mock_response.headers = {'x-csrf-token': 'token'}
       mock_post.return_value.__aenter__.return_value = mock_response

       success, error = await udm_api.login()

       assert success == True
       assert error is None
       assert udm_api.cookies == {'cookie': 'value'}
       assert udm_api.csrf_token == 'token'

@pytest.mark.asyncio
async def test_ensure_logged_in_success(udm_api):
   udm_api.cookies = {'cookie': 'value'}
   udm_api.csrf_token = 'token'
   udm_api.last_login = datetime.now()

   with patch.object(udm_api, 'login') as mock_login:
       result = await udm_api.ensure_logged_in()

       assert result == True
       mock_login.assert_not_called()

@pytest.mark.asyncio
async def test_get_firewall_policies_success(udm_api):
   mock_policies = [{"_id": "1", "enabled": True}, {"_id": "2", "enabled": False}]
   with patch.object(udm_api, '_make_authenticated_request') as mock_request:
       mock_request.return_value = (True, mock_policies, None)

       success, policies, error = await udm_api.get_firewall_policies()

       assert success is True
       assert policies == mock_policies
       assert error is None

@pytest.mark.asyncio
async def test_get_firewall_policies_failure(udm_api):
   with patch.object(udm_api, '_make_authenticated_request') as mock_request:
       mock_request.return_value = (False, None, "API Error")

       success, policies, error = await udm_api.get_firewall_policies()

       assert success is False
       assert policies is None
       assert "API Error" in error

@pytest.mark.asyncio
async def test_get_firewall_policy_success(udm_api):
   policy_id = "test_id"
   mock_policy = {"_id": policy_id, "enabled": True, "name": "Test Policy"}
   
   with patch.object(udm_api, '_make_authenticated_request') as mock_request:
       mock_request.return_value = (True, mock_policy, None)
       
       success, policy, error = await udm_api.get_firewall_policy(policy_id)
       
       assert success is True
       assert policy == mock_policy
       assert error is None

@pytest.mark.asyncio
async def test_get_firewall_policy_failure(udm_api):
   policy_id = "test_id"
   
   with patch.object(udm_api, '_make_authenticated_request') as mock_request:
       mock_request.return_value = (False, None, "API Error")
       
       success, policy, error = await udm_api.get_firewall_policy(policy_id)
       
       assert success is False
       assert policy is None
       assert error == "API Error"

@pytest.mark.asyncio
async def test_toggle_firewall_policy_success(udm_api):
   policy_id = "test_id"
   mock_policy = {"_id": policy_id, "enabled": False}
   
   with patch.object(udm_api, '_make_authenticated_request') as mock_request:
       mock_request.side_effect = [
           (True, mock_policy, None),  # GET response
           (True, None, None)  # PUT response
       ]
       
       success, error = await udm_api.toggle_firewall_policy(policy_id, True)
       
       assert success is True
       assert error is None
       assert mock_request.call_count == 2

@pytest.mark.asyncio
async def test_toggle_firewall_policy_get_failure(udm_api):
   policy_id = "test_id"
   
   with patch.object(udm_api, '_make_authenticated_request') as mock_request:
       mock_request.return_value = (False, None, "Failed to fetch policy")
       
       success, error = await udm_api.toggle_firewall_policy(policy_id, True)
       
       assert success is False
       assert "Failed to fetch policy" in error

@pytest.mark.asyncio
async def test_get_traffic_routes_success(udm_api):
   mock_routes = [
       {
           "_id": "route1",
           "description": "Test Route 1",
           "enabled": True,
           "matching_target": "INTERNET"
       },
       {
           "_id": "route2",
           "description": "Test Route 2",
           "enabled": False,
           "matching_target": "DOMAIN"
       }
   ]
   
   with patch.object(udm_api, '_make_authenticated_request') as mock_request:
       mock_request.return_value = (True, mock_routes, None)
       
       success, routes, error = await udm_api.get_traffic_routes()
       
       assert success is True
       assert routes == mock_routes
       assert error is None

@pytest.mark.asyncio
async def test_get_traffic_routes_failure(udm_api):
   with patch.object(udm_api, '_make_authenticated_request') as mock_request:
       mock_request.return_value = (False, None, "API Error")
       
       success, routes, error = await udm_api.get_traffic_routes()
       
       assert success is False
       assert routes is None
       assert error == "API Error"

@pytest.mark.asyncio
async def test_toggle_traffic_route_success(udm_api):
   route_id = "route1"
   mock_route = {
       "_id": route_id,
       "description": "Test Route",
       "enabled": False
   }
   
   with patch.object(udm_api, '_make_authenticated_request') as mock_request:
       mock_request.side_effect = [
           (True, [mock_route], None),  # GET response
           (True, None, None)  # PUT response
       ]
       
       success, error = await udm_api.toggle_traffic_route(route_id, True)
       
       assert success is True
       assert error is None
       assert mock_request.call_count == 2

@pytest.mark.asyncio
async def test_toggle_traffic_route_get_failure(udm_api):
   route_id = "route1"
   
   with patch.object(udm_api, '_make_authenticated_request') as mock_request:
       mock_request.return_value = (False, None, "Failed to fetch routes")
       
       success, error = await udm_api.toggle_traffic_route(route_id, True)
       
       assert success is False
       assert "Failed to fetch routes" in error

@pytest.mark.asyncio
async def test_toggle_traffic_route_not_found(udm_api):
   route_id = "nonexistent"
   
   with patch.object(udm_api, '_make_authenticated_request') as mock_request:
       mock_request.return_value = (True, [], None)
       
       success, error = await udm_api.toggle_traffic_route(route_id, True)
       
       assert success is False
       assert "Route with id nonexistent not found" in error

@pytest.mark.asyncio
async def test_make_authenticated_request_success(udm_api):
   mock_response = {"data": "test"}
   
   with patch('aiohttp.ClientSession.get') as mock_get, \
        patch.object(udm_api, 'ensure_logged_in') as mock_ensure_logged_in:
       mock_ensure_logged_in.return_value = True
       mock_get.return_value.__aenter__.return_value.status = 200
       mock_get.return_value.__aenter__.return_value.json = AsyncMock(return_value=mock_response)

       success, data, error = await udm_api._make_authenticated_request('get', 'https://test.com', {})

       assert success == True
       assert data == mock_response
       assert error is None

@pytest.mark.asyncio
async def test_make_authenticated_request_retry_success(udm_api):
   mock_response = {"data": "test"}
   
   with patch('aiohttp.ClientSession.get') as mock_get, \
        patch.object(udm_api, 'ensure_logged_in') as mock_ensure_logged_in, \
        patch('asyncio.sleep', new_callable=AsyncMock) as mock_sleep:
       mock_ensure_logged_in.return_value = True
       mock_get.return_value.__aenter__.return_value.status = 401
       mock_get.return_value.__aenter__.return_value.text = AsyncMock(return_value="Unauthorized")
       mock_get.return_value.__aenter__.side_effect = [
           AsyncMock(status=401, text=AsyncMock(return_value="Unauthorized")),
           AsyncMock(status=200, json=AsyncMock(return_value=mock_response))
       ]

       success, data, error = await udm_api._make_authenticated_request('get', 'https://test.com', {})

       assert success is True
       assert data == mock_response
       assert error is None
       assert mock_sleep.call_count > 0

@pytest.mark.asyncio
async def test_make_authenticated_request_max_retries(udm_api):
   with patch('aiohttp.ClientSession.get') as mock_get, \
        patch.object(udm_api, 'ensure_logged_in') as mock_ensure_logged_in, \
        patch('asyncio.sleep', new_callable=AsyncMock) as mock_sleep:
       mock_ensure_logged_in.return_value = True
       mock_get.return_value.__aenter__.return_value.status = 401
       mock_get.return_value.__aenter__.return_value.text = AsyncMock(return_value="Unauthorized")

       success, data, error = await udm_api._make_authenticated_request('get', 'https://test.com', {})

       assert success is False
       assert data is None
       assert "Request failed. Status: 401" in error
       assert mock_sleep.call_count == udm_api.max_retries - 1