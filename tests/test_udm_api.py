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

pytest.mark.asyncio
async def test_ensure_logged_in_success(udm_api):
    udm_api.cookies = {'cookie': 'value'}
    udm_api.csrf_token = 'token'
    udm_api.last_login = datetime.now()

    with patch.object(udm_api, 'login') as mock_login:
        result = await udm_api.ensure_logged_in()

        assert result == True
        mock_login.assert_not_called()

@pytest.mark.asyncio
async def test_ensure_logged_in_expired(udm_api):
    udm_api.cookies = {'cookie': 'value'}
    udm_api.csrf_token = 'token'
    udm_api.last_login = datetime.now() - udm_api.session_timeout - timedelta(minutes=1)

    with patch.object(udm_api, 'login') as mock_login:
        mock_login.return_value = (True, None)
        result = await udm_api.ensure_logged_in()

        assert result == True
        mock_login.assert_called_once()

@pytest.mark.asyncio
async def test_ensure_logged_in_failed(udm_api):
    udm_api.cookies = None
    udm_api.csrf_token = None
    udm_api.last_login = None

    with patch.object(udm_api, 'login') as mock_login:
        mock_login.return_value = (False, "Login failed")
        result = await udm_api.ensure_logged_in()

        assert result == False
        mock_login.assert_called_once()

@pytest.mark.asyncio
async def test_get_traffic_rules_success(udm_api):
    mock_rules = [{"_id": "1", "enabled": True}]
    with patch.object(udm_api, '_make_authenticated_request') as mock_request:
        mock_request.return_value = (True, mock_rules, None)

        success, rules, error = await udm_api.get_traffic_rules()

        assert success == True
        assert rules == mock_rules
        assert error is None

@pytest.mark.asyncio
async def test_get_traffic_rules_failure(udm_api):
    with patch.object(udm_api, '_make_authenticated_request') as mock_request:
        mock_request.return_value = (False, None, "Failed to fetch traffic rules")

        success, rules, error = await udm_api.get_traffic_rules()

        assert success == False
        assert rules is None
        assert error == "Failed to fetch traffic rules"

@pytest.mark.asyncio
async def test_get_firewall_rules_success(udm_api):
    mock_rules = [{"_id": "1", "enabled": True}, {"_id": "2", "enabled": False}]
    with patch.object(udm_api, '_make_authenticated_request') as mock_request:
        mock_request.return_value = (True, {"data": mock_rules}, None)

        success, rules, error = await udm_api.get_firewall_rules()

        assert success == True
        assert rules == mock_rules
        assert error is None

@pytest.mark.asyncio
async def test_get_firewall_rules_failure(udm_api):
    with patch.object(udm_api, '_make_authenticated_request') as mock_request:
        mock_request.return_value = (False, None, "Failed to fetch firewall rules")

        success, rules, error = await udm_api.get_firewall_rules()

        assert success == False
        assert rules is None
        assert error == "Failed to fetch firewall rules"

@pytest.mark.asyncio
async def test_toggle_traffic_rule_success(udm_api):
    rule_id = "1"
    enabled = True
    mock_rule = {"_id": rule_id, "enabled": not enabled}
    
    with patch.object(udm_api, '_make_authenticated_request') as mock_request:
        mock_request.side_effect = [
            (True, mock_rule, None),  # GET request
            (True, None, None)  # PUT request
        ]

        success, error = await udm_api.toggle_traffic_rule(rule_id, enabled)

        assert success == True
        assert error is None
        assert mock_request.call_count == 2

@pytest.mark.asyncio
async def test_toggle_traffic_rule_failure(udm_api):
    rule_id = "1"
    enabled = True
    
    with patch.object(udm_api, '_make_authenticated_request') as mock_request:
        mock_request.return_value = (False, None, "Failed to toggle rule")

        success, error = await udm_api.toggle_traffic_rule(rule_id, enabled)

        assert success == False
        assert "Failed to toggle rule" in error

@pytest.mark.asyncio
async def test_toggle_firewall_rule_success(udm_api):
    rule_id = "1"
    enabled = True
    mock_rule = {"data": [{"_id": rule_id, "enabled": not enabled}]}
    
    with patch.object(udm_api, '_make_authenticated_request') as mock_request:
        mock_request.side_effect = [
            (True, mock_rule, None),  # GET request
            (True, None, None)  # PUT request
        ]

        success, error = await udm_api.toggle_firewall_rule(rule_id, enabled)

        assert success == True
        assert error is None
        assert mock_request.call_count == 2

@pytest.mark.asyncio
async def test_toggle_firewall_rule_failure(udm_api):
    rule_id = "1"
    enabled = True
    
    with patch.object(udm_api, '_make_authenticated_request') as mock_request:
        mock_request.return_value = (False, None, "Failed to toggle rule")

        success, error = await udm_api.toggle_firewall_rule(rule_id, enabled)

        assert success == False
        assert "Failed to toggle rule" in error

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
        mock_ensure_logged_in.side_effect = [True, True]
        mock_get.return_value.__aenter__.return_value.status = 401
        mock_get.return_value.__aenter__.return_value.text = AsyncMock(return_value="Unauthorized")
        mock_get.return_value.__aenter__.side_effect = [
            AsyncMock(status=401, text=AsyncMock(return_value="Unauthorized")),
            AsyncMock(status=200, json=AsyncMock(return_value=mock_response))
        ]

        success, data, error = await udm_api._make_authenticated_request('get', 'https://test.com', {})

        assert success == True
        assert data == mock_response
        assert error is None
        assert mock_ensure_logged_in.call_count == 2
        assert mock_sleep.call_count == 1

@pytest.mark.asyncio
async def test_make_authenticated_request_max_retries(udm_api):
    with patch('aiohttp.ClientSession.get') as mock_get, \
         patch.object(udm_api, 'ensure_logged_in') as mock_ensure_logged_in, \
         patch('asyncio.sleep', new_callable=AsyncMock) as mock_sleep:
        mock_ensure_logged_in.return_value = True
        mock_get.return_value.__aenter__.return_value.status = 401
        mock_get.return_value.__aenter__.return_value.text = AsyncMock(return_value="Unauthorized")

        success, data, error = await udm_api._make_authenticated_request('get', 'https://test.com', {})

        assert success == False
        assert data is None
        assert "Request failed. Status: 401" in error
        assert mock_ensure_logged_in.call_count == udm_api.max_retries
        assert mock_sleep.call_count == udm_api.max_retries - 1

@pytest.mark.asyncio
async def test_make_authenticated_request_client_error(udm_api):
    with patch('aiohttp.ClientSession.get') as mock_get, \
         patch.object(udm_api, 'ensure_logged_in') as mock_ensure_logged_in, \
         patch('asyncio.sleep', new_callable=AsyncMock) as mock_sleep:
        mock_ensure_logged_in.return_value = True
        mock_get.side_effect = ClientError()

        success, data, error = await udm_api._make_authenticated_request('get', 'https://test.com', {})

        assert success == False
        assert data is None
        assert "Client error during request" in error
        assert mock_ensure_logged_in.call_count == udm_api.max_retries
        assert mock_sleep.call_count == udm_api.max_retries - 1

@pytest.mark.asyncio
async def test_make_authenticated_request_timeout(udm_api):
    with patch('aiohttp.ClientSession.get') as mock_get, \
         patch.object(udm_api, 'ensure_logged_in') as mock_ensure_logged_in, \
         patch('asyncio.sleep', new_callable=AsyncMock) as mock_sleep:
        mock_ensure_logged_in.return_value = True
        mock_get.side_effect = asyncio.TimeoutError()

        success, data, error = await udm_api._make_authenticated_request('get', 'https://test.com', {})

        assert success == False
        assert data is None
        assert error == "Request timed out"
        assert mock_ensure_logged_in.call_count == udm_api.max_retries
        assert mock_sleep.call_count == udm_api.max_retries - 1

@pytest.mark.asyncio
async def test_login_unexpected_error(udm_api):
    with patch('aiohttp.ClientSession.post') as mock_post:
        mock_post.side_effect = Exception("Unexpected error")

        success, error = await udm_api.login()

        assert success == False
        assert "Unexpected error during login" in error

@pytest.mark.asyncio
async def test_get_traffic_rules_no_rules(udm_api):
    with patch.object(udm_api, '_make_authenticated_request') as mock_request:
        mock_request.return_value = (True, [], None)

        success, rules, error = await udm_api.get_traffic_rules()

        assert success == True
        assert rules == []
        assert error is None

@pytest.mark.asyncio
async def test_get_firewall_rules_no_rules(udm_api):
    with patch.object(udm_api, '_make_authenticated_request') as mock_request:
        mock_request.return_value = (True, {"data": []}, None)

        success, rules, error = await udm_api.get_firewall_rules()

        assert success == True
        assert rules == []
        assert error is None

@pytest.mark.asyncio
async def test_toggle_traffic_rule_not_found(udm_api):
    rule_id = "nonexistent"
    enabled = True
    
    with patch.object(udm_api, '_make_authenticated_request') as mock_request:
        mock_request.return_value = (True, None, None)  # Simulate rule not found

        success, error = await udm_api.toggle_traffic_rule(rule_id, enabled)

        assert success == False
        assert f"Rule with id {rule_id} not found" in error

@pytest.mark.asyncio
async def test_toggle_firewall_rule_not_found(udm_api):
    rule_id = "nonexistent"
    enabled = True
    
    with patch.object(udm_api, '_make_authenticated_request') as mock_request:
        mock_request.return_value = (True, {"data": []}, None)  # Simulate rule not found

        success, error = await udm_api.toggle_firewall_rule(rule_id, enabled)

        assert success == False
        assert f"Rule with id {rule_id} not found" in error


@pytest.mark.asyncio
async def test_make_authenticated_request_login_failure(udm_api):
    with patch.object(udm_api, 'ensure_logged_in') as mock_ensure_logged_in:
        mock_ensure_logged_in.return_value = False

        success, data, error = await udm_api._make_authenticated_request('get', 'https://test.com', {})

        assert success == False
        assert data is None
        assert error == "Failed to login"

@pytest.mark.asyncio
async def test_make_authenticated_request_unexpected_error(udm_api):
    with patch('aiohttp.ClientSession.get') as mock_get, \
         patch.object(udm_api, 'ensure_logged_in') as mock_ensure_logged_in:
        mock_ensure_logged_in.return_value = True
        mock_get.side_effect = Exception("Unexpected error")

        success, data, error = await udm_api._make_authenticated_request('get', 'https://test.com', {})

        assert success == False
        assert data is None
        assert "Unexpected error during request" in error