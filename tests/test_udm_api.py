import pytest
from unittest.mock import patch, Mock
from aiohttp import ClientResponseError
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
async def test_login_failure(udm_api):
    with patch('aiohttp.ClientSession.post') as mock_post:
        mock_post.side_effect = ClientResponseError(
            request_info=Mock(),
            history=(),
            status=401,
            message="Unauthorized",
            headers={}
        )

        success, error = await udm_api.login()

        assert success == False
        assert "Failed to log in to UDM: 401, message='Unauthorized'" in error

@pytest.mark.asyncio
async def test_get_traffic_rules(udm_api):
    with patch.object(udm_api, '_make_authenticated_request') as mock_request:
        mock_request.return_value = (True, [{"_id": "1", "enabled": True}], None)

        success, rules, error = await udm_api.get_traffic_rules()

        assert success == True
        assert len(rules) == 1
        assert rules[0]["_id"] == "1"
        assert error is None

@pytest.mark.asyncio
async def test_get_firewall_rules(udm_api):
    mock_rules = [
        {"_id": "1", "enabled": True, "description": "Rule 1"},
        {"_id": "2", "enabled": False, "description": "Rule 2"}
    ]
    with patch.object(udm_api, '_make_authenticated_request') as mock_request:
        mock_request.return_value = (True, {"data": mock_rules}, None)

        success, rules, error = await udm_api.get_firewall_rules()

        assert success == True
        assert len(rules) == 2
        assert rules[0]["_id"] == "1"
        assert rules[1]["_id"] == "2"
        assert error is None

@pytest.mark.asyncio
async def test_get_firewall_rules_failure(udm_api):
    with patch.object(udm_api, '_make_authenticated_request') as mock_request:
        mock_request.return_value = (False, None, "Failed to fetch firewall rules")

        success, rules, error = await udm_api.get_firewall_rules()

        assert success == False
        assert rules is None
        assert error == "Failed to fetch firewall rules"

