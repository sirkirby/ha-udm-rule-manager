# Unifi Network Rule Manager

Integrates with your Unifi Dream Machine to allow basic management of firewall rules within Home Assistant.

## Installation

Install via HACS or copy the `custom_components/udm_network_rules` directory to your `config/custom_components` directory.

1. Using HACS, search for "Unifi Network Rule Manager" and select it.
2. Restart Home Assistant.
3. In the Home Assistant configuration page, click on "Integrations".
4. Click on the "+" button in the bottom right corner.
5. Search for "Unifi Network Rule Manager" and select it.
6. Enter your Unifi Network credentials and click on the "Submit" button.

## Configuration

Host: The IP address of your Unifi Dream Machine.
Username: The local admin account on the UDM.
Password: The password for the UDM account.

## Usage

Once you have configured the integration, you will be able to see the firewall rules for your Unifi Network in Home Assistant. Each rule will be a switch that you can toggle on and off manually or via automations.

## Limitations

The integration is currently limited to managing firewall and traffic rules. It does not currently support managing other types of rules.

## Contributions

Contributions are welcome! Please feel free to submit a PR.
