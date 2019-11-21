# Copyright (c) 2017 Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import pytest
import datetime

from ansible.plugins.inventory.active_directory import InventoryModule
from ansible.errors import AnsibleError


config_data = {
    "plugin": "active_directory",
    "username": "ad_admin",
    "password": "sup3rs3cr3t",
    'domain_controllers': [
        'dc1.ansible.local', 
        'dc1.ansible.local'
        ],
    "organizational_units": [
        "OU=Servers,DC=ansible,DC=local",
        "OU=Desktops,DC=ansible,DC=local",
    ],
    "last_activity": 30,
}

@pytest.fixture(scope="module")
def inventory():
    inventory = InventoryModule()
    inventory._config_data = config_data
    return inventory

def test_set_credentials(inventory):
    inventory._options = {
        'username': 'ANSIBLETEST\\Administrator',
        'password': 'sup3rs3cr3t!',
        'domain_controllers': ['dc1.ansible.local', 'dc1.ansible.local']
    }
    inventory._set_credentials()
    assert inventory.user_name == 'ANSIBLETEST\\Administrator'
    assert inventory.user_password == 'sup3rs3cr3t!'
    assert inventory.domain_controllers == ['dc1.ansible.local', 'dc1.ansible.local']

def test_insufficient_credentials(inventory):
    inventory._options = {
        'username': 'ANSIBLETEST\\Administrator',
        'domain_controllers': ['dc1.ansible.local', 'dc1.ansible.local']
    }
    with pytest.raises(AnsibleError) as error_message:
        inventory._set_credentials()
        assert "insufficient credentials found" in error_message

def test_missing_domain_controllers_list(inventory):
    inventory._options = {
        'username': 'ANSIBLETEST\\Administrator',
        'password': 'sup3rs3cr3t!'
    }
    with pytest.raises(AnsibleError) as error_message:
        inventory._set_credentials()
        assert "domain controllers list is empty" in error_message

def test_loading_computer_objects_using_root(inventory):
    pass


def test_loading_computer_objects_using_simple_organizational_unit(inventory):
    pass


def test_loading_computer_objects_using_nested_organizational_unit(inventory):
    pass
