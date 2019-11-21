# Copyright (c) 2017 Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import pytest
import datetime

from ansible.plugins.inventory.active_directory import InventoryModule
from ansible.errors import AnsibleError
from ldap3 import Server, Connection, MOCK_SYNC

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

@pytest.fixture(scope="module")
def connection():
    server = Server('my_fake_server')
    connection = Connection(server, user='cn=my_user,ou=ansible,o=local', password='my_password', client_strategy=MOCK_SYNC)
    connection.strategy.add_entry('CN=dc1,OU=Domain Controllers,DC=ansible,DC=local', {'objectclass': 'computer', 'lastLogonTimestamp' : '2019-11-11 16:18:36.191551+00:00', 'operatingSystem': 'Windows Server 2016 Datacenter' })
    connection.strategy.add_entry('CN=dc2,OU=Domain Controllers,DC=ansible,DC=local', {'objectclass': 'computer', 'lastLogonTimestamp' : '2019-11-11 16:18:36.191551+00:00', 'operatingSystem': 'Windows Server 2016 Datacenter' })
    connection.open()
    return connection

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

def test_loading_computer_objects_using_root(inventory, connection):
    connection.search(search_base='DC=ansible,DC=local', search_filter='(objectclass=computer)', attributes=['lastLogonTimestamp', 'operatingSystem'])
    assert len(connection.entries) == 2
    assert connection.entries[0].entry_dn in ['CN=dc1,OU=Domain Controllers,DC=ansible,DC=local', 'CN=dc2,OU=Domain Controllers,DC=ansible,DC=local']
    assert connection.entries[0].lastLogonTimestamp == '2019-11-11 16:18:36.191551+00:00'

def test_loading_computer_objects_using_simple_organizational_unit(inventory):
    pass


def test_loading_computer_objects_using_nested_organizational_unit(inventory):
    pass
