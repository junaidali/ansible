# Copyright (c) 2017 Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import pytest
import datetime

from ansible.plugins.inventory.active_directory import InventoryModule
from ansible.errors import AnsibleError
from ldap3 import Server, Connection, ALL, MOCK_SYNC, ObjectDef, AttrDef, OFFLINE_AD_2012_R2
import os

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
    current_dir = os.path.dirname(os.path.realpath(__file__))
    server = Server.from_definition('my_fake_server', os.path.join(current_dir,'test_active_directory_server_info.json'), os.path.join(current_dir,'test_active_directory_server_schema.json'))
    connection = Connection(server, user='cn=admin,ou=users,ou=ansible,o=local', password='s3cr3t', client_strategy=MOCK_SYNC)
    connection.strategy.entries_from_json(os.path.join(current_dir,'test_active_directory_server_data.json'))
    connection.bind()
    return connection

@pytest.fixture(scope="module")
def domain_controller_computer_object(connection):
    connection.search(search_base='OU=Domain Controllers,DC=ansible,DC=local', search_filter='(objectclass=computer)', attributes=['lastLogonTimestamp', 'operatingSystem', 'DNSHostName', 'name'])
    return connection.entries[0]

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

def test_loading_computer_objects_from_domain_controllers_organizational_unit(domain_controller_computer_object):
    assert domain_controller_computer_object.entry_dn == 'CN=DC,OU=Domain Controllers,DC=ansible,DC=local'
    assert isinstance(domain_controller_computer_object.lastLogonTimestamp.value, datetime.datetime)
    assert domain_controller_computer_object.operatingSystem == 'Windows Server 2016 Standard Evaluation'
    assert domain_controller_computer_object.DNSHostName == 'dc.ansible.local'
    assert domain_controller_computer_object.name == 'DC'

def test_computer_object_inventory_hostname_should_default_to_dns_hostname_attribute(inventory, domain_controller_computer_object):
    assert inventory._get_hostname(domain_controller_computer_object, hostnames=None) == 'dc.ansible.local'

def test_computer_object_inventory_hostname_using_name_attribute(inventory, domain_controller_computer_object):
    assert inventory._get_hostname(domain_controller_computer_object, hostnames=['name']) == 'DC'

def test_query_domain_controllers_organizational_unit(inventory, connection):
    assert len(inventory._query(connection, 'OU=Domain Controllers,DC=ansible,DC=local')) == 1

def test_query_invalid_path_should_raise_error(inventory, connection):
    with pytest.raises(AnsibleError):
        inventory._query(connection=connection, path='UNKNOWN-PATH')
        assert "could not retrieve computer objects" in error_message

def test_loading_computer_objects_using_simple_organizational_unit(inventory):
    pass


def test_loading_computer_objects_using_nested_organizational_unit(inventory):
    pass
