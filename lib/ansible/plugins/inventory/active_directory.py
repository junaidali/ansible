# Copyright (c) 2017 Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = """
    name: active_directory
    plugin_type: inventory
    short_description: Active Directory inventory source
    requirements:
        - ldap3
    extends_documentation_fragment:
        - inventory_cache
        - constructed
    description:
        - Get inventory hosts from Active Directory
        - Uses a YAML configuration file that ends with C(active_directory.(yml|yaml)).
    author:
        - Syed Junaid Ali (@junaidali)
    options:
        username:
          description: The active directory user name used for querying computer objects
          type: string
          required: True
        password:
          description: The active directory user's password used for querying computer objects
          type: string
          required: True
        domain_controllers:
          description: The list of domain controllers used for querying computer information
          type: list
          default: []
          required: True
        organizational_units:
          description: The list of organizational units (OU's) to be searched for computer objects within the active directory domain
          type: list
          default: []
        last_activity:
          description:
            - This setting determines the number of days that are tolerated for a given computer to be considered active
            - It uses the lastLogonTimeStamp active directory attribute to determine if the computer was active within this timeframe
          type: number
          default: 90 (days)
        import_disabled:
          description: Forces importing disabled computer objects
          type: boolean
          default: false
        import_computer_groups:
          description: Imports computer groups as ansible inventory host groups
          type: boolean
          default: false
"""

EXAMPLES = """
# Fetch all hosts in the active directory domain
plugin: active_directory
domain_controllers:
  - dc1.ansible.local
username: DOMAIN\\username
password: sup3rs3cr3t

# Fetch all hosts in the active directory domain use two domain controllers
plugin: active_directory
domain_controllers:
  - dc1.ansible.local
  - dc2.ansible.local
username: DOMAIN\\username
password: sup3rs3cr3t

# Fetch all hosts within specific organizational unit
plugin: active_directory
domain_controllers:
  - dc1.ansible.local
organizational_units:
  - servers
  - desktops
username: DOMAIN\\username
password: sup3rs3cr3t

# Fetch all hosts within specific organizational unit and last login activity within given timeframe (in days)
plugin: active_directory
domain_controllers:
  - dc1.ansible.local
organizational_units:
  - servers
  - desktops
last_activity: 30
username: DOMAIN\\username
password: sup3rs3cr3t

# Fetch all hosts within specific organizational unit, even disabled accounts
plugin: active_directory
domain_controllers:
  - dc1.ansible.local
organizational_units:
  - servers
  - desktops
import_disabled: true
username: DOMAIN\\username
password: sup3rs3cr3t
"""

import re

from ansible.errors import AnsibleError
from ansible.module_utils._text import to_native, to_text
from ansible.plugins.inventory import BaseInventoryPlugin, Constructable, Cacheable
from ansible.utils.display import Display

try:
    from ldap3 import Server, ServerPool, Connection, ALL
except ImportError:
    raise AnsibleError('the active_directory dynamic inventory plugin requires ldap3')


class InventoryModule(BaseInventoryPlugin, Constructable, Cacheable):
    """ Host inventory parser for ansible using active directory as source. """

    NAME = "active_directory"

    def __init__(self):
      super(InventoryModule, self).__init__()

      # credentials
      self.user_name = None
      self.user_password = None
      self.domain_controllers = []
    
    def _set_credentials(self):
      """
      :param config_data: contents of the inventory config file
      """
      try:
        self.user_name = self.get_option('username')
      except:
        raise AnsibleError('insufficient credentials found')

      try:
        self.user_password = self.get_option('password')
      except:
        raise AnsibleError('insufficient credentials found')

      try:
        self.domain_controllers = self.get_option('domain_controllers')
      except:
        raise AnsibleError('domain controllers list is empty')

    def _ldap3_conn(self):
      """
      establishes an ldap connection and returns the connection object
      """
      if self.user_name == None or self.user_password == None:
        raise AnsibleError('insufficient credentials found')

      if isinstance(self.domain_controllers, list):
        server = ServerPool()
        for dc in self.domain_controllers:
          server.add(dc)
      else:
        server = Server(host=self.domain_controllers)
      
      connection = Connection(server=server, user=self.user_name, password=self.user_password)
      connection.bind()
      return connection

    def _query(self, connection, path, no_subtree=False):
      """
      queries active directory and returns records
      :param connection: the ldap3 connection object
      :param path: the ldap path to query
      :param no_subtree: limit search to path only, do not include subtree
      """
      pass

    def _get_hostname(self, entry, hostnames):
      """
      :param entry: a ldap3 entry object returned by ldap3 search
      :param hostnames: a list of hostname destination variables in order of preference
      :return the preferred identifer for the host
      """
      if not hostnames:
        hostnames = ['dNSHostName', 'name']
      
      hostname = None
      for preference in hostnames:
        try:
          hostname = entry[preference]
          break
        except:
          pass
      
      return to_text(hostname)

    def verify_file(self, path):
        """
            :param loader: an ansible.parsing.dataloader.DataLoader object
            :param path: the path to the inventory config file
            :return the contents of the config file
        """
        if super(InventoryModule, self).verify_file(path):
            if path.endswith(("active_directory.yml", "active_directory.yaml")):
                return True
        display.debug(
            "active_directory inventory filename must end with 'active_directory.yml' or 'active_directory.yaml'"
        )
        return False

    def parse(self, inventory, loader, path, cache=True):

        super(InventoryModule, self).parse(inventory, loader, path)

        self._read_config_data(path)
