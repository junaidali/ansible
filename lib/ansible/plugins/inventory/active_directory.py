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
  - ou=servers,dc=ansible,dc=local
  - ou=desktops,dc=ansible,dc=local
username: DOMAIN\\username
password: sup3rs3cr3t

# Fetch all hosts within specific organizational unit and last login activity within given timeframe (in days)
plugin: active_directory
domain_controllers:
  - dc1.ansible.local
organizational_units:
  - ou=servers,dc=ansible,dc=local
  - ou=desktops,dc=ansible,dc=local
last_activity: 30
username: DOMAIN\\username
password: sup3rs3cr3t

# Fetch all hosts within specific organizational unit, even disabled accounts
plugin: active_directory
domain_controllers:
  - dc1.ansible.local
organizational_units:
  - ou=servers,dc=ansible,dc=local
  - ou=desktops,dc=ansible,dc=local
import_disabled: true
username: DOMAIN\\username
password: sup3rs3cr3t
"""

import re

from ansible.errors import AnsibleError
from ansible.module_utils._text import to_native, to_text
from ansible.plugins.inventory import BaseInventoryPlugin, Constructable, Cacheable
from ansible.utils.display import Display

display = Display()

try:
    from ldap3 import Server, ServerPool, Connection, ALL, SUBTREE, BASE, ALL_ATTRIBUTES
    from ldap3.core.exceptions import LDAPException
except ImportError:
    raise AnsibleError('the active_directory dynamic inventory plugin requires ldap3')


class InventoryModule(BaseInventoryPlugin, Constructable, Cacheable):
    """ Host inventory parser for ansible using active directory as source. """

    NAME = "active_directory"

    def __init__(self):
      super(InventoryModule, self).__init__()

      # credentials
      display.vvvv('initializing active_directory inventory plugin')
      self.user_name = None
      self.user_password = None
      self.domain_controllers = []
    
    def _set_credentials(self):
      """
      :param config_data: contents of the inventory config file
      """
      display.vvvv('setting credentials')
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

      display.vvvv('credentials: username - ' + self.user_name)

    def _ldap3_conn(self):
      """
      establishes an ldap connection and returns the connection object
      """
      display.vvvv('initializing ldap connection')
      if self.user_name == None or self.user_password == None:
        raise AnsibleError('insufficient credentials found')

      if len(self.domain_controllers) > 1:
        display.vvvv('creating server connection pool to %s' % self.domain_controllers)
        server = ServerPool()
        for dc in self.domain_controllers:
          server.add(dc)
      else:
        server = Server(host=self.domain_controllers[0])
        display.vvvv('creating single server connection to %s' % server)
      try:
        connection = Connection(server=server, user=self.user_name, password=self.user_password, auto_bind=True)
      except LDAPException as err:
        raise AnsibleError("could not connect to domain controller")
      return connection

    def _query(self, connection, path, no_subtree=False):
      """
      queries active directory and returns records
      :param connection: the ldap3 connection object
      :param path: the ldap path to query
      :param no_subtree: limit search to path only, do not include subtree
      """
      display.vvvv('running search query to find computers at path ' + path)
      search_scope = BASE if no_subtree else SUBTREE
      try:
        connection.search(search_base=path, search_filter='(objectclass=computer)', attributes=ALL_ATTRIBUTES, search_scope=search_scope)
      except LDAPException as err:
        raise AnsibleError('could not retrieve computer objects %s', err)
      display.vvvv('total ' + str(len(connection.response)) + ' entries retrieved')
      #display.vvvv('total ' + len(connection.entries) + ' entries retrieved')
      return connection.entries

    def _get_hostname(self, entry, hostnames=None):
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

    def _populate(self, entries):
      """
      populates ansible inventory with active directory entries
      :param entries: ldap entries list
      """
      for entry in entries:
        hostname = self._get_hostname(entry)
        self.inventory.add_host(hostname)

    def verify_file(self, path):
        """
            :param loader: an ansible.parsing.dataloader.DataLoader object
            :param path: the path to the inventory config file
            :return the contents of the config file
        """
        if super(InventoryModule, self).verify_file(path):
            if path.endswith(("active_directory.yml", "active_directory.yaml")):
                return True
        display.vvvv(
            "active_directory inventory filename must end with 'active_directory.yml' or 'active_directory.yaml'"
        )
        return False

    def parse(self, inventory, loader, path, cache=True):

        super(InventoryModule, self).parse(inventory, loader, path)

        self._read_config_data(path)

        self._set_credentials()

        organizational_units_to_search = self.get_option('organizational_units')

        connection = self._ldap3_conn()

        cache_key = self.get_cache_key(path)
        # false when refresh_cache or --flush-cache is used
        if cache:
            # get the user-specified directive
            cache = self.get_option('cache')

        # Generate inventory
        cache_needs_update = False
        if cache:
            try:
                results = self._cache[cache_key]
            except KeyError:
                # if cache expires or cache file doesn't exist
                cache_needs_update = True

        if not cache or cache_needs_update:
          for organizational_unit in organizational_units_to_search:
            results = self._query(connection, organizational_unit)
            self._populate(results)

        # If the cache has expired/doesn't exist or if refresh_inventory/flush cache is used
        # when the user is using caching, update the cached inventory
        if cache_needs_update or (not cache and self.get_option('cache')):
            self._cache[cache_key] = results
