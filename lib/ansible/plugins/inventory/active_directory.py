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
        use_ssl: 
          description: The LDAP connection to active directory domain controllers uses SSL by default. If you have a need to disable SSL for troubleshooting purposes you can disable it by setting this parameter to no. It is highly recommended to use SSL to protect your credential over the wire.
          type: boolean
          default: yes
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
from datetime import datetime, timezone

from ansible.errors import AnsibleError
from ansible.module_utils._text import to_native, to_text
from ansible.plugins.inventory import BaseInventoryPlugin, Constructable, Cacheable
from ansible.utils.display import Display

display = Display()

try:
    from ldap3 import Server, ServerPool, Connection, ALL, SUBTREE, BASE, ALL_ATTRIBUTES
    from ldap3.core.exceptions import LDAPException
except ImportError:
    raise AnsibleError("the active_directory dynamic inventory plugin requires ldap3")


class InventoryModule(BaseInventoryPlugin, Constructable, Cacheable):
    """ Host inventory parser for ansible using active directory as source. """

    NAME = "active_directory"

    def __init__(self):
        super(InventoryModule, self).__init__()

        # set default values for parameters
        display.verbose("initializing active_directory inventory plugin")
        self.user_name = None
        self.user_password = None
        self.domain_controllers = []
        self.use_ssl = True
        self.last_activity = 30
        self.import_disabled = False
        self.import_computer_groups = False

    def _init_data(self):
        """
      :param config_data: contents of the inventory config file
      """
        display.verbose("setting credentials")
        try:
            self.user_name = self.get_option("username")
        except:
            raise AnsibleError("insufficient credentials found")

        try:
            self.user_password = self.get_option("password")
        except:
            raise AnsibleError("insufficient credentials found")

        try:
            self.domain_controllers = self.get_option("domain_controllers")
        except:
            raise AnsibleError("domain controllers list is empty")

        try:
            self.use_ssl = self.get_option("use_ssl")
        except:
            pass

        try:
            self.last_activity = self.get_option("last_activity")
        except:
            pass

        try:
            self.import_disabled = self.get_option("import_disabled")
        except:
            pass

        try:
            self.import_computer_groups = self.get_option("import_computer_groups")
        except:
            pass

        display.verbose("credentials: username - " + self.user_name)

    def _ldap3_conn(self):
        """
      establishes an ldap connection and returns the connection object
      """
        display.verbose("initializing ldap connection")
        if self.user_name == None or self.user_password == None:
            raise AnsibleError("insufficient credentials found")

        if len(self.domain_controllers) > 1:
            display.verbose(
                "creating server connection pool to %s" % self.domain_controllers
            )
            server = ServerPool()
            for dc in self.domain_controllers:
                server.add(Server(host=dc, use_ssl=self.use_ssl))
        elif len(self.domain_controllers) == 1:
            display.verbose(
                "creating single server connection to %s" % self.domain_controllers[0]
            )
            try:
                server = Server(host=self.domain_controllers[0], use_ssl=self.use_ssl)
            except:
                raise AnsibleError(
                    "could not establish connection to domain controller"
                )
        else:
            raise AnsibleError("no domain controller specified")
        display.verbose("initializing connection using server url %s" % server)
        try:
            connection = Connection(
                server=server,
                user=self.user_name,
                password=self.user_password,
                auto_bind=True,
            )
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
        display.verbose("running search query to find computers at path " + path)
        search_scope = BASE if no_subtree else SUBTREE
        try:
            connection.search(
                search_base=path,
                search_filter="(objectclass=computer)",
                attributes=ALL_ATTRIBUTES,
                search_scope=search_scope,
            )
        except LDAPException as err:
            raise AnsibleError("could not retrieve computer objects %s", err)
        display.verbose("total " + str(len(connection.response)) + " entries retrieved")
        return connection.entries

    def _get_hostname(self, entry, hostnames=None):
        """
      :param entry: a ldap3 entry object returned by ldap3 search
      :param hostnames: a list of hostname destination variables in order of preference
      :return the preferred identifer for the host
      """
        if not hostnames:
            hostnames = ["dNSHostName", "name"]

        hostname = None
        for preference in hostnames:
            try:
                hostname = entry[preference]
                break
            except:
                pass

        return to_text(hostname)

    def _get_safe_group_name(self, group_name):
        """
      :param group_name: the name of ansible inventory group you need to sanitize
      :returns the sanitized ansible inventory group name
      """
        sanitized_name = re.sub("-", "_", group_name)
        sanitized_name = re.sub("\\s", "_", sanitized_name)
        return sanitized_name.lower()

    def _get_inventory_group_names_from_computer_distinguished_name(
        self, entry_dn, search_ou
    ):
        """
      converts an active directory computer objects distinguished name to ansible inventory group names.
      :param entry_dn: computer object ldap entry distinguished name
      :param search_ou: the base search organization unit that was used to retrieve the entry. all inventory groups are based off of this OU
      """
        result = []
        if search_ou in entry_dn:
            display.debug("parsing %s" % entry_dn)
            if not re.match("^DC=", search_ou):
                parent_group = search_ou.split(",")[0].split("=")[1]
                result.append(to_text(parent_group))
            dn_without_search_ou = entry_dn.split(search_ou)[0].strip(",")
            display.debug("processing dn_without_search_ou %s" % dn_without_search_ou)
            for count, node in enumerate(dn_without_search_ou.split(",")):
                display.debug("processing node %s" % node)
                if count == 0:
                    display.debug("ignoring object %s in group name calculation" % node)
                else:
                    if "=" in node:
                        result.append(to_text(node.split("=")[1]))
                    else:
                        display.warning(
                            "node %s cannot be split to get inventory group name" % node
                        )
                count += 1
        else:
            raise AnsibleError("%s does not exists in %s" % (search_ou, entry_dn))
        result.reverse()
        display.debug("returning result %s" % result)
        return result

    def _populate(self, entries, organizational_unit):
        """
      populates ansible inventory with active directory entries
      :param entries: ldap entries list
      """
        display.debug("creating all inventory group")
        self.inventory.add_group("all")
        for entry in entries:
            display.debug("processing entry %s" % entry)
            hostname = self._get_hostname(entry)
            # check last logon timestamp to see if account is enabled
            if (
                entry["userAccountControl"] in [4098, 532482]
                and self.import_disabled == False
            ):
                display.vvvv("Ignoring %s as it is currently disabled" % (hostname))
            elif (
                "lastLogonTimestamp" in entry
                and abs(
                    (
                        datetime.now(timezone.utc)
                        - entry["lastLogonTimestamp"].values[0]
                    ).days
                )
                > self.last_activity
            ):
                display.vvvv(
                    "Ignoring %s as its lastLogonTimestamp of %s is past the %d day(s) threshold"
                    % (hostname, entry["lastLogonTimestamp"], self.last_activity)
                )
            else:
                organizational_unit_groups = self._get_inventory_group_names_from_computer_distinguished_name(
                    entry.entry_dn, organizational_unit
                )
                for count, group in enumerate(organizational_unit_groups, start=0):
                    display.debug("%d. processing group %s" % (count, group))
                    new_group_name = ""
                    if count == 0:
                        parent_group_name = self._get_safe_group_name(
                            organizational_unit_groups[0]
                        )
                        display.debug("adding group %s under all" % (parent_group_name))
                        self.inventory.add_group(parent_group_name)
                        self.inventory.add_child("all", parent_group_name)
                        new_group_name = parent_group_name
                    else:
                        parent_group_name = self._get_safe_group_name(
                            "-".join(organizational_unit_groups[0:count])
                        )
                        display.debug("creating parent group %s" % parent_group_name)
                        new_group_name = self._get_safe_group_name(
                            parent_group_name + "_" + group
                        )
                        display.debug(
                            "adding %s to %s" % (new_group_name, parent_group_name)
                        )
                        self.inventory.add_group(new_group_name)
                        self.inventory.add_child(parent_group_name, new_group_name)

                    # add host to leaf ou
                    if count == len(organizational_unit_groups) - 1:
                        self.inventory.add_host(hostname, group=new_group_name)
                        display.vvvv(
                            "%s added to inventory group %s"
                            % (hostname, new_group_name)
                        )

    def verify_file(self, path):
        """
            :param loader: an ansible.parsing.dataloader.DataLoader object
            :param path: the path to the inventory config file
            :return the contents of the config file
        """
        if super(InventoryModule, self).verify_file(path):
            if path.endswith(("active_directory.yml", "active_directory.yaml")):
                return True
        display.verbose(
            "active_directory inventory filename must end with 'active_directory.yml' or 'active_directory.yaml'"
        )
        return False

    def parse(self, inventory, loader, path, cache=True):

        super(InventoryModule, self).parse(inventory, loader, path)

        self._read_config_data(path)

        self._init_data()

        organizational_units_to_search = self.get_option("organizational_units")

        connection = self._ldap3_conn()

        cache_key = self.get_cache_key(path)
        # false when refresh_cache or --flush-cache is used
        if cache:
            # get the user-specified directive
            cache = self.get_option("cache")

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
                self._populate(results, organizational_unit)

        # If the cache has expired/doesn't exist or if refresh_inventory/flush cache is used
        # when the user is using caching, update the cached inventory
        if cache_needs_update or (not cache and self.get_option("cache")):
            self._cache[cache_key] = results
