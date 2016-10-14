# -*- coding: utf-8 -*-

"""
A simple Python module for common Active Directory authentication and lookup tasks
"""

from __future__ import unicode_literals, print_function

from sys import stderr
from base64 import b64encode
from datetime import datetime, timedelta

import ldap
from ldap.controls import SimplePagedResultsControl
from ldap.filter import escape_filter_chars

"""Copyright 2016 Sean Whalen

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License."""


__version__ = "1.0.6"


# Python 2 & 3 support hack
try:
    unicode
except NameError:
    unicode = str

exchange_mailbox_values = {
    1: "User Mailbox",
    2: "Linked Mailbox",
    4: "Shared Mailbox",
    8: "Legacy Mailbox",
    16: "Room Mailbox",
    32: "Equipment Mailbox",
    8192: "System Attendant Mailbox",
    16384: "Mailbox Database Mailbox",
    2147483648: "Remote User Mailbox",
    8589934592: "Remote Room Mailbox",
    17173869184: "Remote Equipment Mailbox",
    34359738368: "Remote Shared Mailbox"
}

remote_exchange_mailbox_values = {
    2147483648: "Remote User Mailbox",
    8589934592: "Remote Room Mailbox",
    17173869184: "Remote Equipment Mailbox",
    34359738368: "Remote Shared Mailbox"
}


def _create_controls(pagesize):
    """Create an LDAP control with a page size of "pagesize"."""
    # Initialize the LDAP controls for paging. Note that we pass ''
    # for the cookie because on first iteration, it starts out empty.
    return SimplePagedResultsControl(criticality=True, size=pagesize, cookie="")


def _get_page_controls(serverctrls):
    """Lookup an LDAP paged control object from the returned controls."""
    # Look through the returned controls and find the page controls.
    # This will also have our returned cookie which we need to make
    # the next search request.
    for control in serverctrls:
        if control.controlType == SimplePagedResultsControl.controlType:
            return control


def convert_ad_timestamp(timestamp, json_safe=False, str_format="%x %X"):
    """
    Converts a LDAP timestamp to a datetime or a human-readable string
    Args:
        timestamp: the LDAP timestamp
        json_safe: If true, return a a human-readable string instead of a datetime
        str_format: The string format to use if json_safe is true

    Returns:
        A datetime or a human-readable string
    """
    try:
        timestamp = int(timestamp)
        if timestamp == 0:
            return None
        epoch_start = datetime(year=1601, month=1, day=1)
        seconds_since_epoch = timestamp / 10 ** 7
        converted_timestamp = epoch_start + timedelta(seconds=seconds_since_epoch)

    except ValueError:
        converted_timestamp = datetime.strptime(timestamp.split(".")[0], "%Y%m%d%H%M%S")

    if json_safe:
        converted_timestamp = converted_timestamp.strftime(str_format)

    return converted_timestamp


def _get_last_logon(timestamp, json_safe=False):
    """
    Converts a LastLogonTimestamp to a datetime or human-readable format
    Args:
        timestamp: The timestamp from a lastLogonTimestamp user attribute
        json_safe: If true, always return a string

    Returns:
        A datetime or string showing the user's last login, or the string "<=14", since
        lastLogonTimestamp is not accurate withing 14 days
    """
    timestamp = convert_ad_timestamp(timestamp, json_safe=False)
    if timestamp is None:
        return -1
    delta = datetime.now() - timestamp
    days = delta.days

    # LastLogonTimestamp is not accurate beyond 14 days
    if days <= 14:
        timestamp = "<= 14 days"
    elif json_safe:
        timestamp.strftime("%x %X")

    return timestamp


def process_ldap_results(results, json_safe=False):
    """
    Converts LDAP search results from bytes to a dictionary of UTF-8 where possible

    Args:
        results: LDAP search results
        json_safe: If true, convert binary data to base64 and datetimes to human-readable strings

    Returns:
        A list of processed LDAP result dictionaries.
    """

    for i in range(len(results)):
        if isinstance(results[i], tuple):
            results[i] = results[i][1]
    results = [result for result in results if isinstance(result, dict)]
    for ldap_object in results:
        for attribute in ldap_object.keys():
            # pyldap returns all attributes as bytes. Yuk!
            for i in range(len(ldap_object[attribute])):
                if isinstance(ldap_object[attribute][i], bytes):
                    try:
                        ldap_object[attribute][i] = ldap_object[attribute][i].decode("UTF-8")
                    except ValueError:
                        if json_safe:
                            ldap_object[attribute][i] = b64encode(ldap_object[attribute][i]).decode("UTF-8")
            if len(ldap_object[attribute]) == 1:
                ldap_object[attribute] = ldap_object[attribute][0]

    return results


def enhance_user(user, json_safe=False):
    """
    Adds computed attributes to AD user results
    Args:
        user: A dictionary of user attributes
        json_safe: If true, converts binary data into base64,
        And datetimes into human-readable strings

    Returns:
        An enhanced dictionary of user attributes
    """
    if "memberOf" in user.keys():
        user["memberOf"] = sorted(user["memberOf"], key=lambda dn: dn.lower())
    if "showInAddressBook" in user.keys():
        user["showInAddressBook"] = sorted(user["showInAddressBook"], key=lambda dn: dn.lower())
    if "lastLogonTimestamp" in user.keys():
        user["lastLogonTimestamp"] = _get_last_logon(user["lastLogonTimestamp"])
    if "lockoutTime" in user.keys():
        user["lockoutTime"] = convert_ad_timestamp(user["lockoutTime"], json_safe=json_safe)
    if "pwdLastSet" in user.keys():
        user["pwdLastSet"] = convert_ad_timestamp(user["pwdLastSet"], json_safe=json_safe)
    if "userAccountControl" in user.keys():
        user["userAccountControl"] = int(user["userAccountControl"])
        user["disabled"] = user["userAccountControl"] & 2 != 0
        user["passwordExpired"] = user["userAccountControl"] & 8388608 != 0
        user["passwordNeverExpires"] = user["userAccountControl"] & 65536 != 0
        user["smartcardRequired"] = user["userAccountControl"] & 262144 != 0
    if "whenCreated" in user.keys():
        user["whenCreated"] = convert_ad_timestamp(user["whenCreated"], json_safe=json_safe)
    if "msExchRecipientTypeDetails" in user.keys():
        user["msExchRecipientTypeDetails"] = int(user["msExchRecipientTypeDetails"])
        user["remoteExchangeMailbox"] = user["msExchRecipientTypeDetails"] in remote_exchange_mailbox_values
        user["exchangeMailbox"] = user["msExchRecipientTypeDetails"] in exchange_mailbox_values.keys()
        if user["exchangeMailbox"]:
            user["exchangeMailboxType"] = exchange_mailbox_values[user["msExchRecipientTypeDetails"]]

    return user


class ADConnection(object):
    """
    A LDAP configuration abstraction

    Attributes:
        config: The configuration dictionary
        ad: The LDAP interface instance
    """
    def __init__(self, config):
        """
        Initializes an ADConnection object

         Args:
            config: A dictionary of configuration settings
                Required:
                    AD_SERVER: The hostname of the Active Directory Server
                Optional:
                    AD_REQUIRE_TLS: Require a TLS connection. True by default.
                    AD_CA_CERT_FILE: The path to the root CA certificate file
                    AD_PAGE_SIZE: Overrides the default page size of 1000
                    AD_OPTIONS: A dictionary of other python-ldap options
        """
        self.config = config
        ad_server_url = "ldap://{0}".format(self.config["AD_SERVER"])
        ad = ldap.initialize(ad_server_url)
        ad.set_option(ldap.OPT_PROTOCOL_VERSION, ldap.VERSION3)
        ad.set_option(ldap.OPT_REFERRALS, 0)

        if "AD_CA_CERT_FILE" in self.config and self.config["AD_CA_CERT_FILE"]:
            ad.set_option(ldap.OPT_X_TLS_CACERTFILE, self.config["AD_CA_CERT_FILE"])  # The root CA certificate
        if "AD_REQUIRE_TLS" in self.config and not self.config["AD_REQUIRE_TLS"]:
            ad.set_option(ldap.OPT_X_TLS_DEMAND, 0)
        else:
            ad.set_option(ldap.OPT_X_TLS_DEMAND, 1)  # Force TLS by default
        if "AD_PAGE_SIZE" not in self.config:
            self.config["AD_PAGE_SIZE"] = 1000
        if "AD_OPTIONS" in config and isinstance(config["AD_OPTIONS"], dict):
            options = config["AD_OPTIONS"]
            for key in options.keys():
                ad.set_option(key, options[key])

        self.ad = ad

    def bind(self, credentials=None):
        """
        Attempts to bind to the Active Directory server

        Args:
            credentials: A optional dictionary of the username and password to use.
            If credentials are not passed, the credentials from the initial EasyAD configuration are used.

        Returns:
            True if the bind was successful

        Raises:
            ldap.LDAP_ERROR
        """
        if credentials is None or "username" not in credentials or "password" not in credentials:
            if "AD_BIND_USERNAME" not in self.config or self.config["AD_BIND_USERNAME"] is None:
                raise ValueError("AD_BIND_USERNAME must be set")
            if "AD_BIND_PASSWORD" not in self.config or self.config["AD_BIND_PASSWORD"] is None:
                raise ValueError("AD_BIND_PASSWORD must be set")

            credentials = dict()
            credentials["username"] = self.config["AD_BIND_USERNAME"]
            credentials["password"] = self.config["AD_BIND_PASSWORD"]

        username = credentials["username"].split("\\")[-1]
        if "@" not in username and "cn=" not in username.lower():
            username = "{0}@{1}".format(username, self.config["AD_DOMAIN"])

        password = credentials["password"]

        self.ad.bind_s(username, password)
        return True

    def unbind(self):
        """
        Unbind from the Active Directory server
        """
        self.ad.unbind()


class EasyAD(object):
    """
    A high-level class for interacting with Active Directory

    Attributes:
        user_attributes: A default list of attributes to return from a user query
        group_attributes: A default list of attributes to return from a user query
    """

    user_attributes = [
        "businessCategory",
        "businessSegment",
        "businessSegmentDescription",
        "businessUnitDescription"
        "c",
        "cn",
        "co",
        "company",
        "costCenter",
        "countryCode",
        "department",
        "departmentNumber",
        "displayName",
        "distinguishedName",
        "employeeClass",
        "employeeNumber",
        "employeeStatus",
        "employeeType",
        "enterpriseBusinessUnitDescription",
        "givenName",
        "hireDate",
        "homeDirectory",
        "homeDrive",
        "iamFullName",
        "ipPhone",
        "jobFamilyDescription",
        "jobFunctionDescription",
        "jobTrack",
        "l",
        "LastLogonTimestamp",
        "lockoutTime",
        "mail",
        "mailNickname",
        "manager",
        "memberOf",
        "msExchRecipientTypeDetails",
        "phonebookVisibility",
        "physicalDeliveryOfficeName",
        "postalCode",
        "prefFirstName",
        "proxyAddresses",
        "pwdLastSet",
        "rehireDate",
        "roomNumber",
        "sAMAccountName",
        "scriptPath",
        "showInAddressBook",
        "siteCode",
        "siteName",
        "sn",
        "st",
        "streetAddress",
        "telephoneNumber",
        "thumbnailPhoto",
        "title",
        "uid",
        "userAccountControl",
        "userPrincipalName",
        "whenCreated"
    ]

    group_attributes = [
        "cn",
        "distinguishedName",
        "managedBy",
        "member",
        "name"
    ]

    # Another python 2 support hack
    user_attributes = list(map(lambda x: str(x), user_attributes))
    group_attributes = list(map(lambda x: str(x), group_attributes))

    def __init__(self, config):
        """
        Initializes an EasyAD object

        Args:
            config: A dictionary of configuration settings
                Required:
                    AD_SERVER: The hostname of the Active Directory Server
                    AD_DOMAIN: The domain to bind to, in TLD format
                Optional:
                    AD_REQUIRE_TLS: Require a TLS connection. True by default.
                    AD_CA_CERT_FILE: The path to the root CA certificate file
                    AD_BASE_DN: Overrides the base distinguished name. Derived from AD_DOMAIN by default.
                    AD_PAGE_SIZE: Overrides the default page size of 1000
                    AD_OPTIONS: A dictionary of other python-ldap options
        """
        self.config = config
        base_dn = ""
        for part in self.config["AD_DOMAIN"].split("."):
            base_dn += "dc={0},".format(part)
        base_dn = base_dn.rstrip(",")
        if "AD_BASE_DN" not in self.config.keys() or self.config["BASE_DN"] is None:
            self.config["AD_BASE_DN"] = base_dn
        self.user_attributes = EasyAD.user_attributes
        self.group_attributes = EasyAD.group_attributes

    def search(self, base=None, scope=ldap.SCOPE_SUBTREE, filter_string="(objectClass=*)", credentials=None,
               attributes=None, json_safe=False, page_size=None):
        """
        Run a search of the Active Directory server, and get the results

        Args:
            base: Optionally override the DN of the base object
            scope: Optional scope setting, subtree by default.
            filter_string: Optional custom filter string
            credentials: Optionally override the bind credentials
            attributes: A list of attributes to return. If none are specified, all attributes are returned
            json_safe: If true, convert binary data to base64, and datetimes to human-readable strings
            page_size: Optionally override the number of results to return per LDAP page

        Returns:
            Results as a list of dictionaries

        Raises:
            ldap.LDAP_ERROR

        Notes:
            Setting a small number of search_attributes and return_attributes reduces server load and bandwidth
            respectively
        """

        connection = ADConnection(self.config)
        results = []
        first_pass = True

        if base is None:
            base = self.config["AD_BASE_DN"]

        if page_size is None:
            page_size = self.config["AD_PAGE_SIZE"]

        # Create the page control to work from
        pg_ctrl = SimplePagedResultsControl(criticality=True, size=page_size, cookie='')

        try:
            connection.bind(credentials)

            while first_pass or pg_ctrl.cookie:
                first_pass = False
                msgid = connection.ad.search_ext(base,
                                                 scope=scope,
                                                 filterstr=filter_string,
                                                 attrlist=attributes,
                                                 serverctrls=[pg_ctrl])

                rtype, rdata, rmsgid, serverctrls = connection.ad.result3(msgid)
                results += process_ldap_results(rdata, json_safe=json_safe)

                pctrls = _get_page_controls(serverctrls)
                if pctrls is None:
                    print("Warning: Server ignores RFC 2696 control", file=stderr)
                    break

                # Update the cookie
                pg_ctrl.cookie = serverctrls[0].cookie

        finally:
            connection.unbind()

        return results

    def get_user(self, user_string, base=None, credentials=None, attributes=None, json_safe=False):
        """
        Searches for a unique user object and returns its attributes

        Args:
            user_string: A userPrincipalName, sAMAccountName, uid, email address, or distinguishedName
            base: Optionally override the base dn
            credentials: A optional dictionary of the username and password to use.
            If credentials are not passed, the credentials from the initial EasyAD configuration are used.
            attributes: An optional list of attributes to return. Otherwise uses self.user_attributes.
            To return all attributes, pass an empty list.
            json_safe: If true, convert binary data to base64 and datetimes to human-readable strings

        Returns:
            A dictionary of user attributes

        Raises:
            ValueError: Query returned no or multiple results

        Raises:
            ldap.LDAP_ERROR
        """
        if base is None:
            base = self.config["AD_BASE_DN"]

        if attributes is None:
            attributes = self.user_attributes.copy()

        filter_string = "(&(objectClass=user)(|(userPrincipalName={0})(sAMAccountName={0})(uid={0})(mail={0})" \
                        "(distinguishedName={0})(proxyAddresses=SMTP:{0})))".format(escape_filter_chars(user_string))

        results = self.search(base=base,
                              filter_string=filter_string,
                              credentials=credentials,
                              attributes=attributes,
                              json_safe=json_safe)

        if len(results) == 0:
            raise ValueError("No such user")
        elif len(results) > 1:
            raise ValueError("The query returned more than one result")

        return enhance_user(results[0], json_safe=json_safe)

    def authenticate_user(self, username, password, base=None, attributes=None, json_safe=False):
        """
        Test if the given credentials are valid

        Args:
            username: The username
            password: The password
            base: Optionally overrides the base object DN
            attributes: A list of user attributes to return
            json_safe: Convert binary data to base64 and datetimes to human-readable strings

        Returns:
            A dictionary of user attributes if successful, or False if it failed

        Raises:
            ldap.LDAP_ERROR
        """
        credentials = dict(username=username, password=password)
        try:
            user = self.get_user(username,
                                 credentials=credentials,
                                 base=base,
                                 attributes=attributes,
                                 json_safe=json_safe)
            return user
        except ldap.INVALID_CREDENTIALS:
            return False

    def get_group(self, group_string, base=None, credentials=None, attributes=None, json_safe=False):
        """
        Searches for a unique group object and returns its attributes

        Args:
            group_string: A group name, cn, or dn
            base: Optionally override the base object dn
            credentials: A optional dictionary of the username and password to use.
            If credentials are not passed, the credentials from the initial EasyAD configuration are used.
            attributes: An optional list of attributes to return. Otherwise uses self.group_attributes.
            To return all attributes, pass an empty list.
            json_safe: If true, convert binary data to base64 and datetimes to human-readable strings

        Returns:
            A dictionary of group attributes

        Raises:
            ValueError: Query returned no or multiple results
            ldap.LDAP_ERROR: An LDAP error occurred
        """
        if base is None:
            base = self.config["AD_BASE_DN"]

        if attributes is None:
            attributes = self.group_attributes.copy()

        group_filter = "(&(objectClass=Group)(|(cn={0})(distinguishedName={0})))".format(
            escape_filter_chars(group_string))

        results = self.search(base=base,
                              filter_string=group_filter,
                              credentials=credentials,
                              attributes=attributes,
                              json_safe=json_safe)

        if len(results) == 0:
            raise ValueError("No such group")
        elif len(results) > 1:
            raise ValueError("The query returned more than one result")

        group = results[0]
        if "member" in group.keys():
            group["member"] = sorted(group["member"], key=lambda dn: dn.lower())

        return group

    def resolve_user_dn(self, user, base=None, credentials=None, json_safe=False):
        """
        Returns a user's DN when given a principalAccountName, sAMAccountName, email, or DN

        Args:
            user: A principalAccountName, sAMAccountName, email, DN, or a dictionary containing a DN
            base: Optionally overrides the base object DN
            credentials: An optional dictionary of the username and password to use
            json_safe: If true, convert binary data to base64 and datetimes to human-readable strings

        Returns:
            The user's DN

        Raises:
            ldap.LDAP_ERROR
        """
        if isinstance(user, dict):
            user = user["distinguishedName"]
        elif isinstance(user, str) or isinstance(user, unicode):
            if not user.lower().startswith("cn="):
                user = self.get_user(user,
                                     base=base,
                                     credentials=credentials,
                                     attributes=["distinguishedName"],
                                     json_safe=json_safe)["distinguishedName"]
        else:
            raise ValueError("User passed as an unsupported data type")
        return user

    def resolve_group_dn(self, group, base=None, credentials=None, json_safe=False):
        """
        Returns a group's DN when given a principalAccountName, sAMAccountName, email, or DN

        Args:
            group: A group name, CN, or DN, or a dictionary containing a DN
            base: Optionally overrides the base object DN
            credentials: An optional dictionary of the username and password to use
            json_safe: If true, convert binary data to base64 and datetimes to human-readable strings

        Returns:
            The groups's DN

        Raises:
            ldap.LDAP_ERROR
        """
        if isinstance(group, dict):
            group = group["distinguishedName"]
        elif isinstance(group, str) or isinstance(group, unicode):
            if not group.lower().startswith("cn="):
                group = self.get_group(group,
                                       base=base,
                                       credentials=credentials,
                                       attributes=["distinguishedName"],
                                       json_safe=json_safe)["distinguishedName"]
        else:
            raise ValueError("Group passed as an unsupported data type")
        return group

    def get_all_user_groups(self, user, base=None, credentials=None, json_safe=False):
        """
        Returns a list of all group DNs that a user is a member of, including nested groups

        Args:
            user: A username, distinguishedName, or a dictionary containing a distinguishedName
            base: Overrides the configured base object dn
            credentials: An optional dictionary of the username and password to use
            json_safe: If true, convert binary data to base64 and datetimes to human-readable strings

        Returns:
            A list of group DNs that the user is a member of, including nested groups

        Raises:
            ldap.LDAP_ERROR

        Notes:
            This call can be taxing on an AD server, especially when used frequently.
            If you just need to check if a user is a member of a group,
            use EasyAD.user_is_member_of_group(). It is *much* faster.
        """
        user_dn = self.resolve_user_dn(user)
        filter_string = "(member:1.2.840.113556.1.4.1941:={0})".format(escape_filter_chars(user_dn))

        results = self.search(base=base,
                              filter_string=filter_string,
                              credentials=credentials,
                              json_safe=json_safe)

        return sorted(list(map(lambda x: x["distinguishedName"], results)), key=lambda s: s.lower())

    def get_all_users_in_group(self, group, base=None, credentials=None, json_safe=False):
        """
        Returns a list of all user DNs that are members of a given group, including from nested groups

       Args:
           group: A group name, cn, or dn
           base: Overrides the configured base object dn
           credentials: An optional dictionary of the username and password to use
           json_safe: If true, convert binary data to base64 and datetimes to human-readable strings

       Returns:
           A list of all user DNs that are members of a given group, including users from nested groups

        Raises:
            ldap.LDAP_ERROR

       Notes:
           This call can be taxing on an AD server, especially when used frequently.
           If you just need to check if a user is a member of a group,
           use EasyAD.user_is_member_of_group(). It is *much* faster.
       """
        group = self.resolve_group_dn(group)
        if base is None:
            base = self.config["AD_BASE_DN"]
        filter_string = "(&(objectClass=user)(memberof:1.2.840.113556.1.4.1941:={0}))".format(
            escape_filter_chars(group))

        results = self.search(base=base,
                              scope=ldap.SCOPE_SUBTREE,
                              filter_string=filter_string,
                              attributes=["distinguishedName"],
                              credentials=credentials,
                              json_safe=json_safe)

        return sorted(list(map(lambda x: x["distinguishedName"],
                               process_ldap_results(results, json_safe=json_safe))), key=lambda s: s.lower())

    def user_is_member_of_group(self, user, group, base=None, credentials=None):
        """
        Tests if a given user is a member of the given group

        Args:
            user: A principalAccountName, sAMAccountName, email, or DN
            group: A group name, cn, or dn
            base: An optional dictionary of the username and password to use
            credentials: An optional dictionary of the username and password to use

        Raises:
            ldap.LDAP_ERROR

        Returns:
            A boolean that indicates if the given user is a member of the given group
        """
        user = self.resolve_user_dn(user, base=base, credentials=credentials)
        group = self.resolve_group_dn(group, base=base, credentials=credentials)
        return len(self.get_all_users_in_group(group, base=user, credentials=credentials)) > 0

    def search_for_users(self, user_string, base=None, search_attributes=None, return_attributes=None, credentials=None,
                         json_safe=False):
        """
        Returns matching user objects as a list of dictionaries

        Args:
            user_string: The substring to search for
            base: Optionally override the base object's DN
            search_attributes: The attributes to search through, with binary data removed
            easyad.EasyAD.user_attributes by default
            return_attributes: A list of attributes to return. easyad.EasyAD.user_attributes by default
            credentials: Optionally override the bind credentials
            json_safe: If true, convert binary data to base64 and datetimes to human-readable strings

        Returns:
            Results as a list of dictionaries

        Raises:
            ldap.LDAP_ERROR

        Notes:
            Setting a small number of search_attributes and return_attributes reduces server load and bandwidth
            respectively

        """
        if search_attributes is None:
            search_attributes = EasyAD.user_attributes.copy()
        if "memberOf" in search_attributes:
            search_attributes.remove("memberOf")
        if "thumbnailPhoto" in search_attributes:
            search_attributes.remove("thumbnailPhoto")

        if return_attributes is None:
            return_attributes = EasyAD.user_attributes.copy()

        generated_attributes = ["disabled", "passwordExpired", "passwordNeverExpires", "smartcardRequired"]
        for attribute in generated_attributes:
            if attribute in return_attributes:
                if "userAccountControl" not in return_attributes:
                    return_attributes.append("userAccountControl")
                break

        filter_string = ""
        for attribute in search_attributes:
            filter_string += "({0}=*{1}*)".format(attribute, escape_filter_chars(user_string))

        filter_string = "(&(objectClass=User)(|{0}))".format(filter_string)

        results = self.search(base=base,
                              filter_string=filter_string,
                              attributes=return_attributes,
                              credentials=credentials,
                              json_safe=json_safe)

        results = list(map(lambda user: enhance_user(user, json_safe=json_safe), results))

        return results

    def search_for_groups(self, group_string, base=None, search_attributes=None, return_attributes=None,
                          credentials=None, json_safe=False):
        """
        Returns matching group objects as a list of dictionaries
        Args:
            group_string: The substring to search for
            base: Optionally override the base object's DN
            search_attributes: The attributes to search through, with binary data removed
            easyad.EasyAD.group_attributes by default
            return_attributes: A list of attributes to return. easyad.EasyAD.group_attributes by default
            credentials: Optionally override the bind credentials
            json_safe: If true, convert binary data to base64 and datetimes to human-readable strings

        Returns:
            Results as a list of dictionaries

        Raises:
            ldap.LDAP_ERROR

        Notes:
            Setting a small number of search_attributes and return_attributes reduces server load and bandwidth
            respectively

        """
        if search_attributes is None:
            search_attributes = EasyAD.group_attributes.copy()
        if "member" in search_attributes:
            search_attributes.remove("member")

        if return_attributes is None:
            return_attributes = EasyAD.group_attributes.copy()

        filter_string = ""
        for attribute in search_attributes:
            filter_string += "({0}=*{1}*)".format(attribute, escape_filter_chars(group_string))

        filter_string = "(&(objectClass=Group)(|{0}))".format(filter_string)

        results = self.search(base=base,
                              filter_string=filter_string,
                              attributes=return_attributes,
                              credentials=credentials,
                              json_safe=json_safe)

        return results
