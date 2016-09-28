# -*- coding: utf-8 -*-

"""
A simple Python module for common Active Directory authentication and lookup tasks
"""

from __future__ import unicode_literals

from base64 import b64encode
from datetime import datetime, timedelta

import ldap

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


__version__ = "1.0.0"


def convert_ad_timestamp(timestamp, json_safe=False):
    """
    Converts a LDAP timestamp to a datetime or a human-readable string
    Args:
        timestamp: the LDAP timestamp
        json_safe: If true, return a a human-readable string instead of a datetime

    Returns:
        A datetime or a human-readable string
    """
    timestamp = int(timestamp)
    if timestamp == 0:
        return None
    epoch_start = datetime(year=1601, month=1, day=1)
    seconds_since_epoch = timestamp / 10 ** 7
    converted_timestamp = epoch_start + timedelta(seconds=seconds_since_epoch)

    if json_safe:
        converted_timestamp = converted_timestamp.strftime("%x %X")

    return converted_timestamp


def _get_last_logon(timestamp, json_safe=False):
    """
    Converts a LastLogonTimestamp to a datetime or human-readable format
    Args:
        timestamp: The timestamp from a LastLogonTimestamp user attribute
        json_safe: If true, always return a string

    Returns:
        A datetime or string showing the user's last login, or the string "<=14", since
        LastLogonTimestamp is not accurate withing 14 days
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


def _decode_ldap_results(results, json_safe=False):
    """
    Converts LDAP search results from bytes to a dictionary of UTF-8 where possible
    Args:
        results: LDAP search results
        json_safe: If true, convert binary data to base64 and datetimes to human-readable strings

    Returns:
        A list of processed LDAP LDAP result dictionaries.

    """
    results = [entry for dn, entry in results if isinstance(entry, dict)]
    for ldap_object in results:
        for attribute in ldap_object.keys():
            # pyldap returns all attributes as bytes. Yuk!
            for i in range(len(ldap_object[attribute])):
                try:
                    ldap_object[attribute][i] = ldap_object[attribute][i].decode("UTF-8")
                except ValueError:
                    if json_safe:
                        ldap_object[attribute][i] = b64encode(ldap_object[attribute][i]).decode("UTF-8")
            if len(ldap_object[attribute]) == 1:
                ldap_object[attribute] = ldap_object[attribute][0]

    return results


class EasyAD(object):
    """
    A simple class for interacting with Active Directory

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
        "MemberOf",
        "phonebookVisibility",
        "physicalDeliveryOfficeName",
        "postalCode",
        "prefFirstName",
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
        "userPrincipalName"
    ]

    group_attributes = [
        "cn",
        "distinguishedName",
        "managedBy",
        "member",
        "name"
    ]

    def __init__(self, config):
        """
        Initializes the EasyAD object
        Args:
            config: A dictionary of configuration settings
                Required:
                    AD_SERVER: the hostname of the Active Directory Server
                    AD_DOMAIN: The domain to bind to, in TLD format
                Optional:
                    AD_REQUIRE_TLS: Require a TLS connection. True by default.
                    AD_CA_CERT_FILE: the path to the root CA certificate file
                    AD_BASE_DN: Overrides the base distinguished name. Derived from AD_DOMAIN by default.
        """
        self.config = config
        base_dn = ""
        for part in self.config["AD_DOMAIN"].split("."):
            base_dn += "dc={0},".format(part)
        base_dn = base_dn.rstrip(",")
        if "BASE_DN" not in self.config.keys() or self.config["BASE_DN"] is None:
            self.config["BASE_DN"] = base_dn
        self.ad = self._get_ad()
        self.user_attributes = EasyAD.user_attributes
        self.group_attributes = EasyAD.group_attributes

    def _get_ad(self):
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

        return ad

    def bind(self, credentials=None):
        """
        Attempts to bind to the Active Directory server

        Args:
            credentials: A optional dictionary of the username and password to use.
            If credentials are not passed, the credentials from the initial EasyAD configuration are used.

        Returns:
            True if the bind was successful

        Raises:
            ldap.INVALID_CREDENTIALS
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
        if "@" not in username:
            username = "{0}@{1}".format(username, self.config["AD_DOMAIN"])

        password = credentials["password"]

        self.ad.bind_s(username, password)
        return True

    def unbind(self):
        self.ad.unbind()

    def get_user(self, user_string, json_safe=False, credentials=None, attributes=None):
        """
        Searches for a unique user object and returns its attributes

        Args:
            user_string: A userPrincipalName, sAMAccountName, or distinguishedName
            json_safe: If true, convert binary data to base64 and datetimes to human-readable strings
            credentials: A optional dictionary of the username and password to use.
            If credentials are not passed, the credentials from the initial EasyAD configuration are used.
            attributes: An optional list of attributes to return. Otherwise uses self.user_attributes.
            To return all attributes, pass an empty list.

        Returns:
            A dictionary of user attributes

        Raises:
            ValueError: query returned no or multiple results
        """
        if attributes is None:
            attributes = self.user_attributes

        filter_string = "(&(objectClass=user)(|(userPrincipalName={0})(sAMAccountName={0})(mail={0})" \
                        "(distinguishedName={0})))".format(user_string)

        try:
            self.bind(credentials)
            results = self.ad.search_s(base=self.config["BASE_DN"],
                                       scope=ldap.SCOPE_SUBTREE,
                                       filterstr=filter_string,
                                       attrlist=attributes)

            results = _decode_ldap_results(results, json_safe=json_safe)

            if len(results) == 0:
                raise ValueError("No such user")
            elif len(results) > 1:
                raise ValueError("The query returned more than one result")

            user = results[0]

            if "lastLogonTimestamp" in user.keys():
                user["lastLogonTimestamp"] = _get_last_logon(user["lastLogonTimestamp"])
            if "lockoutTime" in user.keys():
                user["lockoutTime"] = convert_ad_timestamp(user["lockoutTime"], json_safe=json_safe)

            if "userAccountControl" in user.keys():
                user["userAccountControl"] = int(user["userAccountControl"])
                user["disabled"] = user["userAccountControl"] & 2 != 0
                user["passwordExpired"] = user["userAccountControl"] & 8388608 != 0
                user["passwordNeverExpires"] = user["userAccountControl"] & 65536 != 0
                user["smartcardRequired"] = user["userAccountControl"] & 262144 != 0

        finally:
            self.unbind()

        return user

    def get_group(self, group_string, json_safe=False, credentials=None, attributes=None):
        """
        Searches for a unique group object and returns its attributes

        Args:
            group_string: A name, cn, or distinguishedName
            json_safe: If true, convert binary data to base64 and datetimes to human-readable strings
            credentials: A optional dictionary of the username and password to use.
            If credentials are not passed, the credentials from the initial EasyAD configuration are used.
            attributes: An optional list of attributes to return. Otherwise uses self.group_attributes.
            To return all attributes, pass an empty list.

        Returns:
            A dictionary of group attributes

        Raises:
            ValueError: query returned no or multiple results
        """
        if attributes is None:
            attributes = self.group_attributes

        group_filter = "(&(objectClass=Group)(|(cn={0})(distinguishedName={0})))".format(group_string)

        try:
            self.bind(credentials)
            results = self.ad.search_s(base=self.config["BASE_DN"],
                                       scope=ldap.SCOPE_SUBTREE,
                                       filterstr=group_filter,
                                       attrlist=attributes)

            results = _decode_ldap_results(results, json_safe=json_safe)

            if len(results) == 0:
                raise ValueError("No such group")
            elif len(results) > 1:
                raise ValueError("The query returned more than one result")

        finally:
            self.unbind()

        return results[0]
