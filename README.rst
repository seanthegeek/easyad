easyad
======

A simple Python module for common Active Directory authentication and lookup tasks

::

     Copyright 2016 Sean Whalen

     Licensed under the Apache License, Version 2.0 (the "License");
     you may not use this file except in compliance with the License.
     You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

     Unless required by applicable law or agreed to in writing, software
     distributed under the License is distributed on an "AS IS" BASIS,
     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
     See the License for the specific language governing permissions and
     limitations under the License.

Why?
----

Most LDAP solutions for Python and/or Flask focus in being generic LDAP
interfaces. It's up to the developer to understand and work around the
quirks of Active Directory. This module aims to reduce the complexity
and development time for Python-powered applications that securely
interface with Active Directory.

Features
--------

-  Python 2 and 3 support
-  Unicode support
-  Authenticate user credentials via direct bind
-  Quickly test if a user is a member of a group, including nested groups
-  Query user and group attributes
-  Simple user and group search
-  Get all groups that a user is a member of, including nested groups
-  Get a list of all group member users, including from nested groups
-  Options to automatically convert binary data into base64 for JSON-safe
   output


Installing
----------

First, install the system dependencies

::

    $ sudo apt-get install libsasl2-dev python3-dev python3-pip libldap2-dev libssl-dev

Then

::

    $ sudo pip3 -U easyad

Example uses
------------

::

    from __future__ import unicode_literals, print_function

    from getpass import getpass
    from json import dumps

    from easyad import EasyAD

    # Workaround to make input() return a string in Python 2 like it does in Python 3
    # It's 2016...you should really be using Python 3
    try:
        input = raw_input
    except NameError:
            pass

    # Set up configuration. You could also use a Flask app.config
    config = dict(AD_SERVER="ad.example.net",
                  AD_DOMAIN="example.net",
                  CA_CERT_FILE="myrootca.crt")

    # Initialize all the things!
    ad = EasyAD(config)

    # Authenticate a user
    username = input("Username: ")
    password = getpass("Password: ")

    local_admin_group_name = "LocalAdministrators"

    user = ad.authenticate_user(username, password, json_safe=True)

    if user:
        # Successful login! Let's print your details as JSON
        print(dumps(user, sort_keys=True, indent=2, ensure_ascii=False))

        # Lets find out if you are a member of the "LocalAdministrators" group
        print(ad.user_is_member_of_group(user, local_admin_group_name))
    else:
        print("Those credentials are invalid. Please try again.")
        exit(-1)

    # You can also add service account credentials to the config to do lookups without
    # passing in the credentials on every call
    ad.config["AD_BIND_USERNAME"] = "SA-ADLookup"
    ad.config["AD_BIND_PASSWORD"] = "12345LuggageAmazing"

    user = ad.get_user("maurice.moss", json_safe=True)
    print(dumps(user, sort_keys=True, indent=2, ensure_ascii=False))

    group = ad.get_group("helpdesk", json_safe=True)
    print(dumps(user, sort_keys=True, indent=2, ensure_ascii=False))

    print("Is Jen a manager?")
    print(ad.user_is_member_of_group("jen.barber", "Managers"))

    # The calls below can be taxing on an AD server, especially when used frequently.
    # If you just need to check if a user is a member of a group use
    # EasyAD.user_is_member_of_group(). It is *much* faster.

    # I wonder who all is in the "LocalAdministrators" group? Let's run a
    # query that will search in nested groups.
    print(dumps(ad.get_all_users_in_group(local_admin_group_name, json_safe=True)))

    # Let's see all of the groups that Moss in in, including nested groups
    print(dumps(ad.get_all_user_groups(user), indent=2, ensure_ascii=False))

easyad methods
--------------

convert_ad_timestamp(timestamp, json_safe=False)

::

    Converts a LDAP timestamp to a datetime or a human-readable string

    Args:
        timestamp: the LDAP timestamp
        json_safe: If true, return a a human-readable string instead of a datetime

    Returns:
        A datetime or a human-readable string


enhance_user(user, json_safe=False)

::

    Adds computed attributes to AD user results

    Args:
        user: A dictionary of user attributes
        json_safe: If true, converts binary data into base64,
        And datetimes into human-readable strings

    Returns:
        An enhanced dictionary of user attributes

process_ldap_results(results, json_safe=False)

::

    Converts LDAP search results from bytes to a dictionary of UTF-8 where possible

    Args:
        results: LDAP search results
        json_safe: If true, convert binary data to base64 and datetimes to human-readable strings

    Returns:
        A list of processed LDAP result dictionaries.

easyad.ADConnection
-------------------

::

    A LDAP configuration abstraction class

    Attributes:
        config: The configuration dictionary
        ad:The LDAP interface instance


ADConnection.__init__(self, config)

::


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


ADConnection.bind(self, credentials=None)

::

    Attempts to bind to the Active Directory server

    Args:
        credentials: A optional dictionary of the username and password to use.
        If credentials are not passed, the credentials from the initial EasyAD configuration are used.

    Returns:
        True if the bind was successful

    Raises:
        ldap.LDAP_ERROR

ADConnection.unbind(self)

::

    Unbind from the Active Directory server

easyad.EasyAD
-------------

::

    A high-level class for interacting with Active Directory

    Attributes:
        user_attributes: A default list of attributes to return from a user query
        group_attributes: A default list of attributes to return from a user query

EasyAD.__init__(self, config)

::

    Initializes an EasyAD object

     Args:
        config: A dictionary of configuration settings
            Required:
                AD_SERVER: the hostname of the Active Directory Server
                AD_DOMAIN: The domain to bind to, in TLD format
            Optional:
                AD_REQUIRE_TLS: Require a TLS connection. True by default.
                AD_CA_CERT_FILE: the path to the root CA certificate file
                AD_BASE_DN: Overrides the base distinguished name. Derived from AD_DOMAIN by default.


EasyAD.authenticate_user(self, username, password, base=None, attributes=None, json_safe=False)

::

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

EasyAD.get_all_user_groups(self, user, base=None, credentials=None, json_safe=False)

::

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


EasyAD.get_all_users_in_group(self, group, base=None, credentials=None, json_safe=False)

::

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


EasyAD.get_group(self, group_string, base=None, credentials=None, attributes=None, json_safe=False)

::

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


EasyAD.get_user(self, user_string, json_safe=False, credentials=None, attributes=None)

::

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


EasyAD.resolve_group_dn(self, group, base=None, credentials=None, json_safe=False)

::

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

EasyAD.resolve_user_dn(self, user, base=None, credentials=None, json_safe=False)

::

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

search(self, base=None, scope=ldap.SCOPE_SUBTREE, filter_string="(objectClass=*)", credentials=None,
               attributes=None, json_safe=False, page_size=None)

::


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


search_for_groups(self, group_string, base=None, search_attributes=None, return_attributes=None,
                   credentials=None, json_safe=False)

::

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

search_for_users(self, user_string, base=None, search_attributes=None, return_attributes=None, credentials=None,
                 json_safe=False)

::

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


EasyAD.user_is_member_of_group(self, user, group, base=None, credentials=None)

::

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
