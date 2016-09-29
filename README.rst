pyldfire
========

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

Features
--------

-  Python 2 and 3 support
-  Authenticate user credentials via direct bind
-  Query user attributes
-  Query group attributes

Examples
--------

::

    from __future__ import unicode_literals, print_function

    from getpass import getpass
    from json import dumps

    from ldap import INVALID_CREDENTIALS

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

    credentials = dict(username=username, password=password)

    try:
        user = ad.get_user(username, credentials=credentials, json_safe=True)
    except INVALID_CREDENTIALS:
        print("Those credentials are invalid. Please try again.")
        exit(-1)

    # Successful login! Print the user's details as JSON
    print(dumps(user, sort_keys=True, indent=2, ensure_ascii=False))

    # You can also add service account credentials to the config to do lookups without
    # passing in the credentials on every call
    ad.config["AD_BIND_USERNAME"] = "SA-ADLookup"
    ad.config["AD_BIND_PASSWORD"] = 12345LuggageAmazing"

    user = ad.get_user("maurice.moss", json_safe=True)
    print(dumps(user, sort_keys=True, indent=2, ensure_ascii=False))

    group = ad.get_group("helpdesk", json_safe=True)
    print(dumps(user, sort_keys=True, indent=2, ensure_ascii=False))

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


easyad.EasyAD methods
---------------------

EasyAD.__init__(self, config)

::

    Initializes the EasyAD class

     Args:
            config: A dictionary of configuration settings
                Required:
                    AD_SERVER: the hostname of the Active Directory Server
                    AD_DOMAIN: The domain to bind to, in TLD format
                Optional:
                    AD_REQUIRE_TLS: Require a TLS connection. True by default.
                    AD_CA_CERT_FILE: the path to the root CA certificate file
                    AD_BASE_DN: Overrides the base distinguished name. Derived from AD_DOMAIN by default.


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


EasyAD.get_group(self, group_string, json_safe=False, credentials=None, attributes=None)

::

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


EasyAD.bind(credentials=None)

::

    Attempts to bind from the Active Directory server

            Args:
                credentials: A optional dictionary of the username and password to use.
                If credentials are not passed, the credentials from the initial EasyAD configuration are used.

            Returns:
                True if the bind was successful

            Raises:
                ldap.INVALID_CREDENTIALS

EasyAD.unbind()

::

    Unbind from the Active Directory server
