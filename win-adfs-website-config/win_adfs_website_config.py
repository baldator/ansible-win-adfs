#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: 2019, Marco Torello <marcotorello@gmail.com>
# MIT License

ANSIBLE_METADATA = {'metadata_version': '0.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = r'''
---
module: win_adfs_website_config
version_added: '2.7'
short_description: Create an ADFS configuration for a SAML/OAuth2 compatible website
description:
- Ansible module to automate Active Directory Federation Service relying parties and clients creation.
- The module support SAML and Oauth2 websites.
author:
- Marco Torello (@baldator)
options:
  name:
    description:
    - The name of the relying party.
    - If type is OAuth it is also the name of the OAuth client.
    type: string
    required: true
  state:
    description:
    - Define if the website configuration is present or not
    type: string
    choices:
    - Present
    - Absent
    default: Present
  redirecturl:
    description:
    - A list of endpoint objects.
    - Each endpoint object must contain a method, a protocol and an url.
    - Url schema must be https.
    - Endpoint index on ADFS is base on list order.
    type: list
    required: true
  claimsrules:
    description:
    - A string containing the claim rules.
    type: string
    required: true
  oauthClientType:
    description:
    - Define if the OAuth client is confidential or public
    choices:
    - public
    - confidential
    default: public
    type: string
  scopes:
    description:
    - The list of OAuth scopes the client will be granted
    choices:
    - allatclaims
    - openid
    default: allatclaims
    type: string
  type:
    description:
    - The website authenticatin protocol.
    choices:
    - saml
    - oauth
    default: saml
    type: string
requirements:
- ADFS PowerShell module on target server

'''

EXAMPLES = r'''
- name: add relying party
    win_adfs_website_config:
      name: testwebsite
      redirecturl: https://localhost1234
      claimsrules: >-
        c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname", Issuer == "AD AUTHORITY"]
        => issue(store = "Active Directory",
        types = ("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"),
        query = ";mail;{0}", param = c.Value);
      type: oauth
      state: present
      endpoints:
        - redirecturl: https://localhost1234
          method: POST
          protocol: SAMLAssertionConsumer
        - redirecturl: https://localhost12345
          method: POST
          protocol: SAMLAssertionConsumer
'''

RETURN = r'''

'''
