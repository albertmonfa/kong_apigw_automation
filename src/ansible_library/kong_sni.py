#!/usr/bin/python
'''
Author: Albert Monfa 2017

This module is based on Christo Crampton work.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
'''

DOCUMENTATION = '''
---
module: kong_consumer
short_description: Manage consumers in Kong
description:
    - Manage Kong SNIs in their main CRUD operations. See U(https://getkong.org/docs/0.10.x/admin-api/) for details.
author: "Albert Monfa (@albertmonfa)"
options:
  admin_url:
    description:
      - Kong comes with an internal RESTful Admin API for administration purposes. Requests to the Admin API can be sent to any node in the cluster, and Kong will keep the configuration consistent across all nodes.
      - 8001 is the default port on which the Admin API listens.
      - 8444 is the default port for HTTPS traffic to the Admin API.
    required: true
notes:
  - The Kong Consumer module always returns changed state because the Admin API does not difference between a consumer changed or unchanged and always return an 200 HTTP code. 
'''

EXAMPLES = '''
   
'''

RETURN = '''

'''

ANSIBLE_METADATA = {
    'metadata_version': '1.0',
    'supported_by': 'community',
    'status': ['preview']
}

class API:

    def __init__(self, admin_url):
        self.admin_url = admin_url

    def __url(self, path):
        return "{}{}" . format (self.admin_url, path)
    
    def list(self):
        url = self.__url("/snis/")
        return requests.get(url)

    def add(self, **data):        
        method = "post"        
        url = self.__url("/snis/")
        return getattr(requests, method)(url, data)

    def update(self, **data):        
        method = "patch"        
        url = self.__url("/snis/")
        name = data.get('name')
        url = "{}{}" . format (url, name)
        return getattr(requests, method)(url, data)
        
    def delete(self, **data):        
        url = self.__url("/snis/")
        name = data.get('name')
        url = "{}{}" . format (url, name)
        return requests.delete(url)        

    def info_sni(self, name):
        url = self.__url("/snis/")
        url = "{}{}" . format (url, name)
        response = requests.get(url)
        return response

class ModuleHelper:

    def param_discovery(self, module):
        
        admin_url = module.params['admin_url']
        state = module.params['state']    
        data = {}

        for field in module.params:
            value = module.params.get(field, None)
            if value is not None and field not in ['admin_url', 'state']:
                data[field] = value
       
        return (admin_url, data, state)

    def get_response(self, response, state):

        if state == "present":
           meta = response.json()
           has_changed = response.status_code in [200, 201]
                       
        if state == "absent":
           meta = {}
           has_changed = response.status_code == 204

        if state == "list":
           meta = response.json()
           has_changed = True

        if state == "info":
            meta = response
            has_changed = True

        if state == "get":
            meta = response
            has_changed = True

        return (has_changed, meta)


def if_failed(module, response):
    if int(response.status_code) > 399:
       module.fail_json(msg=response.json())

def main():
  module = AnsibleModule(
        argument_spec = dict(
            admin_url=dict(required=True, type='str'),
            name=dict(required=False, type='str'),
            ssl_certificate_id=dict(required=False, type='str'),                        
            state=dict(required=False, type='str', default='list', choices=['present', 'absent', 'list', 'info'])
        ),
        required_if=[
                      ('state', 'present', ['admin_url', 'name', 'ssl_certificate_id'])
                    ]
    )

  helper = ModuleHelper()
  admin_url, data, state = helper.param_discovery(module)

  try:
    api = API(admin_url)
    
    if state == "present":
       if 'id 'not in data:        
          response = api.add(**data)
       else:        
          response = api.update(**data)
       if_failed(module, response)

    if state == "absent":     
       response = api.delete(**data)     

    if state == "list":
       response = api.list()

    if state == "info":
       response = api.info_certificate(data.get('name'))
     
    has_changed, meta = helper.get_response(response, state)
    module.exit_json(changed=has_changed, meta=meta)

  except requests.exceptions.ConnectionError:
    module.fail_json(msg="Can't connect to Kong admin port")

from ansible.module_utils.basic import *
from ansible.module_utils.urls import *
from pprint import pprint
import json, requests

global admin_info

if __name__ == '__main__':
    main()
