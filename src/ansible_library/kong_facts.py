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
    - Get details and status from a Kong node. See U(https://getkong.org/docs/0.10.x/admin-api/) for details.
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
    
    def node_details(self):
        url = self.__url("/")
        response = requests.get(url)
        return response.json()

    def node_status(self):
        url = self.__url("/status")
        response = requests.get(url)
        return response.json()

class ModuleHelper:

    def param_discovery(self, module):
        
        admin_url = module.params['admin_url']        
        return admin_url

    def get_response( self, response ): 
        has_changed = True
        meta = response
       
        return (has_changed, meta)


def main():
  module = AnsibleModule(
        argument_spec = dict(
            admin_url=dict(required=True, type='str')            
        ),        
    )

  helper = ModuleHelper()
  admin_url = helper.param_discovery(module)

  try:
    api = API(admin_url)
    
    response = {
                 "info" : [],
                 "status" : [],
               }

    response['info'] = api.node_details()
    response['status'] = api.node_status()
  
    has_changed, meta = helper.get_response(response)
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
