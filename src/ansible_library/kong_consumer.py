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
    - Manage Kong consumers in their main CRUD operations. See U(https://getkong.org/docs/0.10.x/admin-api/) for details.
author: "Albert Monfa (@albertmonfa)"
options:
  admin_url:
    description:
      - Kong comes with an internal RESTful Admin API for administration purposes. Requests to the Admin API can be sent to any node in the cluster, and Kong will keep the configuration consistent across all nodes.
      - 8001 is the default port on which the Admin API listens.
      - 8444 is the default port for HTTPS traffic to the Admin API.
    required: true
  username:
    description:
      - The unique username of the consumer. You must send either this field or custom_id with the request.
  custom_id:
    description:
      - Field for storing an existing unique ID for the consumer - useful for mapping Kong with users in your existing database. You must send either this field or username with the request.
  state:
    description:
      - Create or delete Kong consumer, also we can list all consumers in Kong or get info about one of them. 
    choices: [ 'present', 'absent', 'list', 'info' ]
notes:
  - The Kong Consumer module always returns changed state because the Admin API does not difference between a consumer changed or unchanged and always return an 200 HTTP code. 
'''

EXAMPLES = '''
    # Create Consumer
    - kong_consumer:
        admin_url: http://localhost:8001
        username: 'akita'
        state: 'present'

    # Create Consumer
    - kong_consumer:
        admin_url: http://localhost:8001
        username: 'alaskan'
        custom_id: 'ABCD123-987C'
        state: 'present'

    # Update Consumer
    - kong_consumer:
        admin_url: http://localhost:8001
        username: 'alaskan'
        new_custom_id: '12345'
        state: 'present'

    # List all Consumers
    - kong_consumer:
       admin_url: http://localhost:8001

    # Info about one Consumer
    - kong_consumer:
        admin_url: http://localhost:8001
        username: 'alaskan'
        state: 'info'

    # Delete one Consumer
    - kong_consumer:
        admin_url: http://localhost:8001
        username: 'akita'
        state: 'absent'

    # Delete one Consumer
    - kong_consumer:
        admin_url: http://localhost:8001
        username: 'alaskan'
        state: 'absent'
'''

RETURN = '''
meta:
    description: The Kong Consumer payload.
    type: list
    sample: {
        "created_at": 1493565965000, 
        "custom_id": "12345", 
        "id": "331bd79f-c354-4f6a-87ac-1a5c3c6c93f1", 
        "username": "alaskan"
    }
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

    def _exists(self, name, consumer_list):        
        for consumer in consumer_list:
            if name == consumer.get("username", None):
               return True 
        return False

    def info(self):
        url = self.__url("/")
        response = requests.get(url)
        return response

    def list(self):
        url = self.__url("/consumers/")
        return requests.get(url)

    def add(self, **data):        
        method = "post"        
        url = self.__url("/consumers/")
        return getattr(requests, method)(url, data)

    def update(self, **data):        
        method = "patch"        
        url = self.__url("/consumers/")
        consumer_username = data.get('username')
        if 'new_custom_id' in data:
           data['custom_id'] = data['new_custom_id']
           del data['new_custom_id']
        if 'new_username' in data:
           data['username'] = data['new_username']
           del data['new_username']
        url = "{}{}" . format (url, consumer_username)
        return getattr(requests, method)(url, data)
        
    def delete(self, **data):        
        url = self.__url("/consumers/")
        consumer_username = data.get('username')
        url = "{}{}" . format (url, consumer_username)
        return requests.delete(url)        

    def info_consumer(self, name, consumer_list):
        for consumer in consumer_list:
            if name == consumer.get("username", None):
               return consumer

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

        return (has_changed, meta)


def if_failed(module, response):
    if int(response.status_code) > 399:
       module.fail_json(msg=response.json())

def main():
  module = AnsibleModule(
        argument_spec = dict(
            admin_url=dict(required=True, type='str'),
            username=dict(required=False, type='str'),
            custom_id=dict(required=False, type='str'),
            new_username=dict(required=False, type='str'),
            new_custom_id=dict(required=False, type='str'),
            state=dict(required=False, type='str', default='list', choices=['present', 'absent', 'list', 'info'])
        ),
        required_if=[
                      ('state', 'present', ['admin_url', 'username']),
                      ('state', 'info', ['username'])
                    ]
    )

  helper = ModuleHelper()
  admin_url, data, state = helper.param_discovery(module)

  try:
    api = API(admin_url)
    admin_info = api.info().json()
    consumer_list = api.list().json().get('data', [])

    if state == "present":
       if not api._exists(data.get('username'), consumer_list):        
          response = api.add(**data)
       else:        
          response = api.update(**data)
       if_failed(module, response)

    if state == "absent":
       if api._exists(data.get('username'), consumer_list):
          response = api.delete(**data)
       else:
          module.fail_json(msg='error: Consumer {} Not found! Deletion failed.' . format (data.get("username")))
       if_failed(module, response)

    if state == "list":
       response = api.list()

    if state == "info":
       response = api.info_consumer(data.get('username'), consumer_list)
  
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
