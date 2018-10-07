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
module: kong_api
short_description: Manage APIs in Kong
description:
    - Manage Kong APIs in their main CRUD operations. See U(https://getkong.org/docs/0.10.x/admin-api/) for details.
author: "Albert Monfa (@albertmonfa)"
options:
  admin_url:
    description:
      - Kong comes with an internal RESTful Admin API for administration purposes. Requests to the Admin API can be sent to any node in the cluster, and Kong will keep the configuration consistent across all nodes.
      - 8001 is the default port on which the Admin API listens.
      - 8444 is the default port for HTTPS traffic to the Admin API.
    required: true
  name:
    description:
      - The API name.
  hosts:
    description:
      - A comma-separated list of domain names that point to your API. For example: example.com. At least one of hosts, uris, or methods should be specified.
    aliases: ['request_host']
  uris:
    description:
      - A comma-separated list of URIs prefixes that point to your API. For example: /my-path. At least one of hosts, uris, or methods should be specified. 
    aliases: ['request_path']
  methods:
    description:
      - A comma-separated list of HTTP methods that point to your API. For example: GET,POST. At least one of hosts, uris, or methods should be specified.
  upstream_url:
    description:
      - The base target URL that points to your API server. This URL will be used for proxying requests. For example: https://example.com.
  strip_uri:
    description:
      - When matching an API via one of the uris prefixes, strip that matching prefix from the upstream URI to be requested. Default: true
    type: bool
  preserve_host:
    description:
      - When matching an API via one of the hosts domain names, make sure the request Host header is forwarded to the upstream service. By default, this is false, and the upstream Host header will be extracted from the configured upstream_url.
    type: bool
  retries:
    description:
      - The number of retries to execute upon failure to proxy. The default is 5.
  upstream_connect_timeout:
    description:
      - The timeout in milliseconds for establishing a connection to your upstream service. Defaults to 60000.
  upstream_send_timeout:
    description:
      - The timeout in milliseconds between two successive write operations for transmitting a request to your upstream service Defaults to 60000.
  upstream_read_timeout:
    description:
      - The timeout in milliseconds between two successive read operations for transmitting a request to your upstream service Defaults to 60000.
  https_only:
    description:
      - To be enabled if you wish to only serve an API through HTTPS, on the appropriate port (8443 by default). Default: false.
    type: bool
  http_if_terminated:
    description:
      - Consider the X-Forwarded-Proto header when enforcing HTTPS only traffic. Default: true.
    type: bool
  state:
    description:
      - Create or delete Kong API, also we can list all APIS in Kong or get info about one of them. 
    choices: [ 'present', 'absent', 'list', 'info' ]
notes:
  - The Kong API module always returns changed state because the Admin API does not difference between a API changed or unchanged and always return an 200 HTTP code. 
'''

EXAMPLES = '''
# Create API
- kong_api:
    admin_url: http://localhost:8001
    name: 'akita'
    request_path: '/akita'
    upstream_url: 'http://akita.domain.int/'
    state: 'present'

# Create API
- kong_api:
    admin_url: http://localhost:8001
    name: 'alaskan'
    request_path: '/alaskan'
    upstream_url: 'http://all.domain.int/'
    state: 'present'

# Update API
- kong_api:
    admin_url: http://localhost:8001
    name: 'alaskan'
    request_path: '/alaskan'
    upstream_url: 'http://all.domain.int/alaskan'
    state: 'present'

# List all APIs
- kong_api:
   admin_url: http://localhost:8001

# Info about one API
- kong_api:
    admin_url: http://localhost:8001
    name: 'alaskan'
    state: 'info'

# Delete one API
- kong_api:
    admin_url: http://localhost:8001
    name: 'akita'
    state: 'absent'

# Delete one API
- kong_api:
    admin_url: http://localhost:8001
    name: 'alaskan'
    state: 'absent'
'''

RETURN = '''
meta:
    description: The Kong API payload.
    type: list
    sample: {
        "created_at": 1493552358000, 
        "id": "e8e35e79-5b70-4924-b893-6ac3817553f9", 
        "name": "alaskan", 
        "preserve_host": false, 
        "request_path": "/alaskan", 
        "strip_request_path": false, 
        "upstream_url": "http://all.domain.int/alaskan"
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

    def _exists(self, name, api_list):        
        for api in api_list:
            if name == api.get("name", None):
               return True 
        return False

    def info(self):
        url = self.__url("/")
        response = requests.get(url)
        return response

    def list(self):
        url = self.__url("/apis/")
        return requests.get(url)

    def add(self, **data):        
        method = "post"        
        url = self.__url("/apis/")
        return getattr(requests, method)(url, data)

    def update(self, **data):        
        method = "patch"        
        url = self.__url("/apis/")
        api_name = data.get('name')
        url = "{}{}" . format (url, api_name)
        return getattr(requests, method)(url, data)
        
    def delete(self, **data):        
        url = self.__url("/apis/")
        api_name = data.get('name')
        url = "{}{}" . format (url, api_name)
        return requests.delete(url)        

    def info_api(self, name, api_list):
        for api in api_list:
            if name == api.get("name", None):
               return api

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
            hosts=dict(required=False, type='str'),
            uris=dict(required=False, type='str'),
            request_host=dict(aliases=['hosts']),
            request_path=dict(aliases=['uris']),
            methods=dict(required=False, type='str'),
            http_if_terminated=dict(required=False, type='str'),
            https_only=dict(required=False, type='bool'),
            preserve_host=dict(required=False, default=False, type='bool'),
            retries=dict(required=False, type='int'),
            strip_uri=dict(required=False, type='bool'),
            strip_request_path=dict(required=False, type='bool'),
            name=dict(required=False, type='str'),
            upstream_connect_timeout=dict(required=False, type='int'),
            upstream_read_timeout=dict(required=False, type='int'),
            upstream_send_timeout=dict(required=False, type='int'),            
            upstream_url=dict(required=False, type='str'),
            state=dict(required=False, type='str', default='list', choices=['present', 'absent', 'list', 'info'])
        ),
        required_if=[
                      ('state', 'present', ['admin_url', 'name', 'upstream_url']),
                      ('state', 'info', ['name'])
                    ]
    )

  helper = ModuleHelper()
  admin_url, data, state = helper.param_discovery(module)

  try:
    api = API(admin_url)
    admin_info = api.info().json()
    api_list = api.list().json().get('data', [])
  
    if state == "present":
       if not api._exists(data.get('name'), api_list):        
          response = api.add(**data)
       else:        
          response = api.update(**data)
       if_failed(module, response)

    if state == "absent":
       if api._exists(data.get('name'), api_list):
          response = api.delete(**data)
       else:
          module.fail_json(msg='error: API {} Not found! Deletion failed.' . format (data.get("name")))
       if_failed(module, response)

    if state == "list":
       response = api.list()

    if state == "info":
       response = api.info_api(data.get('name'), api_list)
  
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
