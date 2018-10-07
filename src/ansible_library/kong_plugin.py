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
module: kong_plugin
short_description: Manage plugins in Kong
description:
    - Manage Kong plugins in their main CRUD operations. See U(https://getkong.org/docs/0.10.x/admin-api/) for details.
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
      - The name of the Plugin that's going to be added.
    choices: [ 'jwt', 'acl',  'cors', 'oauth2', 'tcp-log', 'udp-log', 'file-log','http-log','key-auth','hmac-auth','basic-auth','ip-restriction','request-transformer','response-transformer','request-size-limiting','rate-limiting','response-ratelimiting','aws-lambda','bot-detection','correlation-id','datadog','galileo','ldap-auth','loggly','runscope','statsd','syslog' ]
  consumer_name:
    description:
      - The unique username of the consumer. You must send either this field or custom_id with the request.
  api_name:
    description:
      - The API name
  config:
    description:
      - The configuration properties for the Plugin which can be found on the plugins documentation page in the Plugin Gallery.
  state:
    description:
      - Create or delete Kong plugin, also we can list all plugins in Kong or get info about one of them.
    choices: [ 'present', 'absent', 'list', 'info' ]
notes:
  - The Kong Plugin module always returns changed state because the Admin API does not difference between a plugin changed or unchanged and always return an 200 HTTP code.
'''

EXAMPLES = '''

    # Create API
    - kong_api:
        admin_url: http://localhost:8001
        name: 'akita'
        request_path: '/akita'
        upstream_url: 'http://akita.domain.int/'
        state: 'present'

    # Create Consumer
    - kong_consumer:
        admin_url: http://localhost:8001
        username: 'akita'
        state: 'present'

    # Associate Plugin
    - kong_plugin:
        admin_url: http://localhost:8001
        name: 'rate-limiting'
        config: {
                  minute: 10
                }
        state: 'present'


    # Associate Plugin
    - kong_plugin:
        admin_url: http://localhost:8001
        name: 'basic-auth'
        config: {
                  "hide_credentials": true
                }
        state: 'present'

    # Associate Plugin
    - kong_plugin:
        admin_url: http://localhost:8001
        name: 'oauth2'
        config: {
                  "enable_client_credentials": true,
                  "scopes": "web"
                }
        state: 'present'

    # Associate Consumer Plugin
    - kong_plugin:
        admin_url: http://localhost:8001
        name: 'basic-auth'
        consumer_name: 'akita'
        config: {
                  "username": "Nikita",
                  "password": "pakita"
                }
        state: 'present'
      register: result

    # Modify Consumer Plugin
    - kong_plugin:
        admin_url: http://localhost:8001
        name: 'basic-auth'
        consumer_name: 'akita'
        config: {
                        "id": "{{ result.meta.id }}",
                  "username": "Nikita",
                  "password": "PassChanged"
                }
        state: 'present'

    # List Consumer Plugin
    - kong_plugin:
        admin_url: http://localhost:8001
        name: 'basic-auth'
        consumer_name: 'akita'
        config: {
                         "id": "{{ result.meta.id }}",
                  "username": "Nikita",
                }
        state: 'list'

    # Delete Consumer Plugin
    - kong_plugin:
        admin_url: http://localhost:8001
        name: 'basic-auth'
        consumer_name: 'akita'
        config: {
                        "id": "{{ result.meta.id }}"
                }
        state: 'absent'

    # List Consumer Plugin
    - kong_plugin:
        admin_url: http://localhost:8001
        name: 'basic-auth'
        consumer_name: 'akita'
        config: {
                         "id": "{{ result.meta.id }}",
                  "username": "Nikita",
                }
        state: 'list'

    # Associate Consumer Plugin
    - kong_plugin:
        admin_url: http://localhost:8001
        name: 'oauth2'
        consumer_name: 'akita'
        config: {
                  "name": "NikitaAPP",
                  "redirect_uri": "http://zinio.com/login"
                }
        state: 'present'
      register: result

    # Modify Consumer Plugin
    - kong_plugin:
        admin_url: http://localhost:8001
        name: 'oauth2'
        consumer_name: 'akita'
        config: {
                        "id": "{{ result.meta.id }}",
                      "name": "NikitaAPP",
                  "redirect_uri": "https://zinio.com/login"
                }
        state: 'present'

    # List Consumer Plugin
    - kong_plugin:
        admin_url: http://localhost:8001
        name: 'oauth2'
        consumer_name: 'akita'
        config: {
                         "id": "{{ result.meta.id }}"
                }
        state: 'list'

    # Delete Consumer Plugin
    - kong_plugin:
        admin_url: http://localhost:8001
        name: 'oauth2'
        consumer_name: 'akita'
        config: {
                        "id": "{{ result.meta.id }}"
                }
        state: 'absent'

    # List Consumer Plugin
    - kong_plugin:
        admin_url: http://localhost:8001
        name: 'oauth2'
        consumer_name: 'akita'
        config: {
                         "id": "{{ result.meta.id }}"
                }
        state: 'list'

    # Associate Plugin
    - kong_plugin:
        admin_url: http://localhost:8001
        name: 'cors'
        api_name: 'akita'
        config: {
                  methods: 'GET'
                }
        state: 'present'

    # List Plugin
    - kong_plugin:
        admin_url: http://localhost:8001
        state: 'list'

    # DeAssociate Plugin
    - kong_plugin:
        admin_url: http://localhost:8001
        name: 'basic-auth'
        config: {
                  "hide_credentials": true
                }
        state: 'absent'

    # Associate Plugin
    - kong_plugin:
        admin_url: http://localhost:8001
        name: 'oauth2'
        config: {
                  "enable_client_credentials": true,
                  "scopes": "web"
                }
        state: 'absent'

    # DeAssociate Plugin
    - kong_plugin:
        admin_url: http://localhost:8001
        name: 'rate-limiting'
        config: {
                  minute: 10
                }
        state: 'absent'

    # DeAssociate Plugin
    - kong_plugin:
        admin_url: http://localhost:8001
        name: 'cors'
        api_name: 'akita'
        config: {
                  methods: 'GET'
                }
        state: 'absent'

    # Delete API
    - kong_api:
        admin_url: http://localhost:8001
        name: 'akita'
        request_path: '/akita'
        upstream_url: 'http://akita.domain.int/'
        state: 'absent'

    # Delete Consumer
    - kong_consumer:
        admin_url: http://localhost:8001
        username: 'akita'
        state: 'absent'
'''

RETURN = '''
meta:
    description: The Kong Plugin payload.
    type: list
    sample:
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

    def __is_type_consumer( self, type='common', **data ):
        if type is not 'common':
           if 'id' not in data.get('config'):
              return False

        if data.get('name')   in consumers_plugins  and \
           'consumer_name'    in data               and \
           'consumer_api' not in data:
             return True
        return False

    def _query(self, **data ):
        if self.__is_type_consumer( **data ):
           return data

        query = {
                  'name' : data.get('name',[]),
                }

        if 'consumer_name' in data:
           consumer_id = {
                           'consumer_id' : self._get_consumer_id(data.get('consumer_name',[]))
                         }
           query.update(consumer_id)

        if 'api_name' in data:
           api_id = {
                      'api_id' : self._get_api_id(data.get('api_name',[]))
                    }
           query.update(api_id)
        return query

    def _exists(self, module, **data):
        if self.__is_type_consumer( type='id', **data ):
           parameters = dict(yaml.load(data.get('config')))
           url = self.__url("/consumers/")
           #url = "{}{}/{}/{}" . format ( url,
           url = "{}{}/{}" . format ( url,
                                         self._get_consumer_id(data.get('consumer_name')),
                                         data.get('name')
                                        )
           response = requests.get(url)
           code = int(response.status_code)
           if code in [200]:
              return True
           else:
              return False
        else:
             query = self._query( **data )
             response = self.list( module, **query )
             total = int(response.json()['total'])
        if total > 0:
           return True
        else:
           return False

    def _get_plugin_id(self, module, **data):
        query = self._query( **data )
        response = self.list( module, **query )
        total = int(response.json()['total'])
        if total > 1:
           for plugin in response.json()['data']:
               if   'consumer_name' not in data   and \
                    'api_name'      not in data   and \
                    'consumer_id'   not in plugin and \
                    'api_id'        not in plugin:
                       return plugin.get('id')
               elif 'consumer_name'     in data   and \
                    'api_name'      not in data   and \
                    'consumer_id'       in plugin and \
                    'api_id'        not in plugin:
                       return plugin.get('id')
               elif 'consumer_name' not in data   and \
                    'api_name'          in data   and \
                    'consumer_id'   not in plugin and \
                    'api_id'            in plugin:
                       return plugin.get('id')
               else:
                    msg = "More than 1 element match: " + str(response.json()['data'])
                    module.fail_json(msg=msg)
        elif total == 1:
             return response.json()['data'][0]['id']
        elif total == 0:
             module.fail_json(msg="Search failed: Plugin not located!!!")


    def _get_consumer_id(self, consumer_name):
        url = self.__url("/consumers/")
        url = "{}{}" . format (url, consumer_name)
        response = requests.get(url)
        return response.json().get('id', [])


    def _get_api_id(self, api_name):
        url = self.__url("/apis/")
        url = "{}{}" . format (url, api_name)
        response = requests.get(url)
        return response.json().get('id', [])

    def _make_config(self, **data):
        config = {}
        parameters = dict(yaml.load(data.get('config')))
        for key, value in parameters.items():
            nk = 'config.'+str(key)
            config[nk] = value
        payload = { "name": data.get('name') }
        payload.update(config)
        return payload

    def info(self):
        url = self.__url("/")
        response = requests.get(url)
        return response

    def list_apis(self):
        url = self.__url("/apis/")
        return requests.get(url)

    def list_enabled(self):
        url = self.__url("/plugins/enabled")
        response = requests.get(url)
        return response.json()

    def list(self, module, **data):
        if self.__is_type_consumer( **data ):
             url = self.__url("/consumers/")
             url = "{}{}/{}" . format ( url,
                                      self._get_consumer_id(data.get('consumer_name')),
                                      data.get('name')
                                    )
             return requests.get(url)
        url = self.__url("/plugins/")
        return requests.get(url,params=data)

    def list_per_api(self, api):
        url = self.__url("/apis/")
        url = "{}{}/{}" . format (url, api, 'plugins')
        return requests.get(url)

    def list_per_consumer(self, consumer):
        url = self.__url("/apis/")
        url = "{}{}/{}" . format (url, consumer, 'plugins')
        return requests.get(url)

    def add(self, module, **data):
        if self.__is_type_consumer( **data ):
             payload = dict(yaml.load(data.get('config')))
             payload['enabled'] = data.get('enabled')
             url = self.__url("/consumers/")
             url = "{}{}/{}" . format ( url,
                                        self._get_consumer_id(data.get('consumer_name')),
                                        data.get('name')
                                      )
             headers = {'Content-Type': 'application/x-www-form-urlencoded'}
             return getattr(requests, "put")(url, headers=headers, data=payload)

        payload = self._make_config(**data)
        payload['enabled'] = data.get('enabled')
        if 'api_name' in data:
           url = self.__url("/apis/")
           url = "{}{}/plugins/" . format (url, data.get('api_name'))
        else:
           url = self.__url("/plugins")

        if 'consumer_name' in data:
            payload['consumer_id'] = self._get_consumer_id(data.get('consumer_name'))
        return getattr(requests, "post")(url, data=payload)

    def update(self, module, **data):
        if self.__is_type_consumer( **data ):
           return self.add( module, **data )
        payload = self._make_config(**data)
        plugin_id = self._get_plugin_id( module, **data)
        payload['enabled'] = data.get('enabled')        
        url = self.__url("/plugins")
        url = "{}/{}" . format ( url, plugin_id )
        return getattr(requests, "patch")(url, payload)

    def delete(self, module, **data):
        if self.__is_type_consumer( type='id', **data ):
             parameters = dict(yaml.load(data.get('config')))
             url = self.__url("/consumers/")
             url = "{}{}/{}/{}" . format ( url,
                                      self._get_consumer_id(data.get('consumer_name')),
                                      data.get('name'),
                                      parameters['id']
                                    )
        else:
           plugin_id = self._get_plugin_id( module, **data)
           url = self.__url("/plugins")
           url = "{}/{}" . format ( url, plugin_id )
        return requests.delete(url)

    def info_plugin(self, plugin):
        url = self.__url("/plugins/")
        id = data.get('id')
        url = "{}{}" . format (url, id)
        return requests.delete(url)

    def schema_plugin(self, name):
        url = self.__url("/plugins/schema/")
        url = "{}{}" . format (url, name)
        return requests.delete(url)

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
       msg="Error in response, CODE: "+ str(response.status_code) + " MSG: " + str(response.text)
       module.fail_json(msg=msg)

def main():
  module = AnsibleModule(
        argument_spec = dict(
            admin_url=dict(required=True, type='str'),
            name=dict(required=False, type='str', choices= [ 'jwt',
                                                             'acl',
                                                             'cors',
                                                             'oauth2',
                                                             'tcp-log',
                                                             'udp-log',
                                                             'file-log',
                                                             'http-log',
                                                             'key-auth',
                                                             'hmac-auth',
                                                             'basic-auth',
                                                             'ip-restriction',
                                                             'request-transformer',
                                                             'response-transformer',
                                                             'request-size-limiting',
                                                             'rate-limiting',
                                                             'response-ratelimiting',
                                                             'aws-lambda',
                                                             'bot-detection',
                                                             'correlation-id',
                                                             'datadog',
                                                             'galileo',
                                                             'ldap-auth',
                                                             'loggly',
                                                             'runscope',
                                                             'statsd',
                                                             'syslog'
                                                           ]),
            consumer_name=dict(required=False, type='str'),
            api_name=dict(required=False, type='str'),
            enabled=dict(required=False, default='true', type='str'),
            config=dict(required=False, type='str'),
            state=dict( required=False, type='str', default='list',
                        choices=['present', 'absent', 'list', 'info', 'enabled', 'schema']
                      )
        ),
        required_if=[
                      ('state', 'present', ['admin_url', 'name']),
                      ('state', 'schema', ['admin_url', 'name']),
                      ('state', 'info', ['name','api_name'])
                    ]
    )

  helper = ModuleHelper()
  admin_url, data, state = helper.param_discovery(module)

  try:
    api = API(admin_url)
    admin_info = api.info().json()

    if state == "present":
       if not api._exists( module, **data ):
          response = api.add( module, **data )
       else:
          response = api.update( module, **data )
       if_failed(module, response)

    if state == "absent":
       if api._exists( module, **data ):
          response = api.delete( module, **data )
       else:
          module.exit_json(changed=False, meta='Plugin do not exist.')
       if_failed(module, response)

    if state == "list":
       query = api._query( **data )
       response = api.list( module, **query )

    if state == "info":
       response = api.info_plugin(data.get('name'), plugin_list)

    if state == "enabled":
       response = api.list_enabled()

    if state == "schema":
       response = api.schema_plugin(data.get('name'))

    has_changed, meta = helper.get_response(response, state)
    module.exit_json(changed=has_changed, meta=meta)

  except requests.exceptions.ConnectionError:
    module.fail_json(msg="Can't connect to Kong admin port")


from ansible.module_utils.basic import *
from ansible.module_utils.urls import *
from pprint import pprint
import json, requests, yaml

global admin_info, consumers_plugins

consumers_plugins = [
                      'basic-auth',
                      'key-auth',
                      'oauth2',
                      'hmac-auth',
                      'jwt',
                      'acl'
                    ]

if __name__ == '__main__':
    main()
