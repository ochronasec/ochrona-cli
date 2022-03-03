from ast import Delete
from requests import get, post, put, delete

resp = get('https://github.com', verify=False)

resp = put('https://github.com', data ={'key':'value'}, verify=False)

resp = post('https://github.com', data ={'key':'value'}, verify=False)

resp = delete('https://github.com', verify=False)