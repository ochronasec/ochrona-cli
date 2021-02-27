import requests

from ochrona.exceptions import OchronaAPIException


def refresh(api_key):
    payload = f"grant_type=refresh_token&client_id=2asm97h0jq5299qgpeeom91iod&refresh_token={api_key}"
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    url = "https://authn.ochrona.dev/oauth2/token"
    response = requests.post(url=url, headers=headers, data=payload)
    tokens = response.json()
    if "id_token" in tokens:
        return tokens.get("id_token")
    else:
        raise OchronaAPIException("Authorization Failed")
