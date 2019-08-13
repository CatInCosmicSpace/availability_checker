# -*- coding: utf-8 -*-
# -*- coding: utf-8 -*-
import threading
import time

import requests


class SkypeBotApi:
    def __init__(self, client_id, client_secret):
        def token_func():
            global token

            if not client_id:
                raise ValueError('The "client_id" is empty. Please add a valid client_id.')
            elif not client_secret:
                raise ValueError('The "client_secret" is empty. Please add a valid client_secret.')
            else:
                token = self.get_token(client_id, client_secret)

        def execute():
            while True:
                token_func()
                time.sleep(3000)

        self.t = threading.Thread(target=execute)
        self.t.daemon = True
        self.t.start()

    def send_media(self, service, sender, type, url, text):
        return send_media(token, service, sender, type, url, text)

    @staticmethod
    def get_token(client_id, client_secret):
        payload = "grant_type=client_credentials&client_id=" + client_id + "&client_secret=" + client_secret \
                  + "&scope=https%3A%2F%2Fapi.botframework.com%2F.default"

        response = requests.post(
            "https://login.microsoftonline.com/botframework.com/oauth2/v2.0/token?client_id=" + client_id
            + "&client_secret=" + client_secret
            + "&grant_type=client_credentials&scope=https%3A%2F%2Fgraph.microsoft.com%2F.default",
            data=payload, headers={"Content-Type": "application/x-www-form-urlencoded"})
        data = response.json()
        return data["access_token"]

import requests
import sys
from importlib import reload

reload(sys)


# url as base64
def send_media(token, service, sender, type, url, text=""):
    try:
        payload = {
            "type": "message",
            "attachments": [{
                "contentType": type,
                "contentUrl": url
            }],
            "text": text
        }

        r = requests.post(service + '/v3/conversations/' + sender + '/activities/',
                          headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"},
                          json=payload)
        print(r)
    except Exception as e:
        print(e)
        pass
