# -*- coding: utf-8 -*-
import base64
import os
import sys
import traceback
import json
from importlib import reload
from PIL import Image, ImageDraw, ImageFont
from dotenv import load_dotenv
from flask import Flask, request
from apihelper import SkypeBotApi

load_dotenv()
reload(sys)

app = Flask(__name__)

APP_ID = 'bec372bc-8acd-43a8-929e-3156dfe8eb5a'
APP_SECRET = '=c2sflh_4Es3k[JP8A.XQSQ49s2nz.5E'

bot = SkypeBotApi(APP_ID, APP_SECRET)

contacts = []
if os.path.exists('contacts.json'):
    with open('contacts.json', 'r') as f:
        contacts = json.load(f)


@app.route('/report', methods=['POST'])
def report():
    try:
        addresses = request.data.decode().split('\n')
        addresses = list(filter(bool, addresses))
        print("addresses is:", addresses)
        if (len(addresses) > 0):
            img = Image.new('RGB', (500, 20 * len(addresses) - 1), color=(255, 255, 255))
            font = ImageFont.truetype("arial.ttf", 15)
            d = ImageDraw.Draw(img)
            for i in range(len(addresses)):
                d.text((10, 20 * (i)), addresses[i], fill=(0, 0, 0), font=font)
            img.save("addresses.png")
            print("image saved")
            for i in contacts:
                bot.send_media(i[2], i[1], "image/png", "data:image/png;base64," +
                               base64.b64encode(open("addresses.png", "rb").read()).decode(),
                               "Отчет о доступности ресурсов")
            return 'Data sent to all contacts successfully'
        else:
            return 'No data provided'
    except:
        return '500'


@app.route('/', methods=['POST', 'GET'])
def main():
    if request.method == 'POST':
        try:
            data = json.loads(request.data)
            if data['type'] == 'message':
                pass
            elif data['type'] == 'contactRelationUpdate':
                if data['action'] == 'add':
                    contacts.append([data['from']['name'], data['from']['id'], data["serviceUrl"]])
                    file = open('contacts.json', 'w+')
                    json.dump(contacts, file)
                    file.close()
                    pass
                else:
                    pass
            else:
                pass
        except Exception as e:
            print(traceback.format_exc())  # something went wrong
    return 'Ok'


if __name__ == '__main__':
    context = ('fullchain.pem', 'key.pem')
    app.run(host='0.0.0.0', port=8081, debug=True, ssl_context=context)
