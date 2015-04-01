import json

def get_config():
    return json.loads(open('config.json', 'r').read())
