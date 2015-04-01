import json
import fcntl
import random
import string

def load(token_file):
    return json.loads(open(token_file, 'r').read())

def save(token_file, data):
    f = open(token_file, 'w')
    fcntl.lockf(f, fcntl.LOCK_EX)
    f.write(json.dumps(data, indent=4))
    f.flush()
    f.close()

def check(token):
    tokens = load('tokens.json')
    t = tokens.get(token, 0)
    return t

def use(token):
    tokens = load('tokens.json')
    t = tokens.get(token, 0)
    if t <= 0: return 0
    del tokens[token]
    save('tokens.json', tokens)
    return t

def generate(number, days):
    new_tokens = []
    tokens = load('tokens.json')
    for i in range(number):
        t = ''.join(random.choice('ABCDEFGHJKMNPQRSTUVWXYZabcdefghjkmnopqrstuvwxyz23456789') for x in range(12))
        new_tokens.append(t)
        tokens[t] = days
    save('tokens.json', tokens)
    return new_tokens
