#!/usr/bin/python

from urllib2 import urlopen
from flask import Flask, request
from itertools import chain
app = Flask(__name__)

@app.route('/')
def hello_world():
    return 'Hello World!'

#IPN_URLSTRING = 'https://www.sandbox.paypal.com/cgi-bin/webscr'
IPN_URLSTRING = 'https://www.paypal.com/cgi-bin/webscr'
IPN_VERIFY_EXTRA_PARAMS = (('cmd', '_notify-validate'),)

log = open('ipn.log', 'a')
 
def ordered_storage(f):
    import werkzeug.datastructures
    import flask
    def decorator(*args, **kwargs):
        flask.request.parameter_storage_class = werkzeug.datastructures.ImmutableOrderedMultiDict
        return f(*args, **kwargs)
    return decorator

@app.route('/paypal', methods=['POST'])
@ordered_storage
def paypal_webhook():
    global log
    #probably should have a sanity check here on the size of the form data to guard against DoS attacks
    verify_args = chain(request.form.iteritems(), IPN_VERIFY_EXTRA_PARAMS)
    verify_string = '&'.join(('%s=%s' % (param, value) for param, value in verify_args))
    #req = Request(verify_string)
    print(verify_string)
    response = urlopen(IPN_URLSTRING, data=verify_string)
    status = response.read()
    print(status)
    if status == 'VERIFIED':
        # Do something with the verified transaction details.
        item_name = request.form.get('item_name')
        item_number = request.form.get('item_number')
        payment_status = request.form.get('payment_status')
        payment_amount = request.form.get('mc_gross')
        payment_currency = request.form.get('mc_currency')
        txn_id = request.form.get('txn_id')
        receiver_email = request.form.get('receiver_email')
        payer_email = request.form.get('payer_email')

        line = 'from {payer_email} to {receiver_email}. {mc_gross} {mc_currency} {payment_status}. TX: {txn_id}'.format(**request.form.to_dict())
        print(line)
        log.write(line + '\n')
        for key,val in request.form.to_dict().items():
            log.write('\t{0}:\t{1}\n'.format(key,val))
        log.flush()

    return 'VERIFIED'


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8000, debug=True)
