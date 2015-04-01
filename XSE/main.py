import os
import datetime

from cement.core import foundation, controller, exc, handler

from XSE.server import serve_forever, shutdown
from XSE.database import open_database, create_session_factory, Base, Console
from XSE import token


class XSEDBMixin(object):
    def _setup(self, app_obj):
        super(XSEDBMixin, self)._setup(app_obj)
        engine = open_database('xse.db')
        self.db = create_session_factory(engine)()


class XSEBaseController(controller.CementBaseController):
    class Meta:
        label = 'base'
        description = 'XSE'
        arguments = [
            (['--today'], dict(help='Show only currently active consoles', action='store_true')),
            (['--not-today'], dict(help='Hide currently active consoles', action='store_true')),
            (['--expired'], dict(help='Show only expired consoles', action='store_true')),
            (['--not-expired'], dict(help='Hide expired consoles', action='store_true')),
            (['--life'], dict(help='Show only lifetime consoles', action='store_true')),
            (['--not-life'], dict(help='Hide lifetime consoles', action='store_true')),
            (['--enabled'], dict(help='Show only enabled consoles', action='store_true')),
            (['--disabled'], dict(help='Show only disabled consoles', action='store_true')),
            (['--bypassed'], dict(help='Show only bypassed consoles', action='store_true')),
            (['--not-bypassed'], dict(help='Hide bypassed consoles', action='store_true'))
        ]

    @controller.expose(hide=True)
    def default(self):
        print('go away')

    @controller.expose(help='Run the server')
    def runserver(self):
        try:
            print('XSE Server Starting...')
            serve_forever()
        except exc.CaughtSignal as ex:
            shutdown()
            if ex.signum != 2:
                raise ex
            print('XSE Server Terminating...')

    @controller.expose(help='Create the database')
    def syncdb(self):
        print('Creating database...')
        engine = open_database('xse.db')
        Base.metadata.drop_all(engine)
        Base.metadata.create_all(engine)

    @controller.expose(help='Show stats')
    def stats(self):
        engine = open_database('xse.db')
        Session = create_session_factory(engine)

        now = datetime.datetime.now()
        before = now - datetime.timedelta(hours=24)

        print 'Last 24 hours:\t', Session().query(Console).filter(Console.last_connect.between(before, now)).count()
        before = now - datetime.timedelta(minutes=6)
        print 'Currently On:\t', Session().query(Console).filter(Console.last_connect.between(before, now)).count()
        print 'Total KV\'s:\t', Session().query(Console).count()

    @controller.expose(help='Export key vaults')
    def export(self):
        engine = open_database('xse.db')
        Session = create_session_factory(engine)

        os.mkdir('kvexport')

        for console in Session().query(Console).yield_per(5):
            if not console.key_vault: continue
            if console.last_connect < (datetime.datetime.now() - datetime.timedelta(days=1)): continue

            dir = os.path.join('kvexport', console.cpu_key)
            os.makedirs(dir)

            kvfile = open(os.path.join(dir, 'kv.bin'), 'wb')
            kvfile.write(console.key_vault)
            kvfile.flush()
            kvfile.close()

            cpufile = open(os.path.join(dir, 'cpukey.txt'), 'wb')
            cpufile.write(console.cpu_key + '\n')
            cpufile.flush()
            cpufile.close()

    @controller.expose(help='list all consoles')
    def list(self):
        engine = open_database('xse.db')
        Session = create_session_factory(engine)

        n = datetime.datetime.now()

        filters = []

        if self.pargs.today:
            filters.append(Console.day_expires > n)
        elif self.pargs.not_today:
            filters.append(Console.day_expires < n)

        if self.pargs.expired:
            filters.append(Console.days < 1)
            filters.append(Console.day_expires < n)
        elif self.pargs.not_expired:
            filters.append(Console.days >= 1)

        if self.pargs.life:
            filters.append(Console.days > 100)
        elif self.pargs.not_life:
            filters.append(Console.days <= 100)

        if self.pargs.enabled:
            filters.append(Console.enabled == True)
        elif self.pargs.disabled:
            filters.append(Console.enabled == False)

        if self.pargs.bypassed:
            filters.append(Console.bypass == True)
        elif self.pargs.not_bypassed:
            filters.append(Console.bypass == False)

        for console in Session().query(Console).filter(*filters).order_by(Console.last_connect.desc()).yield_per(5):
            days = 'LIFE' if (console.days > 100) else console.days
            expired = 'EX' if (console.days < 1 and console.day_expires < n) else '  '
            print '{0.cpu_key} | {0.day_expires} | {2} | {0.payment} | {0.enabled} | {0.last_connect} | {1} | {0.last_ip} | {0.name}'.format(console, expired, days)

    @controller.expose(help='reset all days')
    def reset_all(self):
        engine = open_database('xse.db')
        Session = create_session_factory(engine)
        s = Session()

        n = datetime.datetime.now()

        for console in s.query(Console).yield_per(5):
            if console.day_expires > n:
                print 'resetting console {0}'.format(console.cpu_key)
                console.day_expires = n
                console.days += 1

        s.commit()


class XSETokenController(controller.CementBaseController):
    class Meta:
        label = 'token'
        description = 'token management'
        arguments = [
            (['token'], dict(nargs='?', help='Token to act on')),
            (['-n', '--number'], dict(help='Number of tokens to generate', type=int)),
            (['-d', '--days'], dict(help='Number of days each token can be redeemed for', type=int)),
        ]

    @controller.expose(help='Generate tokens')
    def generate(self):
        if not self.pargs.number:
            print 'you must specify a number of tokens to generate'
            return
        if not self.pargs.days:
            print 'you must specify how many days each token is worth'
            return

        tokens = token.generate(self.pargs.number, self.pargs.days)
        for t in tokens:
            print t

    @controller.expose(help='check a token')
    def check(self):
        days = token.check(self.pargs.token)
        if days <= 0:
            print 'token is not valid, possibly redeemed?'
            return
        print 'token is valid for {0} days'.format(days)

    @controller.expose(help='delete a token')
    def delete(self):
        days = token.use(self.pargs.token)
        if days <= 0:
            print 'token is not valid, possibly redeemed?'
            return
        print 'token was for {0} days. deleted'.format(days)
        

class XSEConsoleController(XSEDBMixin, controller.CementBaseController):
    class Meta:
        label = 'console'
        description = 'console management commands'
        arguments = [
            (['cpu_key'], dict(help='CPU key of the console to add')),
            (['--name'], dict(help='Name of the console to add')),
            (['--days'], dict(help='Number of days to add to console', type=int)),
            (['--payment'], dict(help='Method of payment used, ex: paypal email')),
            (['--enable'], dict(help='Enable the console', action='store_true')),
            (['--disable'], dict(help='Disable the console', action='store_true')),
            (['--bypass'], dict(help='Enable bypass on user', action='store_true')),
            (['--disable-bypass'], dict(help='Disable bypass on user', action='store_true'))
        ]

    @controller.expose(help='Show console info')
    def info(self):
        user = self.db.query(Console).filter_by(cpu_key=self.pargs.cpu_key.lower()).first()
        if not user:
            print 'not found'
            return

        time_left = datetime.timedelta()
        if user.day_expires > datetime.datetime.now():
            time_left += user.day_expires - datetime.datetime.now()
        time_left += datetime.timedelta(days=user.days)

        print 'name:\t', user.name
        print 'enabled:\t', user.enabled
        print 'payment:\t', user.payment
        print 'bypass:\t', user.bypass
        print 'days:\t', user.days
        print 'day_expires:\t', user.day_expires
        print 'last_ip:\t', user.last_ip
        print 'last_connect:\t', user.last_connect
        print 'time_left:\t', datetime.timedelta(seconds=int(time_left.total_seconds()))

    @controller.expose(help='Modify console info')
    def mod(self):
        user = self.db.query(Console).filter_by(cpu_key=self.pargs.cpu_key.lower()).first()
        if not user:
            print 'not found'
            return

        if self.pargs.enable and self.pargs.disable:
            print 'specify only enable or disable'
            return
        if self.pargs.bypass and self.pargs.disable_bypass:
            print 'specify only bypass or disable-bypass'
            return

        if not self.pargs.days is None: user.days = self.pargs.days
        if not self.pargs.name is None: user.name = self.pargs.name
        if not self.pargs.payment is None: user.payment = self.pargs.payment
        if self.pargs.enable: user.enabled = True
        if self.pargs.disable: user.enabled = False
        if self.pargs.bypass: user.bypass = True
        if self.pargs.disable_bypass: user.bypass = False

        self.db.commit()
        print 'user updated'


    @controller.expose(help='Add a console')
    def add(self):
        if len(self.pargs.cpu_key) != 32:
            print 'invalid cpu key'
            return

        user = self.db.query(Console).filter_by(cpu_key=self.pargs.cpu_key.lower()).first()

        if user:
            print 'user exists'
            return

        if not self.pargs.name:
            print 'you must specify a console name with --name'
            return

        if not self.pargs.payment:
            print 'you must specify a payment method with --payment'
            return

        if not self.pargs.days:
            print 'be sure to add days with add-days'
            self.pargs.days = 0

        user = Console(self.pargs.cpu_key.lower())
        
        user.enabled = True
        user.days = self.pargs.days
        user.day_expires = datetime.datetime.now()
        user.name = self.pargs.name
        user.payment = self.pargs.payment
        user.bypass = self.pargs.bypass

        self.db.add(user)
        self.db.commit()

        print('Console added')

    @controller.expose(help='delete a user')
    def delete(self):
        user = self.db.query(Console).filter_by(cpu_key=self.pargs.cpu_key.lower()).first()

        if not user:
            print 'user does not exist'
            return

        self.db.delete(user)
        self.db.commit()

        print 'user deleted'

    @controller.expose(help='Add days to a console')
    def add_days(self):
        user = self.db.query(Console).filter_by(cpu_key=self.pargs.cpu_key.lower()).first()

        if not user:
            print 'user does not exist'
            return

        if not self.pargs.days:
            print 'you must specify a number of days with --days'
            return

        user.days += self.pargs.days

        if self.pargs.bypass: user.bypass = True
        if self.pargs.disable_bypass: user.bypass = False

        if self.pargs.payment:
            user.payment = self.pargs.payment

        self.db.commit()

        print 'days added'

    @controller.expose(help='reset the current day')
    def reset_day(self):
        user = self.db.query(Console).filter_by(cpu_key=self.pargs.cpu_key.lower()).first()

        if not user:
            print 'user does not exist'
            return

        user.days += 1
        user.day_expires = datetime.datetime.now()

        self.db.commit()

        print 'day reset'


def main():
    app = foundation.CementApp('XSE', base_controller=XSEBaseController)

    try:
        handler.register(XSEConsoleController)
        handler.register(XSETokenController)
        app.setup()
        app.run()
    finally:
        app.close()

if __name__ == '__main__':
    main()
