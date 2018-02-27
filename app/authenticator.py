
"""
This is the integrated component for crossbar that does dynamic authentication. Crossbar
will instantiate the below AuthenticatorSession() class, you do not need to run this
yourself.

Remember that because crossbar is running this, we are strictly "twisted" here, don't
use asyncio.
"""

__version__  = '1.6'
__author__   = 'David Ford <david@blue-labs.org>'
__email__    = 'david@blue-labs.org'
__date__     = '2017-Feb-28 02:45z'
__license__  = 'Apache 2.0'


import ssl
import time
import txaio
import base64
import hashlib
import datetime
import traceback
import configparser

from ldap3                   import Server
from ldap3                   import Connection
from ldap3                   import Tls
from ldap3                   import ALL_ATTRIBUTES
from ldap3                   import ALL
from ldap3                   import SUBTREE
from ldap3                   import LEVEL
from ldap3                   import MODIFY_REPLACE
from ldap3                   import SIMPLE
from ldap3.core.exceptions   import LDAPInvalidCredentialsResult
from ldap3.core.exceptions   import LDAPSizeLimitExceededResult
from ldap3.core.exceptions   import LDAPException
from ldap3.core.exceptions   import LDAPSessionTerminatedByServerError
from ldap3.core.exceptions   import LDAPSocketReceiveError

from dateutil                import parser as dateparser
from pprint                  import pprint
from base64                  import urlsafe_b64decode as dcode
from twisted.internet.defer  import inlineCallbacks
from autobahn.twisted.wamp   import ApplicationSession
from autobahn.wamp.exception import ApplicationError

txaio.start_logging(level='info')
txaio.use_twisted()

# configparser helpers
def _cfg_None(config, section, key):
    return  config.get(section, key, fallback=None) or \
        config.get('default', key, fallback=None) or \
        None

def _cfg_List(config, section, key):
    v = _cfg_None(config, section, key)
    if not v:
        return
    return [x for x in v.replace(',', ' ').split(' ') if x]


class LDAP():
    def __init__(self, cfg):
        self.log         = txaio.make_logger()
        self.cfg         = cfg
        self.valid_names = _cfg_List(cfg, 'authentication', 'valid names')
        self.host        = cfg.get('authentication', 'host', fallback='127.0.0.1')
        self.port        = int(cfg.get('authentication', 'port', fallback='389'))
        self.base        = cfg.get('authentication', 'base')
        self.userdn      = cfg.get('authentication', 'userdn')
        self.username    = ''
        self.password    = ''


    def retry_connect(self):
        deadtime = datetime.datetime.utcnow() + datetime.timedelta(seconds=60)
        self.ctx = None

        username = 'uid={},ou=People,{}'.format(self.username,self.base)

        while deadtime > datetime.datetime.utcnow():
            try:
                ca_file = '/etc/ssl/certs/ca-certificates.crt'
                tlso    = Tls(ca_certs_file=ca_file,
                              validate=ssl.CERT_REQUIRED,
                              valid_names=self.valid_names)
                server  = Server(host=self.host,
                                 port=self.port,
                                 use_ssl=False,
                                 get_info=ALL,
                                 tls=tlso)
                ctx     = Connection(server,
                                     user=username,
                                     password=self.password,
                                     raise_exceptions=True,
                                     authentication=SIMPLE)
                ctx.open()
                ctx.start_tls()
                if not ctx.bind():
                    raise ApplicationError('org.blue_labs.misty.ldap.error',
                                           'Failed to bind')
                break

            except (LDAPSessionTerminatedByServerError, LDAPSocketReceiveError):
                time.sleep(1)

            except Exception as e:
                self.log.error('LDAP error: {}'.format(e))
                raise ApplicationError('org.blue_labs.misty.ldap.error', e)

        self.ctx = ctx


    def rsearch(self, base=None, filter=None, attributes=ALL_ATTRIBUTES):
        if not base:
            base = self.base
        try:
            self.ctx.search(base, filter, attributes=attributes)
        except (LDAPSessionTerminatedByServerError, LDAPSocketReceiveError):
            self.retry_connect()
            self.ctx.search(base, filter, attributes=attributes)


class AuthenticatorSession(ApplicationSession):
    @inlineCallbacks
    def onJoin(self, details):
        self.log = txaio.make_logger()
        self.log.debug("WAMP-Ticket dynamic authenticator joined: {}".format(details))

        try:
            self._ldap
        except:
            # we expect to be started by crossbar and crossbar's CWD will be $path/.crossbar/
            # allow exceptions to propagate up to the router
            cfg = configparser.ConfigParser()
            cfg.read('../auth.conf')
            host,*port = (cfg['authentication']['host']).rsplit(':',1)
            port       = port and port[0] or '389'
            cfg['authentication']['host'] = host
            cfg['authentication']['port'] = cfg.get('authentication', 'port', fallback=port)

            for key in ('valid names','host','userdn','userpassword','base'):
               if not cfg.get('authentication', key):
                  s = "section [authentication]; required config option '{}' not found".format(key)
                  raise ApplicationError('org.blue_labs.misty.config.error',s)

            if not cfg.get('WAMP', 'realm'):
                s = "section [WAMP]; required config option 'realm' not found"
                raise ApplicationError('org.blue_labs.misty.config.error',s)

            self.cfg = cfg
            self._ldap = LDAP(cfg)
            self._ldap.username = cfg.get('authentication','userdn').split(',')[0].split('=')[1]
            self._ldap.password = cfg.get('authentication','userpassword')
            self._ldap.retry_connect()


        def authenticate(realm, authid, details):
            self.log.debug("WAMP-Ticket dynamic authenticator invoked: realm='{}', authid='{}', details=".format(realm, authid))
            pprint(details)
            gnow       = datetime.datetime.now(datetime.timezone.utc)
            ticket     = details['ticket']
            apimanager = self.cfg.get('authentication', 'userdn', fallback=None).split(',',1)[0].split('=')[1]

            try:
                ldap_bind_check          = LDAP(self.cfg)
                ldap_bind_check.username = authid
                ldap_bind_check.password = ticket
                ldap_bind_check.retry_connect()
                ldap_bind_check.ctx.unbind()
                del ldap_bind_check
            except Exception as e:
                self.log.error('fuck: {}'.format(e))
                raise ApplicationError('org.blue_labs.misty.invalid_credentials',
                    "could not authenticate session - invalid credentials for {!r}"
                    .format(authid))

            attributes=['uid','title','department','displayName','jpegPhoto',
                        'shadowInactive','shadowExpire','userPassword',
                        'realm','role','roleAdmin',
                        ]

            try:
                self._ldap.rsearch(filter='(uid={authid})'.format(authid=authid),
                      attributes=attributes)
            except Exception as e:
                self.log.error('omgwtf: {}'.format(e))
                raise ApplicationError('org.blue_labs.misty.ldap.error',
                    'user not assigned any realms to authenticate with')

            if len(self._ldap.ctx.response) > 1:
                raise ApplicationError('org.blue_labs.misty.ldap.error',
                    "could not authenticate session - multiple entries exist for principal '{}'"
                    .format(authid))

            if not len(self._ldap.ctx.response) == 1:
               raise ApplicationError('org.blue_labs.misty.invalid_credentials',
                   "could not authenticate session - invalid credentials for principal '{}'"
                   .format(authid))

            try:
                principal = self._ldap.ctx.response[0]['attributes']

                if not 'role' in principal:
                    principal['role'] = 'user'

                if not 'realm' in principal:
                    if not authid == apimanager:
                        raise ApplicationError('org.blue_labs.misty.invalid_credentials',
                            'user not assigned any realms to authenticate with')
                    else:
                        principal['realm'] = realm
                elif not realm in principal['realm']:
                    raise ApplicationError('org.blue_labs.misty.invalid_credentials',
                        'user not permitted to authenticate in realm; {!r} not in {}:'
                        .format(realm, principal['realm']))

                if not 'roleAdmin' in principal:
                    principal['roleAdmin'] = False
                if not 'jpegPhoto' in principal:
                    principal['jpegPhoto'] = []
                if not 'displayName' in principal:
                    principal['displayName'] = ''
                if not 'department' in principal:
                    principal['department'] = ['']
                if not 'title' in principal:
                  principal['title'] = ''

                if principal['jpegPhoto']:
                    bl = []
                    print('reencoding jpeg images as b64')
                    for p in principal['jpegPhoto']:
                        bp = base64.b64encode(p).decode()
                        bl.append(bp)
                    principal['jpegPhoto'] = bl

                if not authid == apimanager:
                    # if not, this effectively means there's no expiration
                    if 'shadowExpire' in principal:
                        try:
                            shadow_expire = int(principal['shadowExpire'][0])
                        except:
                            shadow_expire = -1

                        epoch_to_now = (datetime.datetime.utcnow() - datetime.datetime(1970,1,1)).days
                        self.log.debug('epoch_to_now = {}'.format(epoch_to_now))
                        days_until_expired = epoch_to_now - shadow_expire
                        if days_until_expired <= 0:
                            raise ApplicationError('org.blue_labs.misty.account_expired',
                                "could not authenticate session - expired password for principal '{}'"
                                .format(authid))
                    else:
                        self.log.warning("maybe uid='{}' should have shadowExpire set?".format(authid))


                if not 'notBefore' in principal and 'notAfter' in principal:
                    raise ApplicationError('org.blue_labs.misty.invalid_role_configured',
                        "couldn't authenticate session - invalid role configuration '{}' for principal '{}'"
                        .format(ticket, authid))

            except Exception as e:
                traceback.print_exc()
                raise ApplicationError('org.blue_labs.misty.attribute_error', e)

            # res.realm only refers to the realm the request was made with
            # clients need to be activated into a realm. currently Crossbar only supports one
            # realm per connection so for now just force everyone into the 'misty' realm
            # regardless of which realm they log in with
            realm=self.cfg.get('WAMP', 'realm')

            res = {
                'realm': realm,
                'role':  principal['role'],
                'extra': {
                    'roleAdmin':   principal['roleAdmin'],
                    'jpegPhoto':   principal['jpegPhoto'],
                    'department':  principal['department'],
                    'displayName': principal['displayName']
                }
            }

            resp = {
                'realm': principal['realm'],
                'role':  principal['role'],
                'extra': {
                    'roleAdmin':   principal['roleAdmin'],
                    'jpegPhoto':   '<suppressed>',
                    'department':  principal['department'],
                    'displayName': principal['displayName']
                }
            }

            self.log.info('{} login, requested realm: {}, assigned role: {}'.format(authid, realm, principal['role']))

            # crossbar/txaio still not able to handle formatted format strings that have braces in them... log.info("foo {}".format(somedictionary))
            # 2017-02-28T01:08:01-0500 [Router      17628] Unable to format event {'log_logger': <Logger 'autobahn.wamp.protocol.ApplicationSession'>, 'log_source': None, 'log_format': "WAMP-Ticket authentication success: {'realm': ['misty'], 'role': 'Provider', 'extra': {'roleAdmin': [], 'jpegPhoto': '<suppressed>', 'department': [], 'displayName': []}}", 'log_time': 1488262081.92916}: "'realm'"
            self.log.info("WAMP-Ticket authentication success: {resp}", resp=resp)
            return res

        try:
            yield self.register(authenticate, 'org.blue_labs.misty.authenticate')
            self.log.info("WAMP-Ticket dynamic authenticator registered")
        except Exception as e:
            raise ApplicationError('org.blue_labs.misty.error',
                'Failed to register dynamic authenticator: {}'.format(e))
