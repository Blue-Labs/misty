"""
This is the integrated component for crossbar that does dynamic authentication. Crossbar
will instantiate the below AuthenticatorSession() class, you do not need to run this
yourself.

Remember that because crossbar is running this, we are strictly "twisted" here, don't
use asyncio.
"""

__version__  = '1.0'
__author__   = 'David Ford <david@blue-labs.org>'
__email__    = 'david@blue-labs.org'
__date__     = '2017-Mar-9 07:45z'
__license__  = 'Apache 2.0'


import ssl
#import time
import txaio
import base64
#import hashlib
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
        self.cfg         = cfg
        self.valid_names = _cfg_List(cfg, 'authentication', 'valid names')
        self.host        = cfg.get('authentication', 'host', fallback='127.0.0.1')
        self.port        = int(cfg.get('authentication', 'port', fallback='389'))
        self.base        = cfg.get('authentication', 'base')
        self.userdn      = cfg.get('authentication', 'userdn')
        self.username    = ''
        self.password    = ''
        self.log         = txaio.make_logger()


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
                                     read_only=True,
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
                # print so it's visible, crossbar likes to swallow things
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

def b32encode(subj):
    return '_____'+base64.b32encode(subj.encode()).lower().decode().replace('=','_')

def b32decode(subj):
    return base64.b32decode(subj[5:].replace('_','=').upper().encode()).decode()

class AuthorizerSession(ApplicationSession):
    @inlineCallbacks
    def onJoin(self, details):
        self.log.info("Dynamic authorizer joined: {}".format(details))

        try:
            self._ldap
        except:
            # we expect to be started by crossbar and crossbar's CWD will be $path/.crossbar/
            # allow exceptions to propagate up to the router
            cfg = configparser.ConfigParser()
            cfg.read('../auth.conf')
            host,*port = (cfg['authorization']['host']).rsplit(':',1)
            port       = port and port[0] or '389'
            cfg['authorization']['host'] = host
            cfg['authorization']['port'] = cfg.get('authorization', 'port', fallback=port)

            for key in ('valid names','host','userdn','userpassword','base'):
               if not cfg.get('authorization', key):
                  s = "section [authorization]; required config option '{}' not found".format(key)
                  raise ApplicationError('org.blue_labs.misty.config.error',s)

            if not cfg.get('WAMP', 'realm'):
                s = "section [WAMP]; required config option 'realm' not found"
                raise ApplicationError('org.blue_labs.misty.config.error',s)

            self.cfg = cfg
            self._ldap = LDAP(cfg)
            self._ldap.username = cfg.get('authorization','userdn').split(',')[0].split('=')[1]
            self._ldap.password = cfg.get('authorization','userpassword')
            self._ldap.retry_connect()

        try:
            yield self.register(self.authorize, 'org.blue_labs.misty.authorizer')
        except:
            traceback.print_exc()


    def authorize(self, session, uri, action):

        default_permissions = {
            'org.blue_labs.misty.nodes':{'subscribe':True},
            'org.blue_labs.misty.role.lookup':{'call':True},
            'org.blue_labs.misty.rpi.get.revision':{'call':True},
            'org.blue_labs.misty.nodes.research':{'publish':True},
        }

        def answer(uri, action, perm, session):
            color=['\x1b[1;31m','\x1b[1;32m'][perm]
            s='{}/{}{}\x1b[0m/{}'.format(session['authid'], color, action, uri)
            print(s)
            return {'allow':perm, 'disclose':{'caller':True, 'publisher':True}}

        if not uri.startswith('org.blue_labs.misty.'):
            print('unknown URI prefix: {}'.format(uri))
            return answer(uri, action, False, session)

        # reform the topic
        prefix      = uri[:20]
        topic_parts = uri[20:].split('.')
        try:
            if topic_parts[1].startswith('_____') and topic_parts[1].endswith('_'):
                x   = b32decode(topic_parts[1])
                uri = topic_parts[0]+'.'+x
                if len(topic_parts)>2:
                     uri += '.' +'.'.join(topic_parts[2:])
                uri = prefix+uri
        except:
            pass

        if uri in default_permissions:
            adic = default_permissions.get(uri)
            success = adic.get(action, False)
            return answer(uri, action, success, session)

        if topic_parts[0] == 'node':
            if len(topic_parts)>1 and topic_parts[1].startswith('_____'):
                # lookup of a pi-node, or zone
                pi_node = b32decode(topic_parts[1])
                zone    = None

                if len(topic_parts)>2:
                     zone = topic_parts[2]

                friendlyname = 'node.'+pi_node
                if zone:
                     friendlyname +='.'+zone

                self._ldap.rsearch(filter='(&(objectClass=mistyNode)(cn={}))'.format(pi_node),
                                   attributes=['manager-user','viewer-user'])

                # if 'manage-user' is present and authid is not in this list, user has RO access to modify pi-node
                if len(self._ldap.ctx.response)>0:
                   perms = self._ldap.ctx.response[0]['attributes']
                   #print ('ldap node perms: {}'.format(perms))
                   mu = perms.get('manager-user')
                   vu = perms.get('viewer-user')

                   # test
                   if zone in ('4','5'):
                        mu=None
                        vu=None

                   # warning, these need to ensure the action matches the read/writability method


                   if mu and session['authid'] in mu:
                        # user has RW access for everything on this pi
                        return answer(uri, action, True, session)
                   elif vu and session['authid'] in vu:
                        # user has RO to this pi-node, this is a read only function
                        return answer(uri, action, True, session)
                   elif vu and not session['authid'] in vu:
                        # user doesn't have RW, VU is present without user specified. no access
                        return answer(uri, action, False, session)
                   elif zone is None:
                        # default permissions, everything is permitted
                        return answer(uri, action, True, session)
                   else:
                        # check specific zone controls
                        self._ldap.rsearch(filter='(&(objectClass=mistyZone)(zone={})(pi-node={}))'.format(zone,pi_node),
                                           attributes=['manager-user','viewer-user'])
                        perms = self._ldap.ctx.response[0]['attributes']
                        #print('ldap zone perms: {}'.format(perms))
                        mu = perms.get('manager-user')
                        vu = perms.get('viewer-user')

                        if mu and session['authid'] in mu:
                            return answer(uri, action, True, session)
                        elif vu and session['authid'] in vu:
                            # user has RO to this pi-node, this is a read only function
                            return answer(uri, action, True, session)
                        elif vu and not session['authid'] in vu:
                            # user doesn't have RW, VU is present without user specified. no access
                            return answer(uri, action, False, session)

                # failed all ACLs
                return answer(uri, action, False, session)


        elif 'shizzle':
            pass

        print('dyn-authorize, FAILED: session={}, uri={}, action={}'
            .format(session, uri, action))

        return True

"""
                            "permissions": [
                                {
                                    "uri": "org.blue_labs.misty.role.*",
                                    "allow": {
                                        "call": true
                                    },
                                    "disclose": {
                                        "caller": true,
                                        "publisher": true
                                    }
                                },
                                {
                                    "uri": "org.blue_labs.misty.nodes",
                                    "allow": {
                                        "subscribe": true,
                                        "call": true
                                    },
                                    "disclose": {
                                        "caller": true,
                                        "publisher": true
                                    }
                                },
                                {
                                    "uri": "org.blue_labs.misty.nodes.research",
                                    "allow": {
                                        "subscribe": true,
                                        "publish": true
                                    },
                                    "disclose": {
                                        "caller": true,
                                        "publisher": true
                                    }
                                },
                                {
                                    "uri": "org.blue_labs.misty.nodezone.*",
                                    "allow": {
                                        "subscribe": true,
                                        "call": true
                                    },
                                    "disclose": {
                                        "caller": true,
                                        "publisher": true
                                    }
                                },
                                {
                                    "uri": "org.blue_labs.misty.rpi.*",
                                    "allow": {
                                        "subscribe": true,
                                        "call": true
                                    },
                                    "disclose": {
                                        "caller": true,
                                        "publisher": true
                                    }
                                }
                            ]

"""
