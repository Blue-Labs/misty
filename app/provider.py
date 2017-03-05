
"""
This is the standalone provider for crossbar that provides all the RPCs and pub/sub for
operations. We ONLY use asyncio here, no twisted.
"""

__version__  = '1.9'
__author__   = 'David Ford <david@blue-labs.org>'
__email__    = 'david@blue-labs.org'
__date__     = '2017-Feb-28 5:39z'
__license__  = 'Apache 2.0'

# ubjson emits an ImportWarning warning so import it now before we turn on warnings (imported in autobahn wamp serializers)
import ubjson

def warn_with_traceback(message, category, filename, lineno, file=None, line=None):
    traceback.print_stack()
    log = file if hasattr(file,'write') else sys.stderr
    log.write(warnings.formatwarning(message, category, filename, lineno, line))

import warnings
warnings.resetwarnings()
warnings.showwarning = warn_with_traceback

import asyncio
import base64
import configparser
import datetime
import logging
import re
import os
import sys
import ssl
import time
import traceback
import txaio
import janus
import pprint
import functools
import threading
import subprocess

import RPi.GPIO as GPIO
GPIO.setwarnings(False)

from ldap3 import Server
from ldap3 import Connection
from ldap3 import Tls
from ldap3 import ALL_ATTRIBUTES
from ldap3 import ALL
from ldap3 import SUBTREE
from ldap3 import LEVEL
from ldap3 import MODIFY_ADD
from ldap3 import MODIFY_REPLACE
from ldap3 import MODIFY_DELETE
from ldap3 import SIMPLE
from ldap3 import HASHED_SALTED_SHA
from ldap3.core.exceptions import LDAPInvalidCredentialsResult
from ldap3.core.exceptions import LDAPSizeLimitExceededResult
from ldap3.core.exceptions import LDAPException
from ldap3.core.exceptions import LDAPSessionTerminatedByServerError
from ldap3.core.exceptions import LDAPSocketReceiveError
from ldap3.core.exceptions import LDAPAttributeOrValueExistsResult
from ldap3.core.exceptions import LDAPNoSuchAttributeResult
from ldap3.utils.hashed import hashed

from autobahn                import wamp
from autobahn.wamp.types     import CallOptions
from autobahn.wamp.types     import Challenge
from autobahn.wamp.types     import CloseDetails
from autobahn.wamp.types     import ComponentConfig
from autobahn.wamp.types     import EventDetails
from autobahn.wamp.types     import PublishOptions
from autobahn.wamp.types     import RegisterOptions
from autobahn.wamp.types     import SessionDetails
from autobahn.wamp.types     import SubscribeOptions
from autobahn.asyncio.wamp   import ApplicationSession
from autobahn.asyncio.wamp   import ApplicationRunner
from autobahn.wamp.exception import ApplicationError

from autobahn.websocket.util import parse_url
from autobahn.asyncio.websocket import WampWebSocketClientFactory

from concurrent.futures import CancelledError
from concurrent.futures import ProcessPoolExecutor

txaio.start_logging(level='info')
txaio.use_asyncio()


class LDAP():
    def __init__(self, cfg):
        self.cfg         = cfg
        self.valid_names = _cfg_List(cfg, 'authentication', 'valid names')
        self.host        = cfg.get('authentication', 'host', fallback='127.0.0.1')
        self.port        = int(cfg.get('authentication', 'port', fallback='389'))
        self.base        = cfg.get('authentication', 'base')
        self.userdn      = cfg.get('authentication', 'userdn')
        self.passwd      = cfg.get('authentication', 'userpassword')
        self.retry_connect()


    def retry_connect(self):
        deadtime = datetime.datetime.utcnow() + datetime.timedelta(seconds=60)
        self.ctx = None
        
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
                                     user=self.userdn,
                                     password=self.passwd,
                                     raise_exceptions=True,
                                     authentication=SIMPLE)

                print('LDAP init {}'.format(ctx))
                ctx.open()
                ctx.start_tls()
                try:
                    ctx.bind()
                except:
                    raise ApplicationError('org.blue_labs.misty.ldap.error', 'Failed to bind')

                break

            except (LDAPSessionTerminatedByServerError, LDAPSocketReceiveError):
                time.sleep(1)

            except Exception as e:
                print('LDAP error: {}'.format(e))
                raise ApplicationError('org.blue_labs.misty.ldap.error', e)

        self.ctx = ctx
        self.server = server


    def rsearch(self, base=None, filter=None, scope=None, attributes=ALL_ATTRIBUTES):
        if not base:
            base = self.base
        if not scope:
            scope = SUBTREE

        try:
            self.ctx.search(search_base   =base,
                            search_filter =filter,
                            search_scope  =scope,
                            attributes    =attributes)
        except (LDAPSessionTerminatedByServerError, LDAPSocketReceiveError):
            self.retry_connect()
            self.ctx.search(base, filter, attributes=attributes)


class _Component(ApplicationSession): # this is the Provider class

    log   = None
    pool  = None
    _ldap = None
    cache = {}
    zones = {}
    topic_subscribers = {}
    
    def __init__(self, realm:str, cfg:dict, loop, q:janus.Queue, event:threading.Event, join_future:asyncio.Future):
        super().__init__(ComponentConfig(realm, cfg))
        #self.log        = logging.getLogger()
        self.log              = txaio.make_logger()

        self.realm            = realm
        self.cfg              = cfg
        self.event_loop       = loop
        self.q                = q
        self.event            = event
        self.__join_future    = join_future
        self.__hardware_setup = False
        
        self.ldap_zone_dn_suffix = cfg.get('zones', 'dn suffix')


    @asyncio.coroutine
    def meta_on_join(self, details, b):
        print('meta_on_join {}, details: {}'.format(b, details))
        #topic = yield self.call("wamp.subscription.get", b)
        #print('create topic:',topic)
        #yield self.publish('org.blue_labs.misty.zones.get_all', self.get_zones.get_all())


    @asyncio.coroutine
    def meta_on_create(self, details, b):
        print('meta_on_create {}, details: {}'.format(b, details))
        topic = yield from self.call("wamp.subscription.get", b)
        print('create topic:',topic)


    # since session.call('wamp.subscription*') breaks no matter what method is tried, we have
    # to resort to this
    @asyncio.coroutine
    def meta_on_subscribe(self, subscriberid, sub_details, details):
        print('meta_on_subscribe: sid:{}, sub_d:{}, d:{}'.format(subscriberid, sub_details, details))
        try:
            topic = yield from self.call("wamp.subscription.get", sub_details)
            print('\x1b[1;32m{} subscribed to {}\x1b[0m'.format(subscriberid, topic['uri']))

            if not topic['uri'] in self.topic_subscribers:
                self.topic_subscribers[topic['uri']] = []
            if not subscriberid in self.topic_subscribers[topic['uri']]:
                self.topic_subscribers[topic['uri']].append(subscriberid)

        except Exception as e:
          print('awwshit (it happens): {} {}'.format(e.__class__, e))


    @asyncio.coroutine
    def meta_on_unsubscribe(self, subscriberid, sub_details, details):
        print('meta_on_unsubscribe: sid:{}, sub_d:{}, d:{}'.format(subscriberid, sub_details, details))
        try:
            topic = yield from self.call("wamp.subscription.get", sub_details)
            print('\x1b[1;32m{} unsubscribed from {}\x1b[0m'.format(subscriberid, topic['uri']))

            if topic['uri'] in self.topic_subscribers and subscriberid in self.topic_subscribers[topic['uri']]:
              self.topic_subscribers[topic['uri']].remove(subscriberid)
        #except wamp.error.no_such_subscription:
        #    print('nss')
        except Exception as e:
            print('awwshit (it happens): {} {}'.format(e.__class__,e))


    """ keep for TZ conversion notes

    # DNS db methods, not used now?
    @asyncio.coroutine
    def _make_dict_list(self, curs, rows=None):
        if not rows:
            rows = yield from curs.fetchall()

        columns = [d.name for d in curs.description]
        rt = []

        try:
            for r in rows:
                _ = dict(zip(columns, r))

                # make strings out of timestamps and trim to 1sec precision, also convert from TZ to UTC
                for key in ('created','updated','modified'):
                    if key in _:
                        ts = _[key]
                        #print('set ts to: [{}] {} on row: {}'.format(key,ts,_))
                        try:
                            ts = _[key].astimezone(tz=datetime.timezone.utc)
                        except Exception as e:
                            print(str(e))
                            print('Missing create/update data on row')
                            print(curs.query.decode())
                            print(_)
                            print('---')
                            ts = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)

                        ts = ts.replace(microsecond=0).strftime('%F %T')
                        _[key] = ts

                rt.append(_)

        except Exception as e:
            print(e)
            traceback.print_exc()

        return rt
    """


    def onConnect(self):
        self.log.debug('onConnect launch')
        try:
            self.close_reason = None
            realm  = self.cfg.get('WAMP', 'realm')
            userdn = self.cfg.get('authentication', 'userdn', fallback=None)
            authid = userdn.split(',')[0].split('=')[1]
        except Exception as e:
            traceback.print_exc()

        print("ClientSession connected:          Joining realm <{}> with authid <{}>".format(realm if realm else 'not provided', authid))
        try:
            self.join(realm, ['ticket'], authid)
        except Exception as e:
            traceback.print_exc()
        #self._ldap = LDAP(self.cfg) # called in onJoin()


    def onChallenge(self, challenge):
        print("ClientSession challenge received: {}".format(challenge))
        if challenge.method == 'ticket':
            return self.cfg.get('authentication', 'userpassword', fallback=None)
        else:
            raise Exception("Invalid authmethod {}".format(challenge.method))


    @asyncio.coroutine
    def onJoin(self, details):
        print('ClientSession onJoin:             {}',details)
        if not self._ldap:
            self._ldap   = LDAP(self.cfg)
            self.pi_node = cfg.get('provider', 'pi node')

        sublist = yield from self.call('wamp.subscription.list')
        print('onjoin sublist:',sublist)

        yield from self.register(self, options=RegisterOptions(details_arg='detail'))
        yield from self.subscribe(self.meta_on_join, 'wamp.subscription.on_join')
        yield from self.subscribe(self.meta_on_subscribe, 'wamp.subscription.on_subscribe', options=SubscribeOptions(details_arg="details"))
        yield from self.subscribe(self.meta_on_unsubscribe, 'wamp.subscription.on_unsubscribe', options=SubscribeOptions(details_arg="details"))

        try:
            res = yield from self.subscribe(self, options=SubscribeOptions(match="prefix", details_arg='details'))
            print("Subscribed {} procedure(s)".format(len(res)))
        except Exception as e:
            print("could not subscribe procedures: {}".format(e))

        # discard results, but trigger updates on UIs. this updates UIs to current state of things
        yield from self.call('org.blue_labs.misty.zones.research')
        
        # this updates hardware and UIs to scheduled state of things
        self.event.set()

        self.__join_future.set_result(details)
        self.__join_future = None


    def onLeave(self, details):
        print("ClientSession left:               {}".format(details))
        self.disconnect()


    def onDisconnect(self):
        print('clientSession disconnected')
        asyncio.get_event_loop().stop()


    def onSubscribe(self, details):
        print('==========',details)


    def push_pub(self, uri, data, options={}):
        if not 'acknowledge' in options:
            options['acknowledge']=True
        print('\x1b[1;37mpublishing to {}, options={}\x1b[0m {}'.format(uri,options,data))
        asyncio.shield(self.publish(uri, data, options=PublishOptions(**options)))


    @wamp.register('org.blue_labs.misty.role.lookup')
    def role_lookup(self, *args, **kwargs):
        if args and 'all-attributes' in args[0]:
                attributes = ALL_ATTRIBUTES;
        else:
            attributes=['uid','title','department','displayName','jpegPhoto',
                        'shadowInactive','shadowExpire','userPassword',
                        'realm','role','roleAdmin',
                        ]

        # check that the calling user has roleAdmin set
        authid=kwargs['detail'].caller_authid

        if len(args)>1:
            try:
                self._ldap.rsearch(filter='(&(uid={authid})(roleAdmin=TRUE))'.format(authid=authid),
                   attributes=['roleAdmin'])
            except Exception as e:
                print('exc: {}'.format(e))
                raise ApplicationError('org.blue_labs.misty.search_error', e)

            if not self._ldap.ctx.response:
                raise ApplicationError('org.blue_labs.misty.insufficient_privilege',
                  '{} not authorized to manage users'.format(authid))

            authid = args[1]

        principal = {}

        try:
            self._ldap.rsearch(filter='(uid={authid})'.format(authid=authid),
               attributes=attributes)
        except Exception as e:
            print('exc: {}'.format(e))
            raise ApplicationError('org.blue_labs.misty.search_error', e)
        principal.update(self._ldap.ctx.response[0]['attributes'])

        try:
            if 'jpegPhoto' in principal and principal['jpegPhoto']:
                if isinstance(principal['jpegPhoto'], list):
                    principal['jpegPhoto'] = [base64.b64encode(p).decode() for p in principal['jpegPhoto']]
                else:
                    principal['jpegPhoto'] = base64.b64encode(principal['jpegPhoto']).decode()
            else:
               principal['jpegPhoto'] = []

            for k in ('realm','realmAdmin','realmOwner','roleAdmin','email','emailExternal'):
                if not k in principal:
                    principal[k] = []
            for k in ('pqcLength','pqcLowercase','pqcUppercase','pqcDigits','pqcSymbols'):
                if not k in principal:
                    principal[k] = -1
            for k in ('department','title','sn','givenName','displayName'):
                if not k in principal:
                    principal[k] = ''

            if not 'shadowLastChange' in principal:
                principal['shadowLastChange'] = 0

            principal['realm'] += principal['realmAdmin']
            principal['realm'] += principal['realmOwner']
            principal['realm'] = sorted(set(principal['realm']))
            principal['realmAdmin'] = sorted(set(principal['realmAdmin']))
            principal['realmOwner'] = sorted(set(principal['realmOwner']))

            principal['shadowLastChange'] = (datetime.datetime(1970,1,1)+datetime.timedelta(days=principal['shadowLastChange']))

            if args and 'all-attributes' in args[0]:
                if 'userPassword' in principal:
                    del principal['userPassword']
                return principal

            res = {
                'realm': principal['realm'],
                'realmAdmin': principal['realmAdmin'],
                'roleAdmin': principal['roleAdmin'],
                'jpegPhoto': principal['jpegPhoto'],
                'department': principal['department'],
                'title': principal['title'],
                'displayName': principal['displayName']
            }

        except Exception as e:
            print('buttpuff {}'.format(e))
            traceback.print_exc()
            raise ApplicationError('org.blue_labs.misty.error', e)

        return res


    @wamp.register('org.blue_labs.misty.zones.research')
    def _zones_research(self, **args):
        detail = args['detail']
        print('zones.research(caller={})'.format(detail.caller))

        @asyncio.coroutine
        def f__g(detail):
            try:
                Misty._load_zone_data(self)
                zones = self.zones

                # run hardware setup
                if not self.__hardware_setup:
                    Misty._hardware_setup(self, [(zones[z]['wire-id'],'in' if 'digital-input' in zones[z] and zones[z]['digital-input'] else 'out') for z in zones])
                    Misty.__hardware_setup = True

                # if zone is configured as a relay, we need to make it an OUT type
                # for now, just hardwire things as outputs
                # also, if LOW means ON, we need to invert the state, this is a per
                # zone value because we may have individual relay boards instead of
                # groups
                for z in sorted(zones):
                    wire_id             = int(zones[z]['wire-id'])
                    state               = GPIO.input(wire_id) == 1
                    state_when_active   = zones[z]['logic-state-when-active'] if 'logic-state-when-active' in zones[z] else True
                    v                   = str(state == state_when_active).upper()
                    zones[z]['running'] = state == state_when_active

                    print('zone({}/gpio#{}) logic level: {}, active: {}'.format(z, zones[z]['wire-id'], state, v))
                    
            except:
                traceback.print_exc()

            try:
                exc = [s for s in self.topic_subscribers['org.blue_labs.misty.zones'] if not s == detail.caller]
            except:         # sometimes this trigger comes in BEFORE the client subscription event fires which means
                exc = None  # for the first subscriber, we don't know anything about this topic yet

            self.push_pub('org.blue_labs.misty.zones', zones, options={'exclude':exc, 'eligible':[detail.caller]})

        yield from f__g(detail)


    @wamp.register('org.blue_labs.misty.zone.set.enable')
    def zone_set_enable(self, *args, **details):
        d = args[0]

        # need to validate the zone
        print(d)
        zone    = int(d['zone'])
        enabled = d['enabled'] == True

        if not 0 <= zone <= 32:
            raise ApplicationError('org.blue_labs.misty.value.error', 'zone must be in range [0...32]')

        warnings.warn('check if user is authorized to modify either by the pi node or by the zone')

        ops = {'enabled': [(MODIFY_REPLACE, ['TRUE' if enabled else 'FALSE'])]}

        zone = Misty._update_zone_in_ldap(self, zone, ops)
        print('zone:',zone)

        # shutdown if running and not enabled
        if not enabled:
            if 'running' in zone:
                zone['running'] = False
            if 'manual-on' in zone:
                zone['manual-on'] = False

        self.push_pub('org.blue_labs.misty.zones', {zone['zone']:zone})
        return True


    @wamp.register('org.blue_labs.misty.zone.set.state')
    def zone_set_state(self, *args, **details):
        #print(args)
        d = args[0]
        print('d is: {}'.format(d))

        # need to validate the stuff
        zone     = int(d['zone'])
        toggle   = d['toggle']
        state    = d['state'] == True

        if not 0 <= zone <= 32:
            raise ApplicationError('org.blue_labs.misty.value.error', 'zone must be in range [0...32]')
        if not toggle in ('manual','suspend'):
            raise ApplicationError('org.blue_labs.misty.value.error', 'unknown toggle method')

        warnings.warn('check if user is authorized to modify either by the pi node or by the zone')

        end_time = []
        if state:
            if 'end-time' in d and d['end-time']:
                duration = int(d['end-time']) or 31536000
                end_time = datetime.datetime.utcnow() + datetime.timedelta(seconds=duration)

        if end_time:
            end_time = [end_time.strftime('%Y%m%d%H%M%SZ')]

        swap_toggle = {'manual':'suspend','suspend':'manual'}[toggle]
        swap_state  = not state
        
        ops = {'{}-on'.format(toggle): (MODIFY_REPLACE, ['TRUE' if state else 'FALSE']),
               '{}-end-time'.format(toggle): (MODIFY_REPLACE, end_time),
              }

        if state:
            # make sure alternate state is turned off, these are literal, no inversions
            ops['{}-on'.format(swap_toggle)] = (MODIFY_REPLACE, [])
            ops['{}-end-time'.format(swap_toggle)] = (MODIFY_REPLACE, [])

        else:
            if self.zones[zone].get('running'):
                # state indicates OFF but zone is showing as running. clear the running flag
                # this will have the effect of also terminating a calendar run, when manual is
                # ended, if zone was started by calendar
                ops['running'.format(swap_toggle)] = (MODIFY_REPLACE, ['FALSE'])


        print('ops: {}'.format(ops))

        try:
          zone = Misty._update_zone_in_ldap(self, zone, ops, update_wire_state=False)
        except:
          traceback.print_exc()

        print('result is: {}'.format(zone))
        self.push_pub('org.blue_labs.misty.zones', {zone['zone']:zone})
        
        zone['action'] = 'toggle'
        zone['key']    = toggle
        self.q.async_q.put_nowait(zone)
        self.event.set()

        return True


    @wamp.register('org.blue_labs.misty.zone.set.attribute')
    def zone_set_attribute(self, *args, **details):
        #print(args)
        d = args[0]
        print('d is: {}'.format(d))

        zone      = int(d['zone'])
        attribute = d['attribute']
        value     = d['value']

        if not 0 <= zone <= 32:
            raise ApplicationError('org.blue_labs.misty.value.error', 'zone must be in range [0...32]')

        warnings.warn('check if user is authorized to modify either by the pi node or by the zone')

        ops = {attribute: (MODIFY_REPLACE, [value])}
        print('ops: {}'.format(ops))

        zone = Misty._update_zone_in_ldap(self, zone, ops)

        print('result is: {}'.format(zone))
        self.push_pub('org.blue_labs.misty.zones', {zone['zone']:zone})
        
        return True


    def _get_rpi_models(self):
        # http://elinux.org/RPi_HardwareHistory
        models = {
            '0002': 'RaspberryPi Model B Revision 1.0, 256MB',
            '0003': 'RaspberryPi Model B Revision 1.0 + ECN0001 (no fuses, D14 removed), 256MB',
            '0004': 'RaspberryPi Model B Revision 2.0 w/ Mounting holes, 256MB',
            '0005': 'RaspberryPi Model B Revision 2.0 w/ Mounting holes, 256MB',
            '0006': 'RaspberryPi Model B Revision 2.0 w/ Mounting holes, 256MB',
            '0007': 'RaspberryPi Model A Mounting holes w/ Mounting holes, 256MB',
            '0008': 'RaspberryPi Model A Mounting holes w/ Mounting holes, 256MB',
            '0009': 'RaspberryPi Model A Mounting holes w/ Mounting holes, 256MB',
            '000d': 'RaspberryPi Model B Revision 2.0 Mounting holes, 512MB',
            '000e': 'RaspberryPi Model B Revision 2.0 Mounting holes, 512MB',
            '000f': 'RaspberryPi Model B Revision 2.0 Mounting holes, 512MB',
            '0010': 'RaspberryPi Model B+, 512MB',
            '0011': 'RaspberryPi Compute Module, 512MB',
            '0012': 'RaspberryPi Model A+, 256MB',
            '0013': 'RaspberryPi Model B+, 512MB',
          'a01041': 'RaspberryPi 2 Model B, (Sony, UK), 1GB',
          'a21041': 'RaspberryPi 2 Model B, (Embest, China), 1GB',
          '900092': 'RaspberryPi PiZero, 512MB',
          '900093': 'RaspberryPi PiZero, 512MB',
          'a02082': 'RaspberryPi 3 Model B, (Sony, UK), 1GB',
          'a22082': 'RaspberryPi 3 Model B, (Embest, China), 1GB',
        }

        with open('/proc/cpuinfo') as f:
            for line in f:
                if line.startswith('Revision'):
                    revision = line.split()[2]
                    break

        if revision in ('0002','0003','0007','0008','0009','0012'):
            pog=0
        elif revision in ('0004','0005','0006','000d','000e','000f'):
            pog=1
        else:
            pog=2

        try:
            rv = [{'revision':revision, 'model':models.get(revision, "Unknown RPi type"), 'pin_out_group':pog}]
        except:
            traceback.print_exc()

        print(rv)
        return rv


    @wamp.register('org.blue_labs.misty.rpi.get.revision')
    def zone_get_revision(self, *args, **details):
        return self._get_rpi_models()


    @wamp.register('org.blue_labs.misty.zones.get.zone_ids')
    def _zones_get_zone_ids(self, **args):
        """
        try:
            self._ldap.rsearch(base       =self.ldap_zone_dn_suffix,
                          scope      =LEVEL,
                          filter     ='(zone=*)',
                          attributes = ['zone','zone-description']
                          )
        except:
            traceback.print_exc()
            raise
        """
        ids = sorted([(int(e['attributes']['zone']),e['attributes']['zone-description']) for e in self.zones])
        return ids


    @wamp.register('org.blue_labs.misty.zones.get.wire_ids')
    def _zones_get_wire_ids(self, **args):
        """
        try:
            self._ldap.rsearch(base  = self.ldap_zone_dn_suffix,
                          scope      = LEVEL,
                          filter     = '(wire-id=*)',
                          attributes = ['wire-id']
                          )
        except:
            traceback.print_exc()
            raise
        """

        # eventually make a function out of this
        # varies slightly depending on RPi version
        #GPIO -> Phys PIN
        gpiomap = {
          0: {
           0: 3,
           1: 5,
           2: None,
           3: None,
           4: 7,
           5: None,
           6: None,
           7: 26,
           8: 24,
           9: 21,
          10: 19,
          11: 23,
          12: None,
          13: None,
          14: 8,
          15: 10,
          16: None,
          17: 11,
          18: 12,
          19: None,
          20: None,
          21: 13,
          22: 15,
          23: 16,
          24: 18,
          25: 22,
          },
          1: {
           0: None,
           1: None,
           2: 3,
           3: 5,
           4: 7,
           5: None,
           6: None,
           7: 26,
           8: 24,
           9: 21,
          10: 19,
          11: 23,
          12: None,
          13: None,
          14: 8,
          15: 10,
          16: None,
          17: 11,
          18: 12,
          19: None,
          20: None,
          21: 13,
          22: 15,
          23: 16,
          24: 18,
          25: 22,
          26: None,
          27: 13,
          },
          2: {
           0: None,
           1: None,
           2: 3,
           3: 5,
           4: 7,
           5: 29,
           6: 31,
           7: 26,
           8: 24,
           9: 21,
          10: 19,
          11: 23,
          12: 32,
          13: 33,
          14: 8,
          15: 10,
          16: 36,
          17: 11,
          18: 12,
          19: 35,
          20: 38,
          21: 40,
          22: 15,
          23: 16,
          24: 18,
          25: 22,
          26: 37,
          27: 13,
          },
        }

        rv = self._get_rpi_models()
        pin_map = rv[0]['pin_out_group']
        print('pin map is: {}'.format(pin_map))

        ids = sorted([int(z['attributes']['wire-id']) for z in self.zones])
        return [ids,rv[0],gpiomap[pin_map]]


    @wamp.register('org.blue_labs.misty.zones.add')
    def _zones_add_zone(self, nz, **args):
        print(nz)

        warnings.warn('check if user is authorized to modify per the pi node')

        # validate some foo
        bad_values=[]
        for kw in ('zone','wire_id','description','enabled',
                   'mode','follows','trigger_type','trigger',
                   'epoch','duration_type','duration'):
            if not kw in nz:
                bad_values.append(('missing keyword',kw,'keyword value must be present'))

        if bad_values:
            return bad_values

        if not (isinstance(nz['zone'], int) and nz['zone'] in range(33)):
            bad_values.append(('invalid value','zone','zone id must be an integer in the set(0..31)'))

        if not (isinstance(nz['pi-node'], str) and 0 < len(nz['pi-node']) < 256):
            bad_values.append(('invalid value','pi-node','pi-node must be a string within length 1..255'))

        if not (isinstance(nz['wire_id'], int) and nz['wire_id'] in range(28)):
            bad_values.append(('invalid value','wire_id','wire id must be an integer in the set(0..27)'))

        if not (isinstance(nz['description'], str) and 0 < len(nz['description']) < 256):
            bad_values.append(('invalid value','description','description must be a string within length 1..255'))

        if not isinstance(nz['enabled'], bool):
            bad_values.append(('invalid value','enabled','enabled must be True or False'))

        if not (isinstance(nz['mode'], str) and nz['mode'] in ('static','independent','parallel','chained')):
            bad_values.append(('invalid value','mode','mode must be in [static,independent,parallel,chained]'))

        if nz['mode'] == 'independent' and nz['follows']:
            del nz['follows']
        elif nz['mode'] == 'static':
            nz['duration_type'] = ''
            nz['duration']      = ''
            nz['trigger_type']  = ''

        elif nz['mode'] in ('parallel','chained'):
            if not (isinstance(nz['follows'], int) and 0 <= nz['follows'] < 32):
                bad_values.append(('invalid value','follows','mode is {} so follows should be an integer value of zone id'.format(nz['mode'])))

        if not nz['mode'] == 'static':
            if not nz['trigger_type'] in ('static','time of day','day of week','day of month','sensor'):
                bad_values.append(('invalid value','trigger_type','trigger_type must be in [time of day,day of week,day of month,sensor]'))

            if not nz['trigger_type'] == 'time of day':
                if not nz['trigger']:
                    bad_values.append(('invalid value','trigger','trigger must be in set'))
            else:
                if not nz['epoch']:
                    bad_values.append(('invalid value','epoch','start time must be set as HH:MM in 24hr format'))
                elif not re.fullmatch('\d\d:\d\d', nz['epoch']):
                    bad_values.append(('invalid value','epoch','start time must be set as HH:MM in 24hr format'))

            if not nz['duration_type'] in ('time','metered','sensor'):
                bad_values.append(('invalid value','duration_type','duration_type must be in set [time,metered,sensor]'))

            if not nz['duration'] and not nz['mode']=='static':
                bad_values.append(('invalid value','duration','duration value must be in set for non-static'))
            if nz['duration_type'] == 'time':
                m = re.fullmatch('((?:\d+(?:\.\d+|)))(.*)', nz['duration'])
                if not m:
                    bad_values.append(('invalid value','duration','duration value not parsable'))
                else:
                    print('parsed duration type: {}'.format(m.groups()))
                    unit = m.group(1)
                    mux  = m.group(2)

        if bad_values:
            print('bad input: {}'.format(bad_values))
            return bad_values


        nz['programmed']       = 'TRUE'
        nz['running']          = 'FALSE'
        nz['enabled']          = nz['enabled'] and 'TRUE' or 'FALSE'
        nz['wire-id']          = nz['wire_id'];        del nz['wire_id']
        nz['zone-description'] = nz['description'];    del nz['description']
        nz['trigger-type']     = nz['trigger_type'];   del nz['trigger_type']
        nz['duration-type']    = nz['duration_type'];  del nz['duration_type']

        dn = 'zone={},ou=zones,cn={}'.format(nz['zone'], nz['pi-node'], self.ldap_zone_dn_suffix)

        try:
            self._ldap.ctx.add(dn, ['mistyZone'], nz)
            Misty._load_zone_data(self)
        except Exception as e:
            print('ermg: {}'.format(e))
            traceback.print_exc()
            raise ApplicationError('org.blue_labs.misty.zone.add.error', str(e))

        self.push_pub('org.blue_labs.misty.zones', self.zones)
        return True


    @wamp.register('org.blue_labs.misty.zone.delete')
    def _zones_delete_zone(self, nz, **args):
        print(nz)

        warnings.warn('sanitize input')
        warnings.warn('check if user is authorized to modify per the pi node')
        dn = 'zone={},ou=zones,cn={}'.format(nz['zone'], nz['pi-node'], self.ldap_zone_dn_suffix)

        try:
            self._ldap.ctx.delete(dn)
            Misty._load_zone_data(self)
        except Exception as e:
            print('ermg: {}'.format(e))
            traceback.print_exc()

        warnings.warn('is "mode" keyword going to fuck things up as it is used in the zone schema already?')
        self.push_pub('org.blue_labs.misty.zones', {nz['zone']:{'zone':nz['zone'], 'mode':'deleted'}})
        return True



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


class Hardware:
    name = ''


class Relay(Hardware):
    def __init__(self):
        pass


# provider will run as a thread in the background, the foreground will be responsible
# for running the timed events and interaction with the relay hardware
class Misty():
    def __init__(self, cfg):
        self.log = logging.getLogger()
        self.cfg = cfg
        self.event = threading.Event()
        self._shutdown = False
        self.__hardware_setup = False
        self.starttime = datetime.datetime.now(tz=datetime.timezone.utc)

        exit_ = False
        for k in ('__version__','site_irl','realm','join timeout'):
            if not (k in cfg['main'] or k in cfg['WAMP']):
                exit_ = True
                print("required config option '{}' not found".format(k))

        if exit_:
            raise KeyError('missing required config values')

        self.realm          = cfg.get('WAMP','realm')
        self.irl            = cfg.get('WAMP','site_irl')
        self.client_version = cfg.get('main','__version__')
        self.join_timeout   = int(cfg.get('WAMP','join timeout'))
        self.pi_node        = cfg.get('provider', 'pi node')
        
        self._ldap = LDAP(cfg)
        
        self.ldap_zone_dn_suffix = cfg.get('zones', 'dn suffix')

        self.loop = asyncio.get_event_loop()
        self.q = janus.Queue(loop=self.loop)
        #tA = self.loop.run_in_executor(None, self.log_pusher, self.q.sync_q)
        tA = self.loop.run_in_executor(None, self.calendar)
        tB = self.loop.run_in_executor(None, self.wamp)


    def wamp(self):
        """ this runs the WAMP thread which is the Provider process
        We use our own ApplicationRunner here which is almost an identical copy of
        wamp.ApplicationRunner. The difference being that we need to:
         a) explicitly get a new asyncio event loop because we aren't running
            in the main thread - we'll get a RuntimeError: There is no current
            event loop in thread <thread name>, and
         b) don't set a signal handler for SIGTERM, also because we're not
            running in the main thread
        """

        isSecure, host, port, resource, path, params = parse_url(self.irl)
        ssl = True
        serializers = None

        loop = txaio.config.loop = asyncio.new_event_loop()
        self.wamp_eventloop = loop
        asyncio.set_event_loop(loop)

        async def fuck(loop):

            while True:
                try:
                    self.log.debug('Connecting to router ')
                    join_future       = asyncio.Future()
                    session_factory   = functools.partial(_Component, self.realm, self.cfg, loop, self.q, self.event, join_future)
                    transport_factory = WampWebSocketClientFactory(
                        session_factory, url=self.irl, serializers=serializers, loop=loop)

                    transport, protocol = await loop.create_connection(
                        transport_factory, host, port, ssl=ssl)

                except Exception as e:
                    traceback.print_exc()

                try:
                    # Connection established; wait for onJoin to finish
                    self.session_details = await asyncio.wait_for(join_future, timeout=60.0, loop=loop)
                    self.session = protocol._session
                    break
                except (asyncio.TimeoutError,):
                    self.log.warning('router connection timeout')
                    # absorb the concurrent.futures._base.CancelledError error
                    try:
                        await asyncio.wait([join_future])
                    except Exception as e:
                        self.log.critical('unexpected error while connecting to router: {}'.format(e))

                    transport.close()
                    continue
                except CancelledError:
                    try:
                        await asyncio.wait([join_future])
                    except Exception as e:
                        self.log.critical('unexpected error while connecting to router: {}'.format(e))
                    break
                except Exception as e:
                    self.log.critical(traceback.format_exc())
                    transport.close()
                    break

        while True:
            self.session = None

            tasks = [ asyncio.ensure_future(fuck(loop)), ]

            try:
                loop.run_until_complete(asyncio.wait(tasks))
                self.wamp_established = True
            except CancelledError:
                break
            except Exception as e:
                self.log.critical('unexpected error while connecting to router: {} {}**'.format(e.__class__, e))
                break

            try:
                loop.run_forever()
                if self.session.close_reason:
                    self.log.critical('session close reason: {}'.format(self.session.close_reason))
            except Exception as e:
                self.log.critical(traceback.format_exc())

            if self.session.close_reason == 'wamp.close.transport_lost':
                continue

            break

        # cleanup
        try:
            loop.run_until_complete(asyncio.wait(tasks))
        except:
            pass

        if self.wamp_eventloop.is_running():
            self.wamp_eventloop.stop()

        self.wamp_eventloop.close()


    def shutdown(self):
        now = datetime.datetime.now(tz=datetime.timezone.utc)
        whence = self.starttime + datetime.timedelta(seconds=self.join_timeout)
        self._shutdown = True

        if not self.q.async_q.empty():
            if not self.wamp_established and now < whence:
                self.log.debug('waiting for publish queue to be sent')

                # wait up to 10 seconds for client to connect
                while datetime.datetime.now(tz=datetime.timezone.utc) < whence:
                    time.sleep(.5)
                    if self.wamp_established:
                        self.log.debug('session joined, publishing')
                        # wait a few more seconds
                        while not self.q.async_q.empty():
                            time.sleep(.5)
                        break
                if not self.wamp_established:
                    self.log.warning('WAMP session still not established, giving up')
            else:
                self.log.warning('publish queue unable to be sent within timeout, losing messages')


        if self.session:
            self.session.leave('wamp.close.logout', 'logged out')

        tasks = asyncio.Task.all_tasks(loop=self.wamp_eventloop)
        for t in tasks:
            if not t.done():
                self.wamp_eventloop.call_soon_threadsafe(t.cancel)

        # how do we a) test if messages are still in queue or b) understand that
        # we do have messages in queue but can't send them? or c) we ran so fast
        # that we haven't even connected to the router yet?
        self.wamp_eventloop.stop()


    @staticmethod
    def _hardware_setup(caller, channels):
        """
        channels:   a sequence of tuples in the form of (wire id, 'in' | 'out')
        
        set up digital GPIO as IN or OUT per `channel' definitions.
        definitions should be in BCM (wire-id) form, at least for now ;)
        """
    
        # NOTE. make sure you chown/chgrp however you need so the user running this script
        # is able to read/write to /dev/gpiomem

        GPIO.setmode(GPIO.BCM)
        
        IN  = [int(ch) for ch,dio in channels if dio.lower() == 'in']
        OUT = [int(ch) for ch,dio in channels if dio.lower() == 'out']
        caller.log.info('hardware setup: {} set for input'.format(IN))
        caller.log.info('hardware setup: {} set for output'.format(OUT))
        
        GPIO.setup(IN, GPIO.IN)
        GPIO.setup(OUT, GPIO.OUT)


    @staticmethod
    def _update_zone_in_ldap(caller, zone, ops=None, update_wire_state=True):
        # if zone data was passed to us, get the current state of the zone and update the 'running' attribute
        if not ops:
            ops = {}

        try:
         if isinstance(zone, int):
              print('got int zone, convert to dict')
              zone = caller.zones[zone]
        
         print('do update with dict: {}'.format(zone))

         if update_wire_state:
             state          = str(GPIO.input(int(zone['wire-id'])) == zone['logic-state-when-active']).upper()
             ops['running'] = (MODIFY_REPLACE, [state])

         dn = 'zone={},ou=zones,cn={},{}'.format(zone['zone'], caller.pi_node, caller.ldap_zone_dn_suffix)

         # future todo, ensure sanity of dn
         # RFC-2849, make sure any pi-node name is safe for use
         #dn = base64.b64encode(dn.encode()).decode()
         #print('update b64dn: {}'.format(dn))
    
         caller._ldap.ctx.modify(dn, ops)
         #caller._ldap.rsearch(base   = self.ldap_zone_dn_suffix,
         #                     filter = '(zone={})'.format(zone['zone']),
         #                     scope  = LEVEL,
         #                    )

         # refresh caller's copy of zone data
         Misty._load_zone_data(caller)
        except Exception as e:
         traceback.print_exc()

        return caller.zones[zone['zone']]


    @staticmethod
    def _load_zone_data(caller):
        try:
            caller._ldap.rsearch(filter='(&(zone=*)(pi-node={}))'.format(caller.pi_node))
        except Exception as e:
            print('fucknut: {}'.format(e))
            return

        caller.zones = Misty._ldap_response_to_dict(caller._ldap.ctx.response)


    def _ldap_response_to_dict(response):
        zones = {}
        try:
            for d in response:
                zoneid = int(d['attributes']['zone'])
                zones[zoneid] = {}

                for k,v in d['attributes'].items():
                    if k == 'objectClass':
                        continue

                    if k in ('zone','wire-id'):
                        v = int(v)
                
                    elif isinstance(v, datetime.datetime):
                        k+='_seconds'
                        v = (v - datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)).total_seconds()
                    
                    zones[zoneid][k]=v
                        
                warnings.warn('we need a function to reduce something like "1245m" to 20h45m')

        except:
            traceback.print_exc()

        return zones


    def calendar(self):
        # set initial duration to wait forever. when our session has joined, we'll trigger the event
        # and let the calendar start running
        # reload the zone data and turn on/off per schedule, then calculate duration to wake up from

        def _get_epoch(s):
            if not s:
                return False
            if ':' in s:
                hr,mn = list(map(int, s.split(':')))
            else:
                hr = int(s[:2])
                mn = int(s[2:])
            return datetime.datetime.now().replace(hour=hr, minute=mn, second=0, microsecond=0)


        def _get_duration(s):
            m = re.fullmatch('(\d+)([dhms])\w*', s)
            if not m:
                print('fuck, no match in {}'.format(s))
                return False
            n = int(m.group(1))
            n *= {'d':86400, 'h':3600, 'm':60, 's':1}[m.group(2)]
            return datetime.timedelta(seconds=n)


        def _epoch_contains_now(z, begin, duration):
            print('zone {} epoch: {} for duration of {}'.format(z, begin.strftime('%m/%d-%H:%M'), duration))
            now = datetime.datetime.now().replace(second=0, microsecond=0)
            end = begin + duration
            
            #print('now:   {}'.format(now))
            #print('begin: {}'.format(begin))
            
            # if now - duration crosses midnight, roll begin back to the previous day and reset end
            if now < begin and (now - duration).day < now.day:
                begin -= datetime.timedelta(days=1)
                end = begin+duration

            b = begin.strftime('%m/%d-%H:%M')
            n = now.strftime('%m/%d-%H:%M')
            e = end.strftime('%m/%d-%H:%M')

            if begin <= now < end:
                print('   {}  \x1b[1;32m{}\x1b[0m  {}'.format(b,n,e))
                return True
            else:
                print('   {}  {}  {}'.format(b,n,e))


        # run hardware setup
        if not self.__hardware_setup:
            self._load_zone_data(self)
            zones = self.zones
            self._hardware_setup(self, [(zones[z]['wire-id'],'in' if 'digital-input' in zones[z] and zones[z]['digital-input'] else 'out') for z in zones])
            self.__hardware_setup = True

        event_duration=None

        while True:
            try:
                self.event.wait(timeout=event_duration)
                self.event.clear()
            except KeyboardInterrupt:
                self.event.set()
                self._shutdown = True

            if self._shutdown:
                break

            print('running calendar cycle')
            self._load_zone_data(self)
            zones = self.zones

            try:
                running={}
                calendar_times=[]
                # find any zones that should be on per manual/calendar/sensor. skip suspended
                for z in sorted(zones):
                    print('Check(zone={})'.format(z))
                
                    if 'suspend-on' in zones[z] and zones[z]['suspend-on']:
                        print('  suspended')
                        continue

                    if not 'enabled' in zones[z]:
                        print('  not enabled')
                        continue

                    if 'manual-on' in zones[z] and zones[z]['manual-on']:
                        running[z]=True
                        print('  manually on')
                        continue
                    
                    # must be programmed for remaining modes
                    if not zones[z]['programmed']:
                        print('  not programmed')
                        continue

                    print('  {}'.format(zones[z]['mode']))

                    if zones[z]['mode']=='static':
                        running[z]=True
                        print('  always on')
                        continue

                    if zones[z]['mode'] == 'independent':
                        
                        if _epoch_contains_now(z, _get_epoch(zones[z]['epoch']), _get_duration(zones[z]['duration'])):
                            print('    epoch indicates: should be running')
                            running[z] = True
                    
                    if zones[z]['mode'] in ('parallel','chained'):
                        # see if the parent that this follows is currently on
                        # which means this zone should be on too
                        parent = zones[z]['follows']
                        
                        if zones[z]['mode'] == 'parallel':
                            if _epoch_contains_now(parent, _get_epoch(zones[parent]['epoch']), _get_duration(zones[parent]['duration'])):
                                print('    epoch of parent (parallel) indicates: should be running')
                                running[z] = True
                        else:
                            pd = _get_duration(zones[parent]['duration'])
                            # need to follow the chain, accumulating duration
                            while not zones[parent]['mode'] == 'independent':
                                parent = zones[parent]['follows']
                                pd += _get_duration(zones[parent]['duration'])
                            e  = _get_epoch(zones[parent]['epoch'])
                            if _epoch_contains_now(parent, e+pd, _get_duration(zones[z]['duration'])):
                                print('    epoch of parent (chained) indicates: should be running')
                                running[z] = True

                    # need to implement sensor triggered, but there's no point
                    # until we have sensor type zones

            except:
                traceback.print_exc()
            
            print('Zones that should be ON:')
            for z in sorted(running):
                print(' {:<2} {}'.format(z,zones[z]['zone-description']))

            try:
                # now, each zone should match their running state. if not, make corrections
                for z in sorted(zones):
                    if zones[z]['mode'] == 'independent':
                        start =        _get_epoch(zones[z]['epoch'])
                        stop  = start+ _get_duration(zones[z]['duration'])
                    elif zones[z]['mode'] in ('parallel','chained'):
                        parent = zones[z]['follows']
                        pd = _get_duration(zones[parent]['duration'])
                        # need to follow the chain, accumulating duration
                        while not zones[parent]['mode'] == 'independent':
                            parent = zones[parent]['follows']
                            pd += _get_duration(zones[parent]['duration'])
                        start =           _get_epoch(zones[parent]['epoch'])
                        stop  = start+pd+ _get_duration(zones[z]['duration'])

                    calendar_times.append( [start, stop] )

                    state_when_active = zones[z]['logic-state-when-active'] if 'logic-state-when-active' in zones[z] else True
                    sys.stdout.flush()

                    wire_id = int(zones[z]['wire-id'])
                    #GPIO.setup(wire_id, GPIO.OUT) # should not be needed
                    logic_state = GPIO.input(wire_id)
                    is_active   = ['Off','On'][logic_state == state_when_active]
                    should_be   = ['Off','On'][z in running]

                    print('zone {}, wire-id {}; is digital state: {}({}) and should be: {}'.format(
                        z, wire_id, logic_state, is_active, should_be))
                    if is_active == should_be: # zone hardware state is current with intended state
                        #print('  zone is current')
                        continue
                    
                    # state doesn't match what it should
                    print('  zone {} should be turned {}'.format(z, should_be))

                    zones[z]['running'] = z in running
                    self._update_zone_in_ldap(self, zones[z])
                
                    print('  dispatching')

                    # send to hardware module
                    zones[z]['action']     = 'calendar'
                    zones[z]['key']        = 'running'

                    self.q.async_q.put_nowait(zones[z])
                    self.event.set()
                    self.event.wait()
                    self.event.clear()

                    if hasattr(self, 'session') and self.session:
                        __ = {z: zones[z]}
                        # we need to wait until session exists before publishing
                        self.session.push_pub('org.blue_labs.misty.zones', __)
            except:
                traceback.print_exc()
            
            # calculate duration until next expected calendar event
            
            # merge overlaps
            final = []
            now   = datetime.datetime.now()
            next_ = None #now.replace(hour=0, minute=0, second=0, microsecond=0)

            #print('before')
            for t in sorted(calendar_times):
                print(t)
            
            try:
                
                for s,e in calendar_times:
                    final.append(s)
                    final.append(e)
                
                final = sorted(set(final))

                #for t in final:
                #    print(' :: {}'.format(t))
                
                for t in final:
                    #print('testing {} > {}'.format(t,now))
                    if t>now:
                        #print('update to {}'.format(t))
                        next_=t
                        break
                
                if not next_: # we've cycled through all events for today so start at the first event tomorrow
                    next_ = final[0]+datetime.timedelta(hours=24)

                # we leave calendar entries for suspended zones in here in case
                # a person unsuspends the zone and it starts running again
                # before the end of the original duration
                print('next event is at {}'.format(next_))
                event_duration = (next_ - now).total_seconds()
            except:
                traceback.print_exc()


    def app(self):
        # set up the relay board initialization
        # calculate what our current state ought to be at this time of day/day of week etc
        # set the current relay states
        # now sit idle until we wake up via event which is either periodic, or triggered via wamp msg
        
        # use the janus.Queue to safely talk across threads
        #self.q = janus.Queue(loop=self.loop)
        event_duration=60
        
        while True:
            try:
                self.event.wait(timeout=event_duration)
                self.event.clear()
            except KeyboardInterrupt:
                self.event.set()
                self._shutdown = True
                break
            
            if self._shutdown:
                break

            try:
                z = self.q.async_q.get_nowait()
            except janus.AsyncQueueEmpty:
                continue
            
            print('received event:\n{}'.format(pprint.pformat(z)))
            sys.stdout.flush()

            action = z['action']
            key    = z['key']
            del z['action']
            del z['key']
            
            #print('pre-list: {}'.format(z))

            #z=z[list(z.keys())[0]]
            
            #print('\x1b[1;33mresponding to {}:{} event: {}\x1b[0m'.format(action,key,z))
            # when event fires, act accordingly, then calculate the duration to the next
            # event. such as a calendar event, or expiration of a timer
            
            # we need a determinate for what type of action happened, manual? calendar? sensor?
            # on, or off? etc. much logic needed
            
            state_when_active = z['logic-state-when-active'] if 'logic-state-when-active' in z else True
            print('set({}): state_when_active: {}'.format(z['zone'], state_when_active))

            # set the default state to off
            future_state = not state_when_active
            
            if action == 'toggle':
                if key in ('manual','suspend'):
                    state =z[key+'-on']

                    if action=='toggle' and key=='manual':
                        future_state = state_when_active if state else not state_when_active
                print('set/toggle({}): future_state set to {}'.format(z['zone'], future_state))
            
            elif action=='calendar':
                if key == 'running':
                    future_state = state_when_active if z['running'] else not state_when_active
                    print('set/calendar({}): future_state set to {}'.format(z['zone'], future_state))
            
            if 'suspend-on' in z and z['suspend-on']:
                # ignore any changes in state, keep the zone turned off
                future_state = not state_when_active
                print('set/suspend({}): future_state set to {}'.format(z['zone'], future_state))
            
            def _state_word(v):
                return ['Off','On'][v == state_when_active]
            
            wire_id = int(z['wire-id'])
            print('set/final({}) wire-id: {}, to {}/{}'.format(z['zone'], wire_id, future_state, _state_word(future_state)))
            
            GPIO.setup(wire_id, GPIO.OUT)
            GPIO.output(wire_id, future_state)
            
            # hardwired status loop, we need a self.zones perhaps?
            for c in (4,17,18,27):
                GPIO.setup(c, GPIO.OUT)
                v = GPIO.input(c)
                print('gpio wire-id:{:>2} is {}'.format(c, _state_word(v)))
        
        self.shutdown()


    def cleanup(self):
        #if production, GPIO.cleanup()
        pass


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    logging.captureWarnings(True)

    # this provider is expecting to be started from the same CWD as crossbar was
    cfg = configparser.ConfigParser()
    cfg.read('provider.conf')

    irl = cfg.get('WAMP', 'site_irl')
    if not irl:
        s = "section [main]; required config option '{}' not found".format('site_irl')

    host,*port = (cfg['authentication']['host']).rsplit(':',1)
    port       = port and port[0] or '389'
    cfg['authentication']['host'] = host
    cfg['authentication']['port'] = cfg.get('authentication', 'port', fallback=port)

    for key in ('valid names','host','userdn','userpassword','base'):
        if not cfg.get('authentication', key):
            s = "section [authentication]; required config option '{}' not found".format(key)
            raise KeyError(s)

    os.environ['TZ'] = cfg.get('main', 'timezone')
    time.tzset()

    # be sure to register an atexit() that closes our gpio channels so we
    # can reopen them cleanly. no need to change states, just close the
    # channels

    misty = Misty(cfg) # this launches the Provider thread
    misty.app()
