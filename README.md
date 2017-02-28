# Misty
All examples in this project will use the hostname *misty.blue-labs.org* and
the realm *misty*. My web content is all served via nginx and I'll use the
standard default settings and locations per nginx. Defaults locations as per
the [Crossbar.io](https://crossbar.io) examples are also used as much as possible.
Both the WAMP router and provider are run as user *non-root*. Pick any
unprivileged username you feel like and remember to adjust instructions as
needed.

The following requirements will pull in additional packages. The below list
should get everything for you.

## Common definitions
| Term | Definition |
|------|------------|
| app dir | /etc/nginx/sites/somehostname.com/app/ |
| AIO | Analog IO |
| DIO | Digital IO |
| pi node | a unique textual reference you assign per Raspberry Pi |
| zone | a single IO unit, such as a GPIO pin that drives a relay |
| router | a WAMP router, the Crossbar.IO is used in this project |



## Requirements

### Overall requirements
* a WAMP setup, I use the crossbario router and python modules
* a webserver
* an LDAP database
* Python 3 (all current versions, 3.2 to 3.6 work fine)
* one or more RaspberryPI units. even the A models can handle this, I use a pi B, pi2 B+,
and pi3 B+
  * you'll need one or more relay boards. you can use either `high` or `low`
    triggered. Misty has logic to correctly handle both on a per-zone basis.
    This means you can have mixed sets of relay boards on the same Pi
  * [future] Analog output
  * [future] Digital or Analog sensors

## Install steps
1. Build an appropriate RaspberryPi server and attach a GPIO controlled
   relay board. At least **provider.py** will be run on it. You can run your
   LDAP and nginx services elsewhere as long as the RaspberryPi can reach it
1. Clone this repo
2. Install/modify an *LDAP* server as applicable
3. Install/modify an *nginx* or web server as applicable, install included
   web content
4. Test the LDAP server and web server
  * if you've configured your LDAP server as needed, you should be able to
    run `ldapsearch -xLLL 'zone=3'` and get results matching the bottom of
    the included **misty.ldif**
5. Install software using disto tools or python tools. test by attempting to
   run **crossbar start** in the app directory, and **python -u provider.py**
   on your pi. Ensure you have all necessary python modules before
   continuing
6. Start the WAMP router in the app directory, **crossbar start**, and leave
   it running
7. Start the provider, **python -u provider.py** in the same directory as
   provider.conf. Local files are not used so it's not really important
   where it's placed. I happen to use the same (although empty) directory
   structure on my pi as I do my web server so it's easy to rsync files.
   **/etc/nginx/sites/hostname.com/app/**

### Python modules
*  crossbar
*  watchdog
*  setproctitle
*  treq
*  PyNaCl
*  py-ubjson
*  cbor
*  u-msgpack-python
*  lmdb
*  psutil
*  sdnotify
*  shutilwhich
*  Pygments
*  mistune
*  Jinja2
*  PyTrie
*  autobahn
*  sdnotify

### Arch Linux
When using pacman or pb/pkgbuilder (for AUR), install these
* pb -S python-crossbar python-watchdog python-setproctitle python-pnacl python-u-msgpack python-psutil python-pygments python-mistune python-jinja python-autobahn

Some packages don't [yet] exist in AUR, so pip or easy install these:
* easy_install treq py-ubjson cbor lmdb sdnotify


### LDAP
You'll need to set up an LDAP server (OpenLDAP assumed).  Accomplish the
following steps as applicable.  If you don't have an LDAP server, all steps
are necessary.

1. Install openldap, follow appropriate distribution instructions to have a
running service.
2. Modify your slapd.conf per included file
3. Copy the two schema files into your schema directory
4. Rebuild your inline configuration
  1. systemctl stop slapd
  2. rm -rf /etc/openldap/slapd.d/*
  3. su - ldap -s /bin/bash -c "slaptest -f /etc/openldap/slapd.conf -F
  /etc/openldap/slapd.d/; slapindex"
5. Restart slapd
6. Modify the included ldif file, you probably don't want me as the only
   user -- it's there as an example. A single Pi node and three zones
   have been included as an example as well
6. Create your DIT for Misty using included ldif file. It's already in
   superior order so you can use slapadd or ldapadd
7. Set password(s) as applicable


## Let's Encrypt setup
Obtain and install your SSL certificates normally, after installing, make
sure appropriate daemons/users have access to the files. We're using
extended file attributes instead of file permissions because a lot of web
servers, SQL servers, etc, bitch like cranky fucks if they don't have
exclusive permissions to keys and it's fucking lame to make a copy of keys
for every service that does this.

```
setfacl -m g:ldap:rx /etc/letsencrypt/{live,archive}
setfacl -m g:ldap:r /etc/letsencrypt/archive/misty.blue-labs.org/privkey*.pem

setfacl -m g:non-root:rx /etc/letsencrypt/{live,archive}
setfacl -m g:non-root:r /etc/letsencrypt/archive/misty.blue-labs.org/privkey*.pem
```


## nginx

```
worker_processes  auto;
error_log /var/log/nginx/error.log debug;

events {
    worker_connections  1024;
}

http {
    sendfile on;

    ssl_ciphers                 "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256";
    ssl_protocols               TLSv1.2;
    ssl_prefer_server_ciphers   on;
    ssl_session_cache           shared:SSL:10m;
    ssl_session_timeout         5m;
    ssl_session_tickets         off;
    ssl_stapling                on;
    ssl_stapling_verify         on;

    ssl_password_file           /etc/nginx/passphrases;

    resolver 107.170.82.162 valid=300s;
    resolver_timeout 5s;

    add_header Strict-Transport-Security "max-age=31536000; includeSubdomains; preload";
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;

    upstream websocket {
        server 127.0.0.1:8080;
    }

    map $http_upgrade $connection_upgrade {
        default upgrade;
        '' close;
    }

    server {
        listen 80 default_server;
        return 301 https://$host$request_uri;
    }

    server {
        ssl                     on;
        listen                  443 ssl http2;
        server_name             misty.blue-labs.org;

        ssl_certificate         /etc/letsencrypt/live/misty.blue-labs.org/fullchain.pem;
        ssl_certificate_key     /etc/letsencrypt/live/misty.blue-labs.org/privkey.pem;
        ssl_trusted_certificate /etc/letsencrypt/live/misty.blue-labs.org/fullchain.pem;

        location / {
           root                 sites/misty.blue-labs.org/htdocs/;
           index                index.html;
        }        

        location /ws {
            #proxy_set_header        X-Forwarded-For $proxy_add_x_forwarded_for;
            #proxy_set_header        X-Forwarded-Proto $scheme;

            proxy_http_version  1.1;
            proxy_set_header    Host $host:8080;
            proxy_set_header    X-Forwarded-For $remote_addr;
            proxy_set_header    Upgrade $http_upgrade;
            proxy_set_header    Connection $connection_upgrade;
            proxy_pass          https://websocket;
        }
    }
}
```


## Systemd unit files
These files are presented as if both the services will be running on the
RaspberryPi. Adjust as needed if you run the WAMP router somewhere else.

**/etc/systemd/system/misty-crossbar.service**
```
[Unit]
Description=Misty service
After=network.target

[Service]
User=non-root
Environment=PYTHONUNBUFFERED=1
WorkingDirectory=/etc/nginx/sites/misty.blue-labs.org/app/
ExecStart=/usr/bin/crossbar start

[Install]
WantedBy=multi-user.target
```

**/etc/systemd/system/misty-app.service**
```
[Unit]
Description=Misty APP
After=network.target
After=misty-crossbar.service

[Service]
User=non-root
PermissionsStartOnly=true
Environment=PYTHONUNBUFFERED=1
WorkingDirectory=/etc/nginx/sites/misty.blue-labs.org/app/
ExecStartPre=/usr/bin/setfacl -m u:non-root:rw /dev/gpiomem
ExecStart=/usr/bin/python provider.py

[Install]
WantedBy=multi-user.target
```


## Crossbar
### manual start
```
cd $projectdirectory/app/
crossbar start
```

You will see a few dozen lines of output. There should be no errors, no
tracebacks, no indications of exceptions and when idle, the last few lines
should resemble this:
```
2017-02-27T23:55:40-0500 [Controller  13395] Router 'worker-001': component 'component-001' started
2017-02-27T23:55:40-0500 [Router      13400] Loaded 0 cookie records from file. Cookie store has 0 entries.
2017-02-27T23:55:40-0500 [Router      13400] File-backed cookie store active /etc/nginx/sites/misty.blue-labs.org/app/.crossbar/cookies.dat
2017-02-27T23:55:40-0500 [Router      13400] Loading server TLS key from /etc/letsencrypt/live/misty.blue-labs.org/privkey.pem
2017-02-27T23:55:40-0500 [Router      13400] Loading server TLS certificate from /etc/letsencrypt/live/misty.blue-labs.org/cert.pem
2017-02-27T23:55:40-0500 [Router      13400] Loading server TLS chain certificate from /etc/letsencrypt/live/misty.blue-labs.org/chain.pem
2017-02-27T23:55:40-0500 [Router      13400] Using explicit TLS ciphers from config
2017-02-27T23:55:40-0500 [Router      13400] OpenSSL is using elliptic curve prime256v1 (NIST P-256)
2017-02-27T23:55:40-0500 [Router      13400] Site (TLS) starting on 8080
2017-02-27T23:55:40-0500 [Controller  13395] Router 'worker-001': transport 'transport-001' started
```


## Provider
The **provider.py** file runs on your raspberrypi machine. **provider.py** and
**provider.conf** should be located in the same directory.


## To-Do

* zone map is applicable per zone, it should redraw depending on which zone
  the user is currently working with (mouse over? clickable? zone choice by
  tab?)
* put zone type image behind zone id
* need zone type indicated somewhere (control or sensor)
* pipe wrench - this editable area is for annotating information about the
  zone such as the zone map; drawing dripper locations and their GPH
* calendar - modify/view zone run times in a calendar view
* where to email alerts and reports
* for zone activity, time+duration, show estimated GPH per zone over time
* sensors; moisture, rainfall, internet:rainfall, light, water level
* icons for the zone type; sprinkler, valve, water pump, lights, etc
* nudge app.calendar() to become aware of the UI events for *manual* and
  *suspend* if a time frame is specified. subsequently, add an RPC to fetch
  calendar events so the web UI can show them accordingly on the applicable
  zone
* add user authorization to make each pi node have a *manager-user*
  attribute and a *viewer-user* attribute so *pi nodes* can be configured
  to only be manageable by certain users, and read-only viewable by certain
  users. in the absence of these attributes, the *pi node* will be
  manageable by all users.
* increase granularity of user authentication to make each zone per-user
  manageable. in the absence of listed users, the zone is manageable by
  all users permitted to manage the given *pi node*
