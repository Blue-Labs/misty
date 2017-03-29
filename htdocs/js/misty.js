'use strict';

// user editable part, if document.location.hostname is not correct
// alter this accordingly, it should be wss:// + hostname + /ws
var wsuri = 'wss://'+document.location.hostname+'/ws';
var wamp_uri_prefix = 'org.blue_labs.misty';
var realm = 'misty';

// that's all. please leave the rest of this to me.
var __version__  = 'version 2.0';
var __author__   = 'David Ford <david@blue-labs.org>'
var __email__    = 'david@blue-labs.org'
var __date__     = '2017-Mar-10 04:33z'
var __license__  = 'Apache 2.0'

var connection, session, principal, ticket,
    wamp_subscriptions = {};

function show_api_errors(errors) {
  var h = $.map(errors, function(v) {
    return '<li>'+v+'</li>';
  });

  h.unshift('<ul>');
  h.push('</ul>');
  h = h.join('\n');

  $('div.api-messages>div').html(h);
  $('div.api-messages').slideDown();

  setTimeout(function(){
    $('div.api-messages').slideUp();
  }, 10000);
}

$(document).ready(function(){
  $('div.api-not-available').show();
  $('div.api-messages').hide();

  page_bindings_wamplogin();
  page_bindings_misty();

  /* WAMP authentication process
   *
   * page loads, connection.open() runs. the callback for connection.open() ensures the
   * login box is faded out when it starts up.
   *
   * if we have recently logged in, our browser will have a cookie and authentication
   * will happen automagically in the background, no challenge-response-authentication
   * needed.
   *
   * if no recent login however, connection.open() will return a challenge and our
   * connection.onchallenge callback (which is a function appropriately named onchallenge)
   * will fire.
   *
   * onchallenge will check to see if our login credentials are available in the input
   * elements. if not, it'll fade in the login box and halt the wamp connection attempt.
   *
   * when the user has entered their credentials, the page binding for the login element
   * will run register_creds which updates our connection parameters and restarts
   * connection.open again. this time everything will repeat but onchallenge will find
   * credentials in our connection paramenters.
   *
   * connection.onchallenge will then submit these values as a response to our challenge.
   *
   * assuming correct credentials, connection.open will then get login details, populate
   * the userbox with info, and slide it into view. subsequently we [re]store our known
   * subscriptions (zones we've edited in this session) then an RPC call is made to
   * trigger a summary of all of the zones being published to us.
   *
   */

  // the WAMP connection to the Router
  connection = new autobahn.Connection({
    url: wsuri,
    realm: realm,
    authmethods: ['cookie','ticket'],
    authid: principal,
    onchallenge: onchallenge
  });

  // fired when connection is established and session attached
  connection.onopen = function (ss, details) {
    fade_out_login();
    $('#api-na-content').html('Waiting for API ...');
    session=ss; // track session

    session.prefix('api', wamp_uri_prefix);

    // wait for the login to fully fade, then fill in our details
    // yeah -- it's the wrong way to do it
    function draw_details(details) {
      setTimeout(function(d) {
        $('.api-not-available').hide();
        slide_in_profile(d);
      }, 750, details);
    }

    function get_role_details() {
      session.call('api:role.lookup').then(
        function(res) { draw_details(res); },
        function(err) { console.log(err);
        if (err.error === 'wamp.error.no_such_procedure') {
            // if no callee registered to handle this, then reschedule
            setTimeout(get_role_details, 5000);
          } else {
            console.warn(err);
            show_api_errors([err]);
          }
        }
      );
    }

    if (details.authextra === undefined) {
      /* cookie auth doesn't get any details from our authenticator, so fetch them */
      get_role_details();
    } else {
      /* cred login comes back fully loaded */
      draw_details(details.authextra);
    }

    // set call back functions per uri
    subscribe({'api:nodes':subscribe_zones});

    // keep trying this until the "no such procedure" error goes away
    function ponderous_attach() {
      session.call('api:rpi.get.revision').then(
        function (res) {
          //console.log('rpi.get.revision called, got',res);

          // trigger [each] provider that is alive to send us their name and a list of zone IDs
          // they service
          session.publish('api:nodes.research', [true]);
        },
        function (error) {
          console.log('error fetching rpi.get.revision',error);
          setTimeout(ponderous_attach, 5000);
        }
      );
    }

    ponderous_attach();
  }

  function onchallenge(session, method, extra) {
    //console.info('challenge received:', session, method, extra);

    if (method === "ticket") {
      // if there's no u/p login cred yet, fade in the login window
      // and ask the user to login. on cred submit, call connection.open()
      // initiator again
      var u,p;
      u = get_login_creds();
      p = u['p'], u=u['u'];

      if (u === undefined || u.length === 0 || p === undefined || p.length === 0) {
        fade_in_login();
        $('#api-na-content').html('Login needed');
        connection.close();
      } else {
        return ticket;
      }
    } else {
      console.warn("i can't handle this challenge method!");
    }
  }

  // fired when connection was lost (or could not be established)
  connection.onclose = function (reason, details) {
    // firefox is having issues after clicking logout
    //console.log(reason, details);

    if (details.reason !== 'wamp.close.normal') {
      console.log("Connection lost: " + reason);
      console.log(details);
    }

    // how odd. chrome gets "closed" on logout, firefox gets "lost"
    if (reason === 'closed' || details.reason && details.reason === 'wamp.close.normal') {
      // someone logged out our session, either it was us, or another person logged in
      // as us somewhere else
      $('div.user-box div.logged-in-profile').hide('slide', function() {
        $.each(['department','username'], function(i,e) {
          $('div.user-box div.logged-in-profile span.'+e).empty();
        });
        $('div.user-box div.logged-in-profile span.userpic').css({backgroundImage:''});
      });

      fade_in_login();
    }

    if (details.reason === 'wamp.error.authentication_failed') {
      console.warn('wamp.error.authentication_failed');
      console.warn(details.message);
      $('#api-na-content').html('Login needed');
      $('div.user-box').addClass('auth-fail');
      var error = details.message.match(/args=\[['"]?(.+?)['"]?\],/)[1];
      show_api_errors([error]);
    }

    remove_sensitive_content();

    $('.api-not-available').show();
    $('.zone-page').css({opacity:.2});
    $('.menu-bar li').css({opacity:.2});
  }

  connection.open();
});

// fade in the login is called when we need the user to input their credentials
function fade_in_login() {
  $('div.user-box').css({zIndex:102});
  $('div.user-box div.anonymous-login').slideDown(500, function() {
    $('div.user-box div.please-log-in').slideDown(500, function() {
      function fadeRunner(i) {
        if (i < 95) {
          $('div.user-box').css({'background-color':'rgba(224,240,255,'+i/100+')'});
          setTimeout(fadeRunner, 3, i+1);
        }
      }
      fadeRunner(0);
    });
  })
}

// fade in the login is called when we need the user to input their credentials
function fade_out_login() {
  function fadeRunner(i) {
    if (i > 0) {
      $('div.user-box').css({'background-color':'rgba(224,240,255,'+i/100+')'});
      setTimeout(fadeRunner, 3, i-1);
    }
  }
  fadeRunner(95);
  $('div.user-box div.please-log-in').slideUp(250)
  $('div.user-box').css({zIndex:100});
  $('div.user-box div.anonymous-login').slideUp(250);
}

function slide_in_profile(d) {
  $('div.user-box div.logged-in-profile').find('span.userpic').css({
    backgroundImage:'url(data:image/png;base64,'+d.jpegPhoto[0],
  })
  .parent().find('span.department').text(d.department)
  .parent().find('span.username').text(d.displayName)
  .parent().toggle('slide', {direction:'right'});
}

function register_creds() {
  var u,p;
  u         = get_login_creds()
  ticket    = u['p'];
  principal = u['u'];

  $('div.user-box').removeClass('failshadow');
  $('#api-na-content').html('Logging in');

  // this = line is a workaround for a wamp-js bug. the authid gets lost :/
  //console.info(connection._options.authid);
  connection._options.authid = principal;
  connection.open();
}

function get_login_creds() {
  var u = $('div.user-box input#username').val(),
      p = $('div.user-box input#password').val();

  return {'u':u, 'p':p};
}

function subscribe(newsubs) {
  $.each(newsubs, function(_topic, _function) {
    if (!wamp_subscriptions.hasOwnProperty(_topic)) {
      //console.log('subscribing to',_topic);
      session.subscribe(_topic, _function)
      .then(
        function(subscription) {
          //console.log('sub good',subscription);
          wamp_subscriptions[_topic] = _function;
        },
        function(error) {
          console.error('subscription failed',error);}
       );
    } else {
      //console.log('already subscribed to',_topic)
    }
  })
}

// we have to resubscribe to all of our subs if crossbar router is restarted
// invisible WTFness evidenced by published events never appearing to us
// surely our wamp module should handle that for us :P
function resubscribe() {
  var promises = [], p;
  $.each(wamp_subscriptions, function(uri,f) {
    console.info('subscribing to',uri);
    p = session.subscribe(uri, f);
    promises.push(p);
  });

  $.when(promises).done(function(res,err,progress) {
    console.info(res,err,progress);
    if (err !== undefined ) {
      show_api_errors([err]);
    }
  });
}

function page_bindings_wamplogin(){
  $(document).on('click', 'div.user-box input[type=button]#login', function(ev) {
    ev.preventDefault();
    register_creds();
  });

  $(document).on('keyup', 'div.user-box input', function(ev) {
    ev.preventDefault();
    if (ev.which !== 13) { return; }
    register_creds();
  });

  $(document).on('click', 'div.user-box img.logout.button', function(ev) {
    ev.preventDefault();
    // warning, this logs out all of your sessions in the SAME browser
    session.leave('wamp.close.logout');
    connection.close();
    wamp_subscriptions={};

    document.cookie = 'cbtid'+'=; expires=Thu, 01 Jan 1970 00:00:01 GMT;';
  });

  $(document).on('click', 'span.zone-program-description', function(ev) {
    ev.stopPropagation();
    var descrip = $(this).text();
    var i = $('<textarea />');
    i.val(descrip);
    $(this).html(i);
    i.focus();
  });

  $(document).on('keydown click', 'span.zone-program-description > textarea', function(ev) {

    ev.stopImmediatePropagation();

    if (ev.type=='click') {
      return;
    }

    if (ev.type=='keydown' && ev.which==13) {
      ev.preventDefault();

      var zid = $(ev.target)
        .closest('span.zone-id-descrip-row')
        .find('span.zone-program-number')
        .text();
      var descrip = $(ev.target).val();

      session.call('api:zone.set.attribute', [{'zone':zid, 'attribute':'zone-description', 'value':descrip},])
        .then(function(res) { $(ev.target).parent().text(descrip); },
              function(err) { console.log('result is err:', err); }
      );
      return;
    }
  });
}

//
// stop drop and roll, this is the end of the login stuff
//
//

// these are the non-login page event bindings
function page_bindings_misty() {
  $(document).on('click', '.menu button', function(event) {
    event.preventDefault();
    $(this).blur();
    name = $(this).text();

    if (name === 'Add zone') { add_zone(); return; }
  });

  $(document).on('click', '.menu-button', function(event) {
    event.preventDefault();
    var c = $(this).parent()
           .find('.circle')
           .toggleClass('open')


    // close the others
    $.each($('.circle.open'), function(i,e) {
      e = $(e)
      if (!e.is(c)) { $(e).removeClass('open'); }
    });

    $(this).closest('.circular-menu')
           .map(function() {
             if (c.hasClass('open') === true) { $(this).css({'z-index':2}); }
             else { $(this).css({'z-index':1}); }
           })
  });

  $(document).on('keyup change', '.new_zone input,.new_zone select', function(event) {
    $(this).removeClass('bad-input-value');
  });

  $(document).on('change', '[name=nz_mode]', function(event) {
    var v = $(this).val();

    var nzf = $('[name=nz_follows]');
    if (['parallel','chained'].indexOf(v) > -1) {
      nzf.removeAttr('disabled');
    } else {
      nzf.attr('disabled','disabled');
    }

    var nzf = $('[name=nz_epoch]');
    if (['static','parallel','chained'].indexOf(v) > -1) {
      nzf.attr('disabled','disabled');
    } else {
      nzf.removeAttr('disabled');
    }

    var nzf = $('[name=nz_duration_type]');
    if (['static'].indexOf(v) > -1) {
      nzf.attr('disabled','disabled');
    } else {
      nzf.removeAttr('disabled');
    }

    var nzf = $('[name=nz_duration]');
    if (['static'].indexOf(v) > -1) {
      nzf.attr('disabled','disabled');
    } else {
      nzf.removeAttr('disabled');
    }
  });

  $(document).on('change', '[name=nz_trigger_type]', function(event) {
    var v = $(this).val();
    var nzt = $('[name=nz_trigger]');
    var nze = $('[name=nz_epoch]');

    if      (v === 'time of day')  { nzt.attr('disabled','disabled'); }
    else if (v === 'interval')     { nzt.attr('type','text'); nzt.removeAttr('disabled'); $('[name=nz_trigger_suffix]').text(''); }
    else if (v === 'days of week') { nzt.attr('type','text'); nzt.removeAttr('disabled'); $('[name=nz_trigger_suffix]').text(''); }
    else if (v === 'days of month'){ nzt.attr('type','text'); nzt.removeAttr('disabled'); $('[name=nz_trigger_suffix]').text(''); }
    else if (v === 'sensor')       { nzt.attr('type','number'); nzt.removeAttr('disabled'); $('[name=nz_trigger_suffix]').text('%'); }
    else if (v === 'rainfall')     { nzt.attr('type','number'); nzt.removeAttr('disabled'); $('[name=nz_trigger_suffix]').text('in'); }
  });

  $(document).on('click', '.circle a', function(event) {
    event.preventDefault();

    var zid = $(this).closest('li.zone-program-entry').find('.zone-program-number').text();
    var b32_cn = $(this).closest('div.pi-node').find('.pi-node-cn').attr('b32_cn');

    if (this.name === 'delete') { delete_zone(b32_cn, zid); }
    if (this.name === 'enable') { toggle_zone_enable(b32_cn, zid); }
    if (this.name === 'manual') { toggle_zone(b32_cn, zid, 'manual'); }
    if (this.name === 'suspend') { toggle_zone(b32_cn, zid, 'suspend'); }
  });
}

/* base32 encode/decode SUBJ with a head and tail of underscore(s)
*/
function b32encode(subj) {
}

function b32decode(subj) {
}

/* this function used to get all the zone data in one lump
   now we iterate all the zones and subscribe to them. after
   we subscribe to them, we'll request zone data for each

   if we don't have permission to view zones or devices, the
   crossbar router will deny our subscription

   as each answer comes in, create the initial object in
   pi_nodes and mark it pending. as each set of zones is
   received, mark it so. at the end of each zone we receive,
   check if all pi-nodes have been marked received. if so,
   regenerate all the html nodes.
   */
var pi_nodes = {}, xx;

function subscribe_zones(args) {
  var pi_node = Object.keys(args[0])[0],
      name    = args[0][pi_node]['real name'],
      zones   = args[0][pi_node]['zones'],
      topic,
      new_subs= {};

  console.log('zones to create:',zones);

  pi_nodes[name] = {state:'pending',
                    zonesHTML:undefined,
                    zones:{},
                    timer:setTimeout(function(pn) {mark_received(pn);}, 10000, name)}; // set default
                                                            // timer to fire in 10s.
                                                            // if we have no permission to this
                                                            // object, we'll never get responses
  for (var z in zones) {
    var zn = zones[z];
    pi_nodes[name]['zones'][zn]={};
  }

  /*
  pi_nodes['aaaaa']={state:'received',
                     zonesHTML:undefined,
                     zones:{
                      1:{state:'received',
                         'objectClass': ['mistyZone'],
                         'zone': 11,
                         'pi-node': 'Bramble yard',
                         'trigger': '', 'trigger-type': 'time of day', 'mode': 'independent',
                         'duration-type': '', 'enabled': true, 'programmed': true,
                         'epoch': '07:30', 'duration': '30m', 'logic-state-when-active': false,
                         'wire-id': 4, 'zone-description': 'Tgaraje', 'suspend-on': false, 'running': false},
                      2:{state:'received',
                         'objectClass': ['mistyZone'],
                         'zone': 12,
                         'pi-node': 'Bramble yard',
                         'trigger': '', 'trigger-type': 'time of day', 'mode': 'independent',
                         'duration-type': '', 'enabled': true, 'programmed': true,
                         'epoch': '07:30', 'duration': '30m', 'logic-state-when-active': false,
                         'wire-id': 4, 'zone-description': 'Tfuzz patch', 'suspend-on': false, 'running': false},
                     },
                     'real name': 'aaaa test node',
                     'meta': {'node-description': 'Test test'},
                     'b32uri': 'org.blue_labs.misty.node._____mjqwg23zmfzgiidhmfzmizloom______'};
  */

  topic = 'api:node.'+pi_node;
  new_subs[topic]=receive_pi_node_data;

  $.each(zones, function(i, zone) {
    topic = 'api:node.'+pi_node+'.'+zone;
    new_subs[topic]=receive_zone_data;
  });

  subscribe(new_subs);
}

function receive_pi_node_data(data) {
  console.info('receive_pi_node_data()',data);
  data = data[0];
  var pi_node = data['real name'];
  //console.log('receive_pi_node_data('+pi_node+')',data);

  pi_nodes[pi_node]['real name']=data['real name'];
  pi_nodes[pi_node]['meta']=data['meta'];
  pi_nodes[pi_node]['b32uri']=data['b32uri'];
  pi_nodes[pi_node]['state']='received';

  // update our timeout. we should expect all our zone data
  // within a few milliseconds at this point. we'll send our
  // receiver a special value to indicate all zones on this
  // node should be marked as received when the timer fires
  clearTimeout(pi_nodes[pi_node]['timer']);
  pi_nodes[pi_node]['timer'] = setTimeout(function(pn) {mark_received(pn);}, 500, pi_node);
}


// collect data and store in our local object
function receive_zone_data(data) {
  console.info('receive_zone_data()',data);

  // if this function is called with 'false', skip to checking pending status
  if (data !== false) {
    data = data[0];
    var pi_node = data['pi-node'];
    var zone    = data['zone'];

    pi_nodes[pi_node]['zones'][zone] = data;
    pi_nodes[pi_node]['zones'][zone]['state']='received';
  }

  //console.log('received zone',zone);
  check_all_received();
}

function mark_received(pi_node) {
  console.info('marking received for',pi_node);

  for (var z in pi_nodes[pi_node]['zones']) {
    pi_nodes[pi_node]['zones'][z]['state'] = 'received'
  }

  pi_nodes[pi_node]['state'] = 'received';

  try {
    clearTimeout(pi_nodes[pi_node]['timer']);
    delete pi_nodes[pi_node]['timer'];
  } catch(e){};

  check_all_received();
}

function check_all_received() {
  var finished = true, imf;

  for (var pn in pi_nodes) {
    if (pi_nodes[pn]['state'] !== 'received') {
      finished = false;
      break;
    }

    imf=true;
    for (var z in pi_nodes[pn]['zones']) {
      if (pi_nodes[pn]['zones'][z]['state'] !== 'received') {
        finished = false;
        imf=false;
        break;
      }
    }

    if (imf == true) {
      try {
        clearTimeout(pi_nodes[pn]['timer']);
      } catch(e){};
    }

  }

  if (finished === true) {
    // clear/reset a master timer on pi_nodes so we only redraw zone data once
    // no matter how many threads fired through here
    try {
      clearTimeout(pi_nodes['redraw timer']);
      delete pi_nodes['redraw timer'];
    } catch(e) {};

    // we're not waiting on anything, we can set this short
    pi_nodes['redraw timer'] = setTimeout(redraw_zones, 150);
  }
  return finished;
}

function redraw_zones() {
  /*
  try {
    clearTimeout(pi_nodes['redraw timer']);
    delete pi_nodes['redraw timer'];
  } catch(e) {};
  */

  var _d, _dd=[], _ul, _li, _html, zi, b32_cn;

  console.log('redrawing zones');

  $.each(pi_nodes, function(pn, pn_dict) {
    if (pn == 'redraw timer') { return; }

    console.log(pn,pn_dict);
    zi = Object.keys(pn_dict['zones']).sort();

    _ul = $('<ul class="pi-nodes-list"></ul>');
    $.each(zi, function(n, z) {
      _li = generate_zone_html(z, pn_dict['zones'][z]);
      _ul.append(_li);
    });

    b32_cn = pn_dict['b32uri'].split('.')[4];
    _d = $('<div class="pi-node"><p class="pi-node-cn" b32_cn="'+b32_cn+'">'+pn+'</p></div>');
    _d.append(_ul);
    _dd.push(_d);
  });

  // we should do this better so we're not laggy waiting for nodes to finish sending us data.
  // build and display zones as soon as they arrive
  $('div.pi-nodes-box').empty().append(_dd);
}

function generate_zone_html(zn, zone) {
  // if this zone doesn't already exist, create it
  // otherwise, ensure stats and indicators are updated
  // lastly, if mode of zone is 'deleted', then remove it

  var existing = $('span.zone-program-number').filter(function() {
    return $(this).text() == zone.zone;
  }).closest('.zone-program-entry');

  //if (zone['mode']==='deleted' && existing != undefined) {
  //  $(existing).remove();
  //  return;
  //}

  var _html, restricted=false;
  if (zone['zone-description'] == undefined) {
    zone['zone-description'] = 'restricted';
    restricted=true;
  }

  // create single zone LI element; grab the template and populate it
  _html = document.querySelector('#zone-template');
  _html.content.querySelector('.zone-program-number').textContent=zn;
  _html.content.querySelector('.zone-program-description').textContent=zone['zone-description'];
  _html = document.importNode(_html.content, true);
  _html = $(_html);

  // calculate icon positions by dividing equally and place on a point around the circle
  // i've done this programatically so i don't have to recalculate positions every time
  // i change icon count or circle location
  var objs = _html.find('.circle a,.circle span')
  $.each(objs, function(i,e) {
    $(e).css({left:(50 -4 - 40*Math.cos(-0.5 * Math.PI - 2*(1/objs.length)*i*Math.PI)).toFixed(5) + "%",
               top:(50 -4 + 40*Math.sin(-0.5 * Math.PI - 2*(1/objs.length)*i*Math.PI)).toFixed(5) + "%"
              });
  })

  if (restricted===true) {
    _html.find('.zone-program-description').addClass('pi-zone-restricted');
  }


  /*
  // find where to insert it based on numerical zone id
  var zone_ids = {}, slice_pos = -1;

  // this no longer works with multiple zones, refactor
  $.each($('.zone-program-number'), function(i, e) {
    var zn = parseInt($(e).text());
    zone_ids[i]=zn;
    if (zn > zone.zone && (slice_pos==-1 || zn < slice_pos)) {
      slice_pos = zn; console.log(zn, slice_pos);
    }
  });

  if (slice_pos < 0) {
    origin.append(_html);
    origin = origin.children('li').last();
  } else {
    origin.children('li').first().before(_html);
    origin = origin.filter('ul').find('li:nth-child('+slice_pos+')');
  }*/

  var e;

  /* zone enabled */
  e = _html.find('.zone-program-status')
            .find('.enable-icon')
  if (zone.enabled===true) {
    e.addClass('status-active');
    _html.find('.circle a[name=enable]')
          .addClass('on');
  } else {
    e.removeClass('status-active');
    _html.find('.circle a[name=enable]')
          .removeClass('on');
  }

  /* scheduled per calendar */
  e = _html.find('.zone-program-status')
                .find('span.schedule-icon')

  if (zone.programmed===true) {
    e.addClass('status-active');
  } else if (zone.manual_on===true) {
    console.warning('not yet employed');
    e.addClass('manual'); // make it greenish instead (find a better way to indicate a manual run)
  } else {
    e.removeClass('status-active').removeClass('manual');
  }

  /* zone is running */
  e = _html.find('.zone-program-status')
            .find('.running-icon')
  if (zone.running===true) {
    e.addClass('status-active');
  } else {
    e.removeClass('status-active');
  }

  /* zone manually activated */
  e = _html.find('.zone-program-status')
            .find('.running-icon');
            console.log()
  if (zone['manual-on']===true) {
    e.addClass('status-active');
    _html.find('.running-suspend').removeClass('on');
    _html.find('.running-manual').addClass('on');
    _html.find('.circle a[name=manual]')
          .addClass('on');
  } else {
    _html.find('.running-manual').removeClass('on');
    _html.find('.circle a[name=manual]')
          .removeClass('on');
  }

  /* manually suppressed */
  e = _html.find('.zone-program-status')
            .find('running-icon')
  if (zone['suspend-on']===true) {
    e.css({visibility:'visible'});
    _html.find('.running-manual').removeClass('on');
    _html.find('.running-suspend').addClass('on');
    _html.find('.circle a[name=suspend]')
          .addClass('on');
  } else {
    e.css({visibility:'hidden'});
    _html.find('.running-suspend').removeClass('on');
    _html.find('.circle a[name=suspend]')
          .removeClass('on');
  }

  return _html;
}


/* input box has been made visible, wait for duration and disappear. if <cr> pressed within duration, save value */
function get_duration(callee) {
  var _this = callee.closest('span').find('.get-duration');
  var _path = callee.closest('.zone-program-entry').find('.timeout-path');

  _this.addClass('active'); // make it visible
  _path.addClass('active'); // start the timer

  _path.on('webkitTransitionEnd', function(ev) {
    ev.preventDefault();
    if (ev.originalEvent.propertyName !== 'stroke-dashoffset') { return; }
    _path.off();
    _this.off();

    _path.removeClass('active');
    _this.removeClass('active');
    set_duration(callee, _this.find('input'));
  });

  _this.on('keyup', function(ev) {
    if (ev.keyCode === 13) {
      _this.off();
      _path.off();

      _this.removeClass('active');
      _path.removeClass('active');
      set_duration(callee, _this.find('input'));
    }
  });
}

var tick;
function set_duration(callee, _this) {
  var duration = $(_this).val(), mx;
  if (duration !== undefined && duration.length > 0 ) {
    [duration,mx] = duration.toLocaleLowerCase().match(/\d+([mhd]?)/);
    duration = parseInt(duration);

    if (mx === 'm') { duration *= 60; }
    if (mx === 'h') { duration *= 3600; }
    if (mx === 'd') { duration *= 86400; }
  }

  tick=_this;
  console.log(_this);

  var zid = $(_this).closest('.zone-program-entry').find('.zone-program-number').text();
  var b32_cn = $(this).closest('div.pi-node').find('.pi-node-cn').attr('b32_cn');
  var state = !callee.hasClass('on');

  // set the duration on the currently running zone
  session.call('api:node.'+b32_cn+'.zone.set.state', [{'toggle':callee.attr('name'), 'zone':zid, 'state':state, 'end-time':duration},])
    .then(function(res) { /*console.log('result is:', res);*/ },
          function(err) { console.log('result is err:', err); }
  );
}

function toggle_zone_enable(b32_cn, zid) {
  var state = !$('.zone-program-number')
                .filter(function() {return $(this).text()==zid})
                .closest('.zone-program-entry')
                .find('.zone-program-status')
                .find('.enable-icon')
                .hasClass('status-active');

  session.call('api:node.'+b32_cn+'.zone.set.enable', [{'zone':zid, 'enabled':state},])
    .then(function(res) { /*console.log('result is:', res);*/ },
          function(err) { console.log('result is err:', err); }
  );
}

function toggle_zone(b32_cn, zid, toggle) {
  var e = $('.zone-program-number')
            .filter(function() {return $(this).text()==zid})
            .closest('.zone-program-entry')
            .find('.circle a[name='+toggle+']'),
      state = !e.hasClass('on');

  if (state) {
    get_duration(e);
  } else {
    console.log(toggle,zid);
    session.call('api:node.'+b32_cn+'.zone.set.state', [{'toggle':toggle, 'zone':zid, 'state':false},])
      .then(function(res) { console.log('result is:', res); },
            function(err) { console.log('result is err:', err); }
    );
  }
}

function delete_zone(b32_cn, zid) {
  var hellyes = confirm('Delete this zone?');

  if (hellyes === true) {
    session.call('api:node.'+b32_cn+'.zone.delete', [{'zone':zid}])
      .then(function(res) { /*console.log('result is:', res);*/ },
            function(err) { console.log('result is err:', err); }
    );
  }
}

function get_zone_ids(cb) {
  var zids={}
  for (var n=0; n<=31; n++) { zids[n] = ''; }

  session.call('api:zones.get.zone_ids')
      .then(function(res) {// console.log('result is:', res);
        $.each(res, function(n,t) {
          zids[t[0]]=t[1];
        });
        cb(zids);
      },
            function(err) { console.log('result is err:', err); }
  );
}

function get_wire_ids(cb) {
  var ids={}
  for (var n=0; n<=27; n++) { ids[n] = ''; }

  session.call('api:zones.get.wire_ids')
      .then(function(res) { //console.log('result is:', res);
        cb(res);
      },
            function(err) { console.log('result is err:', err); }
  );
}

function add_zone() {
  var known_zones, zids;

  var _html = $('<div class="new_zone" title="Add new zone">                               \
    <p class="sbc-model">&nbsp;</p> \
    <label for="nz_zone">Zone ID</label>                                                   \
    <select class="nz_zone" name="nz_zone"/>                                               \
    </select>                                                                              \
    <label for="nz_wire_id">Wire ID</label>                                                \
    <select class="nz_wire_id" name="nz_wire_id" alt="Physical pin number"/>               \
    </select>                                                                              \
    <select class="nz_module" name="nz_module" title="&bull;Digital Out (output is HIGH or LOW) such as a relay\n&bull;Digital In (input is HIGH or LOW) sensor">\
      <option value="digital-output">Digital Out</option>                               \
      <option value="digital-input">Digital In</option>                                 \
    </select>                                                                              \
    <br/>                                                                                  \
    <label for="nz_">Description</label>                                                   \
    <input type="text"  class="nz_description"   name="nz_description"/>                   \
    <br/>                                                                                  \
    <label for="nz_enabled">Enabled</label>                                                \
    <input type="checkbox" class="nz_enabled"    name="nz_enabled" checked="checked" />    \
    <label for="nz_enabled">Module</label>                                                 \
    <label for="nz_inverted_signal">Inverted signal</label>                                \
    <input type="checkbox" class="nz_inverted_signal"    name="nz_signal" />    \
    <br/>                                                                                  \
    <label for="nz_mode">Mode</label>                                                      \
    <select class="nz_mode" name="nz_mode" title="&bull;independent operates without regard to other nodes\n&bull;parallel operates at the same time as the designated leader\n&bull;chained operates immediately following the designated leader"> \
      <option value="static">static</option> \
      <option value="independent">independent</option> \
      <option value="parallel">parallel</option>    \
      <option value="chained">chained</option>    \
    </select>\
    <label for="nz_follows">follows:</label>                                      \
    <select name="nz_follows" disabled="disabled" title="If parallel or chained, what zone will this one run after?"> \
    </select> \
    <br/>\
    <label for="nz_trigger_type">Trigger</label>                                      \
    <select name="nz_trigger_type" disabled="disabled" title="What triggers a run cycle of this zone? examples:\n&bull;every day at 5am\n&bull;every 3 days\n&bull;on Tuesdays\n&bull;on the 15th\n&bull;when below 10% moisture content">\
      <option value="time of day">time of day</option>    \
      <option value="interval">interval</option>    \
      <option value="days of week">day(s) of week</option>    \
      <option value="days of month">day(s) of month</option>    \
      <option value="sensor">[future...]</option>    \
    </select>\
    <label for="nz_trigger">at/on:</label>                                      \
    <input type="text"  class="nz_trigger"  name="nz_trigger" disabled="disabled" /><span name="nz_trigger_suffix"></span>            \
    <br/>\
    <label for="nz_epoch">Start time</label>                                      \
    <input type="time"  class="nz_epoch"    name="nz_epoch" disabled="disabled" title="What time of day to start zone? example: 5:30am" value="05:30" />                            \
    <br/>\
    <label for="nz_duration_type">Duration type</label>                                      \
    <select name="nz_duration_type" disabled="disabled" title="How long before zone shuts off? examples:\n&bull;after 10 minutes\n&bull;after 5 gallons\n&bull;after reaching 20% moisture content">\
      <option value="time">time</option>        \
      <option value="metered">[future...]</option>        \
      <option value="sensor">[future...]</option>        \
    </select>\
    <label for="nz_duration">duration</label>                                      \
    <input type="text"  class="nz_duration"      name="nz_duration" disabled="disabled" />                          \
    </div> \
  ');

  get_zone_ids(function(data){
    var opts = $.map(data, function(t,n) {
      if (t.length === 0) {
        return '<option value="'+n+'">'+n+'</option>';
      } else {
        return '<option value="'+n+'" disabled="disabled">'+n+'</option>';
      }
    });

    opts = opts.join('');

    // append to zone options
    $(_html.filter('div').find('.nz_zone')[0]).append(opts);
  });

  get_wire_ids(function(data){
    var ids = data[0],
        rpi = data[1],
        pin_map = data[2];

    var t = $(_html.filter('div').find('p.sbc-model')[0]);
    t.text(rpi.model);

    var opts = $.map(pin_map, function(phys_pin,gpio_pin) {
      if (phys_pin === null || ids.indexOf(parseInt(gpio_pin)) >= 0) {
        return '<option value="'+gpio_pin+'" disabled="disabled">gpio.'+gpio_pin+'->pin.'+phys_pin+'</option>';
      } else {
        return '<option value="'+gpio_pin+'">gpio.'+gpio_pin+'->pin.'+phys_pin+'</option>';
      }
    });

    opts = opts.join('');

    // append to zone options
    $(_html.filter('div').find('[name=nz_wire_id]')[0]).append(opts);

    // now do the opposite, for all pins that are in use, add them to the 'follows' select
    // actually, this needs to show a list of zones, not gpio map :-}
    opts = $.map($('.zone-program-number'), function(e) { var v = $(e).text(); return '<option value="'+v+'">'+v+'</option>'; } );
    /*opts = $.map(pin_map, function(phys_pin,gpio_pin) {
      if (ids.indexOf(parseInt(gpio_pin)) >= 0) {
        return '<option value="'+gpio_pin+'">gpio.'+gpio_pin+'->pin.'+phys_pin+'</option>';
      }
    });*/

    opts = opts.join('');

    // append to zone options
    $(_html.filter('div').find('[name=nz_follows]')[0]).append(opts);


  });


  // attempt to guess next zone number
  // run an interval timer check & indication to see if someone else adds the same zone # behind our back
  // draw a modal box, gray out behind it, should have two buttons, <ok> and <cancel>
  // .on() the ok, push to api
  _html.dialog({
    modal: true,
    dialogClass: "no-close",
    width: "36rem",
    buttons: [
      {
        text: "OK",
        click: function() {
          // collect form info and submit it

          var nz = new Object();
          nz.zone          = parseInt($('[name=nz_zone]').val());
          nz.wire_id       = parseInt($('[name=nz_wire_id]').val());
          nz.description   = $('[name=nz_description]').val();
          nz.enabled       = $($('[name=nz_enabled]')[0]).val() === 'on';
          nz.mode          = $('[name=nz_mode]').val();
          nz.follows       = parseInt($('[name=nz_follows]').val());
          nz.trigger_type  = $('[name=nz_trigger_type]').val();
          nz.trigger       = $('[name=nz_trigger]').val();
          nz.epoch         = $('[name=nz_epoch]').val();
          nz.duration_type = $('[name=nz_duration_type]').val();
          nz.duration      = $('[name=nz_duration]').val();
          var nzh = $(this);

          save_new_zone(nz, function(data) {
            if (data === true) {
              nzh.dialog("close");
              nzh.dialog("destroy");
            } else {
              console.log('fail for:',data);
              // parse to find each input box with bad data, add effect
              $.each(data, function(n,v) {
                var e=v[1],
                    m=v[2];

                console.info(e);
                $('[name=nz_'+e).addClass('bad-input-value');
              });
            }
          });
        }
      },

      {
        text: "Cancel",
        click: function() {
          $(this).dialog("close");
          $(this).dialog("destroy");
        }
      },
    ]
  });
}

function save_new_zone(data, cb) {
  session.call('api:zones.add', [data])
    .then(function(res) { console.log('result is:',res);     cb(res); },
          function(err) { console.log('result is err:',err); cb(err); }
          );
}

// future
function wamp_cb_touchup() {
}
