'use strict';

if (!global.esfunctional || esfunctional < 1.0500) {
  console.error('This module requires `esfunctional` framework version >= 1.5');
  return;
}

let url = require('url');
let dns = require('dns');
let net = require('net');
let http = require('http');

let S = module.exports;

S.resolveMxAction = (domain) => () => dns [promisify]('resolveMx')(domain);

module.exports.checkEmails = (emails, proxies) => spawn(function*(arg) {
  arg[status].processed = 0;
  arg[status].total = emails.length;
  arg[status].onProgress = [];

  let entsByDomain = (
    emails [map](email => url.parse(`mailto:${email}`)
    [pick]('host', 'auth')
    [extend]({email: email}))
    [groupBy]('host')
  );

  let mxsByDomain = yield (
    entsByDomain
    [mapValues]((ents, domain) => S.resolveMxAction(domain))
    [all]({size: 5, delay: 10, timeout: 10000, timeoutMsg: 'timeout resolving MX records'})
  );

  let mxByDomain = mxsByDomain [mapValues]((mxs) => (
    mxs [reduce]((mx1, mx2) => (
      !mx1.priority ? mx2 :
      !mx2.priority ? mx1 :
      mx1.priority > mx2.priority ? mx2 :
      mx1
    ), {exchange: ''}).exchange || ''
  ));

  let domainsByMx = mxByDomain [invertBy]();
  delete domainsByMx[''];

  let emailsByMx = domainsByMx [mapValues]((domains) => (
    domains [map](domain => entsByDomain[domain] [map]('email')) [flatten]() [chunk](10)
  ));

  let resultsByMx = yield emailsByMx [mapValues]((mxEmailsChunks, mx) => () => (
    mxEmailsChunks [map]((mxEmails) => S.processMxCheckAction(mx, mxEmails, proxies, arg[status])) [all]({
      size: 20,
      delay: 100,
      timeout: 10000,
      timeoutMsg: 'timeout checking emails'
    })
  )) [all]({size: 10, delay: 100});

  let allResults = ({}) [extendArray](
    resultsByMx [map](obj => ({}) [extendArray](obj))
    [map]((obj) => (!obj || obj instanceof Error) ? {} : obj)
  );

  return allResults;
});

S.readLineUtf8 = (socket, buffer) => spawn(function*() {
  if (!buffer) throw new Error('need buffer');
  if (buffer.eof) return null;
  let data = buffer.cut;

  do {
    if (data) {
      let pos = data.indexOf('\n');

      if (pos >= 0) {
        let result = data.substr(0, pos);
        buffer.cut = data.substr(pos + 1);
        return result;
      }
    } else {
      buffer.cut = '';
    }

    let readEvt = socket [event](['data', 'end'], 'error');
    let readEvtReply = yield readEvt;
    if (readEvtReply.event === 'end') {buffer.eof = true; return null;}
    data = buffer.cut += readEvtReply.data.toString();
  } while (true);
});

S.processMxCheckAction = (mx, emails, proxies, allStatus) => () => spawn(function*() {
  let results = yield (proxies || [null]) [map]((proxy) => () => spawn(function*() {
    let socket;
    let result = {};

    if (proxy) {
      let req = http.request({
        host: proxy.match(/^[^:]*/) [0],
        port: (proxy.match(/:(.*)$/) || []) [1],
        method: 'CONNECT',
        path: `${mx}:25`
      });

      let evtConnect = (
        req [event]('connect', 'error')
        [timeout](5000, `timeout connecting to mailserver ${mx}`)
      );

      req.end();
      let connected = yield evtConnect;
      socket = connected.args[1];
    } else {
      socket = net.createConnection(25, mx);
    };

    try {
      let buffer = {};
      let write = socket [promisify]('write');
      let read = () => S.readLineUtf8(socket, buffer);

      let readCode = () => spawn(function*() {
        while (true) {
          let line = yield read();
          //console.log(`${mx}: ${line}`);
          if (!line) return null;
          let match = line.match(/(\d{3})\s/);
          if (match) return match[1];
        }
      });

      if ((yield readCode()) !== '220') throw new Error(`${mx} bad invitation code`);

      yield write(`HELO mail.example.org\n`);
      if ((yield readCode()) !== '250') throw new Error(`${mx} bad reply after HELO`);

      yield write(`MAIL FROM:<name@example.org>\n`);
      if ((yield readCode()) !== '250') throw new Error(`${mx} bad reply after MAIL`);

      yield write(`RCPT TO:<somehuhknowninvalidemail${emails[0]}>\n`);
      let badCode = yield readCode();
      if (badCode === '250') return null;
      if (badCode !== '550') throw new Error(`${mx} bad reply after invalid email check: ${badCode}`);

      for (let email of emails) {
        yield write(`RCPT TO:<${email}>\n`);
        let code = yield readCode();
        if (code === '250') result[email] = true;
        else if (code === '550') result[email] = false;
        else throw new Error(`${mx} bad reply after check request: ${code}`);
      }

      yield write(`QUIT\n`);
      if ((yield readCode()) !== '221') throw new Error(`${mx} not clean exit`);
    } catch (err) {
      socket.end();
      throw err;
    }

    return result;
  })) [all]({race: true, chunk: 5, timeout: 1000 * emails.length, timeoutMsg: `${mx} timeout`}) [catcha]();

  allStatus.processed += emails.length;
  allStatus.onProgress.forEach(spawnAction);

  return results;
});
