'use strict';

// usage:
//   let verified = yield esfEmailsVerify.checkEmails(
//     ['email@domain.tld'],
//     ['http://some:auth@proxyserver.tld'], // list of proxy servers to use* null means direct connection
//     {dns: {timeout: 20000}} // options**
//   );
//
//   >>> {'email@domain.tld': true | false | null | <Error> }
//    + false: email is invalid
//    + true: email is valid
//    + null: MX server does not support email verification
//    + instanceof Error: which error occured processing verification
//
// *  Only 'http:' protocol and HTTP CONNECT method is currently supported.
//      make sure proxy servers allow tunneling to port 25 (usually restricted on public proxies).
//
// ** Funnel optimization options: { 
//   dns: { //DNS requests options
//     maxSimReq: maximum simultaneous requests (5),
//     chunkDelay: delay between chunks of simultaneous requests [msec] (100 msec),
//     timeout: timeout for resolving each entry [msec] (10 sec)
//   },
//
//   smtp: { //SMTP requests options
//     maxEmailsPerReq: maximum allowed number of emails to test using one request (16),
//     maxSimSameMx: maximum simultaneous connections to same MX (1),
//     sameMxChunkDelay: delay between chunks of simultaneous requests to same MX [msec] (100 msec),
//     //sameMxTimeout: timeout for each request to same MX [msec] (10 sec),
//
//     maxSimMx: maximum simultaneous requests to different MXs (30),
//     mxChunkDelay: delay between chunks of simultaneous requests to different MX servers [msec] (100 msec),
//
//     connectTimeout: timeout of TCP connection establishment [msec] (10 sec),
//
//     maxSimProxies: maximum simultaneous proxy servers to ask.
//       if result is acquired, no more proxy servers are asked (5),
//
//     proxyChunkDelay: delay between chunks of simultaneous proxy requests [msec] (100 msec),
//     proxyTimeout: timeout for socket or each proxy request connection [msec] (10 sec),
//     proxyEmailTimeout: timeout for single email SMTP check in same connection [msec] (800 msec)
//   }
// }

if (!global.esfunctional || esfunctional < 1.0600) {
  console.error('This module requires `esfunctional` framework version >= 1.6.0');
  return;
}

let url = require('url');
let dns = require('dns');
let net = require('net');
let http = require('http');

let S = module.exports;

S.resolveMxAction = (domain, opts) => () => (
  dns [promisify]('resolveMx')(domain)
  [timeout](opts.dns.timeout || 10000, 'timeout resolving MX records')
  [catcha](() => [])
);

module.exports.checkEmails = (emails, proxies, opts) => spawn(function*(arg) {
  if (!opts) opts = {};
  if (!opts.dns) opts.dns = {};
  if (!opts.smtp) opts.smtp = {};

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
    [mapValues]((ents, domain) => S.resolveMxAction(domain, opts))

    [all]({
      size: opts.dns.maxSimReq || 5,
      delay: opts.dns.chunkDelay || 100
    })
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
    domains [map](domain => entsByDomain[domain] [map]('email')) [flatten]() [chunk](opts.smtp.maxEmailsPerReq || 16)
  ));

  let resultsByMx = yield emailsByMx [mapValues]((mxEmailsChunks, mx) => () => (
    mxEmailsChunks [map]((mxEmails) => S.processMxCheckAction(mx, mxEmails, proxies, opts, arg[status])) [all]({
      size: opts.smtp.maxSimSameMx || 1,
      delay: opts.smtp.sameMxChunkDelay || 100,
      //timeout: opts.smtp.sameMxTimeout || 10000,
      //timeoutMsg: 'timeout checking emails'
    })
  )) [all]({
    size: opts.smtp.maxSimMx || 30,
    delay: opts.smtp.mxChunkDelay || 100
  });

  let allResults = resultsByMx [map]((arr, mx) => arr [map]((obj) => {
    if (!obj || obj instanceof Error) return emailsByMx[mx][flatten]().map(email => [email, obj]) [fromPairs]();
    return obj;
  })) [flatten]() [extendArray]();

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

S.processMxCheckAction = (mx, emails, proxies, opts, allStatus) => () => spawn(function*() {
  let results = yield index(proxies || ['']) [map]((proxyIndex, proxy) => () => spawn(function*() {
    let socket;
    let result = {};

    if (proxy) {
      let proxyParams = url.parse(proxy);
      if (proxyParams.protocol !== 'http:') throw new Error(`${mx} protocols of all proxies are not supported`);

      let httpParams = ({
        method: 'CONNECT',
        path: `${mx}:25`
      }) [extend](proxyParams [pick]('hostname', 'port', 'auth'));

      let req = http.request(httpParams);

      let evtConnect = (
        req [event]('connect', 'error')
        [timeout](opts.smtp.connectTimeout || 10000, `timeout connecting to mailserver ${mx}`)
      );

      req.end();
      let connected = yield evtConnect;
      socket = connected.args[1];
    } else {
      socket = net.createConnection(25, mx);
    };

    let established = false;

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

    try {
      let inviteCode = yield readCode();
      if (!inviteCode) throw new Error(`${mx} tunneling refused from all proxies`);
      if (inviteCode !== '220') throw new Error(`${mx} bad SMTP invitation code`);

      established = true;

      yield write(`HELO mail.example.org\n`);
      if ((yield readCode()) !== '250') throw new Error(`${mx} bad reply after HELO`);

      yield write(`MAIL FROM:<name@example.org>\n`);
      if ((yield readCode()) !== '250') throw new Error(`${mx} bad reply after MAIL`);

      yield write(`RCPT TO:<somehuhknowninvalidemail${emails[0]}>\n`);
      let badCode = yield readCode();
      if (badCode === '250') throw 'unknown';
      if (badCode !== '550') throw 'unknown'; //throw new Error(`${mx} bad reply after invalid email check: ${badCode}`);

      for (let email of emails) {
        yield write(`RCPT TO:<${email}>\n`);
        let code = yield readCode();
        if (code === '250') result[email] = true;
        else if (code === '550') result[email] = false;
        else throw new Error(`${mx} bad reply after check request: ${code}`);
      }
    } catch (err) {
      result = err === 'unknown' ? null : err;
    }

    if (established) {
      yield write(`QUIT\n`);
      yield readCode();
    }

    socket.end();

    return result;
  })) [all]({
    race: true,
    chunk: opts.smtp.maxSimProxies || 5,
    delay: opts.smtp.proxyChunkDelay || 100,
    timeout: (opts.smtp.proxyTimeout | 10000) + (opts.smtp.proxyEmailTimeout | 800) * emails.length,
    timeoutMsg: `${mx} timeout`
  }) [catcha]();

  allStatus.processed += emails.length;
  allStatus.onProgress.forEach(spawnAction);

  return results;
});
