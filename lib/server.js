'use strict';

const assert = require('assert');
const https = require('https');
const util = require('util');
const pow = require('proof-of-work');
const debug = require('debug')('hc:server');
const Buffer = require('buffer').Buffer;
const WBuf = require('wbuf');
const OBuf = require('obuf');

const hackchain = require('hackchain-core');

const MAX_BODY_SIZE = 256 * 1024;
const PROOF_OF_WORK_SIZE = 4 * 128 * 1024;
const PROOF_OF_WORK_N = 11;
const PROOF_OF_WORK_INTERVAL = 7;

function Server(options) {
  assert(options.ssl && typeof options.ssl === 'object',
         'Server: `config.ssl` is required');
  https.Server.call(this, options.ssl, this._requestHandler);

  assert.equal(typeof options.db, 'string', 'Server: `config.db` is required');

  this.chain = new hackchain.Chain(options.db, options.chain);
  this.pool = new hackchain.Pool(this.chain, options.pool);

  this.version = hackchain.version;

  // Initialize proof-of-work
  const powOptions = options['proof-of-work'];
  assert(powOptions && typeof powOptions === 'object',
         'Server: `config["proof-of-work"] is required');
  assert.equal(typeof powOptions.size, 'number',
               'Server: `config["proof-of-work"].size` is required');
  assert.equal(typeof powOptions.n, 'number',
               'Server: `config["proof-of-work"].n` is required');
  assert.equal(typeof powOptions.complexity, 'number',
               'Server: `config["proof-of-work"].complexity` is required');
  assert.equal(typeof powOptions.interval, 'number',
               'Server: `config["proof-of-work"].interval` is required');

  this.pow = new pow.Verifier({
    size: powOptions.size,
    n: powOptions.n,
    complexity: powOptions.complexity
  });
  this.powCounter = {
    success: 0,
    total: 0
  };

  this.powInterval = setInterval(() => {
    const counter = this.powCounter;

    debug(`proof-of-work reset, ` +
          `hit=${counter.success} total=${counter.total}`);
    counter.success = 0;
    counter.total = 0;
    this.pow.reset();
  }, powOptions.interval);
}
util.inherits(Server, https.Server);
exports.Server = Server;

Server.prototype.init = function init(callback) {
  this.chain.init((err) => {
    if (err)
      return callback(err);

    this.pool.start();
    callback(null);
  });
};

function RouteHandler(server, req, res) {
  this.server = server;
  this.req = req;
  this.res = res;
}

RouteHandler.prototype.run = function run() {
  const req = this.req;
  if (req.method === 'GET') {
    if (req.url === '/' || req.url === '/v1/')
      return this.getInfo();

    if (req.url === '/help' || req.url === '/v1/help')
      return this.getHelp();

    if (req.url === '/unspent' || req.url === '/v1/unspent')
      return this.getUnspent();

    let match = req.url.match(/^\/v1\/(tx|block)\/([a-f0-9]{64})$/);
    if (match !== null) {
      if (match[1] === 'block')
        return this.getBlock(match[2]);
      else if (match[1] === 'tx')
        return this.getTX(match[2]);
    }

    match = req.url.match(/^\/v1\/tx\/([a-f0-9]{64})\/block$/);
    if (match !== null)
      return this.getTXBlock(match[1]);

    match = req.url.match(/^\/v1\/tx\/([a-f0-9]{64})\/(\d+)\/spentby$/);
    if (match !== null)
      return this.getTXSpentBy(match[1], match[2]);
  } else if (req.method === 'POST') {
    let match = req.url.match(/^\/v1\/tx\/([a-f0-9]{64})$/);
    if (match !== null)
      return this.postTX(match[1]);
  }

  this.respond(404, { error: 'Not found' });
};

RouteHandler.prototype.respond = function respond(statusCode, body) {
  const res = this.res;

  res.writeHead(statusCode, {
    server: 'hackchain/' + this.server.version,
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST'
  });
  res.end(JSON.stringify(body));
};

RouteHandler.prototype.withBody = function withBody(callback) {
  const req = this.req;

  if (req.headers['content-type'] !== 'application/json')
    return callback(new Error('Invalid Content-Type value'));

  let chunks = '';
  req.on('data', (chunk) => {
    chunks += chunk;
    if (chunks.length > MAX_BODY_SIZE) {
      req.pause();
      return callback(new Error('Body overflow'));
    }
  });

  req.once('end', () => {
    let data;

    try {
      data = JSON.parse(chunks);
    } catch (e) {
      return callback(e);
    }

    callback(null, data);
  });
};

RouteHandler.prototype.getInfo = function getInfo() {
  this.respond(200, {
    version: this.server.version,
    lastBlock: this.server.chain.lastBlock.toString('hex'),
    nextBlockIn: (this.server.pool.nextBlockIn() / 1000) | 0,
    nextCoinbaseIn: (this.server.pool.nextCoinbaseIn() / 1000) | 0,
    'proof-of-work-complexity': this.server.pow.complexity
  });
};

RouteHandler.prototype.getHelp = function getHelp() {
  this.respond(200, {
    '/': 'information about server and last block',
    '/help': 'this message',
    '/unspent': 'list of currently unspent transactions',
    '/v1/block/(hash)': 'GET block data',
    '/v1/tx/(hash)': 'GET/POST transaction data',
    '/v1/tx/(hash)/block': 'GET the hash of transaction\'s block',
    '/v1/tx/(hash)/(output index)/spentby': 'GET the hash of spending tx'
  });
};

RouteHandler.prototype.getUnspent = function getUnspent() {
  this.server.chain.getUnspentTXs(16 * 1024, (err, txs) => {
    if (err)
      return this.respond(500, { error: err.message });

    this.respond(200, txs.map((tx) => {
      return {
        hash: tx.hash.toString('hex'),
        index: tx.index,
        value: tx.value.toString(10)
      };
    }));
  });
};

RouteHandler.prototype.getBlock = function getBlock(hash) {
  this.server.chain.getRawBlock(Buffer.from(hash, 'hex'), (err, block) => {
    if (err)
      return this.respond(404, { error: 'Block not found' });

    this.respond(200, {
      block: block.toString('hex')
    });
  });
};

RouteHandler.prototype.getTX = function getTX(hash) {
  this.server.chain.getRawTX(Buffer.from(hash, 'hex'), (err, tx) => {
    if (err)
      return this.respond(404, { error: 'TX not found' });

    this.respond(200, {
      tx: tx.toString('hex')
    });
  });
};

RouteHandler.prototype.getTXBlock = function getTXBlock(hash) {
  this.server.chain.getTXBlock(Buffer.from(hash, 'hex'), (err, hash) => {
    if (err)
      return this.respond(404, { error: 'TX not found' });

    this.respond(200, {
      block: hash.toString('hex')
    });
  });
};

RouteHandler.prototype.getTXSpentBy = function getTXSpentBy(hash, index) {
  const rawHash = Buffer.from(hash, 'hex');
  this.server.chain.getTXSpentBy(rawHash, parseInt(index, 10), (err, hash) => {
    if (err)
      return this.respond(404, { error: 'TX not found' });

    this.respond(200, {
      tx: hash.toString('hex')
    });
  });
};

RouteHandler.prototype.postTX = function postTX(hash) {
  const proof = this.req.headers['x-proof-of-work'];
  if (!proof)
    return this.respond(400, { error: 'X-Proof-Of-Work header is required' });

  const verifier = this.server.pow;
  const match = proof.match(/^(\d+):([0-9a-f]{64})$/i);
  if (match === null || (match[1] | 0) !== verifier.complexity) {
    return this.respond(400, {
      error: 'X-Proof-Of-Work header value is must be formatted as ' +
             `\`${verifier.complexity}:32-byte nonce in hex\``
    });
  }

  const counter = this.server.powCounter;

  counter.total++;
  if (!verifier.check(Buffer.from(match[2], 'hex'))) {
    return this.respond(400, {
      error: 'Invalid X-Proof-Of-Work nonce'
    });
  }

  counter.success++;

  this.withBody((err, body) => {
    if (err)
      return this.respond(400, { error: err.message });

    if (!body.tx || typeof body.tx !== 'string' || /[^a-f0-9]/.test(body.tx))
      return this.respond(400, { error: '`body.tx` must be a hex string' });

    let tx;
    try {
      tx = Buffer.from(body.tx, 'hex');
    } catch (e) {
      return this.respond(400, { error: e.message });
    }

    const buf = new OBuf();
    buf.push(tx);

    try {
      tx = hackchain.TX.parse(buf);
    } catch (e) {
      return this.respond(400, { error: e.message });
    }

    this.server.pool.accept(tx, (err) => {
      if (err)
        return this.respond(400, { error: err.message });

      this.respond(200, { ok: true });
    });
  });
};

Server.prototype._requestHandler = function _requestHandler(req, res) {
  const handler = new RouteHandler(this, req, res);

  handler.run();
};
