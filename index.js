const dns = require('dns');
const net = require('net');
const ip  = require('ipaddr.js');


let timeout = 0;

const axfrReqProloge =
    "\x00\x00" +        /* Size */
    "\x00\x00" +        /* Transaction ID */
    "\x00\x20" +        /* Flags: Standard Query */
    "\x00\x01" +        /* Number of questions */
    "\x00\x00" +        /* Number of answers */
    "\x00\x00" +        /* Number of Authority RRs */
    "\x00\x00";         /* Number of Aditional RRs */

const axfrReqEpiloge =
    "\x00" +            /* End of name */
    "\x00\xfc" +        /* Type: AXFR */
    "\x00\x01";         /* Class: IN */


function inet_ntoa(num){
    const nbuffer = new ArrayBuffer(4);
    const ndv = new DataView(nbuffer);
    ndv.setUint32(0, num);

    const a = [];
    for(let i = 0; i < 4; i++){
        a[i] = ndv.getUint8(i);
    }
    return a.join('.');
}


function decompressLabel(data, offset) {
    const res = { len: 0, name: '' };
    let loffset = offset;
    let tmpoff = 0;

    while (data[loffset] != 0x00) {

        /* Check for pointers */
        if ((data[loffset] & 0xc0) == 0xc0) {
            const newoffset = data.readUInt16BE(loffset) & 0x3FFF;
            const label = decompressLabel(data, (newoffset + 2));
            res.name += label.name;
            loffset += 1;
            break;

        /* Normal label */
        } else {
            tmpoff = loffset + 1;
            res.name += data.toString('utf8', tmpoff, (tmpoff + data[loffset]));
            res.name += '.';
            loffset += data[loffset] + 1;
        }
    }

    res.next = loffset + 1;

    return res;
}


function parseResponse(response, result) {

    let offset = 14;
    let entry, tentry = {};
    const table = [];
    let rclass, rlen;
    const len = response.readUInt16BE(0);

    /* Check for valid length */
    if (response.length != (len + 2))
        return -1;

    /* Check for query response packet */
    if ((response[4] & 0x80) != 0x80)
        return -2;

    /* Check for error code */
    if ((response[5] & 0x0F) != 0)
        return -3;

    const questions = response.readUInt16BE(6);
    const answers = response.readUInt16BE(8);
    const authRRs = response.readUInt16BE(10);
    const aditRRs = response.readUInt16BE(12);

    /* Parse queries */
    for (let x = 0; x < questions; x++) {
        entry = decompressLabel(response, offset);

        result.questions.push({
            name: entry.name,
            type: 'AXFR'
        });

        /* Skip type and class (4 bytes) */
        offset = entry.next + 4;
    };

    /* Parse answers */
    for (let x = 0; x < answers; x++) {
        entry = tentry = {};

        /* Parse entry label */
        entry = decompressLabel(response, offset);
        offset = entry.next;
        entry.name = entry.name;

        /* Get fields after label */
        entry.type = response.readUInt16BE(offset);
        rclass = response.readUInt16BE(offset+2);
        entry.ttl = response.readUInt32BE(offset+4);
        rlen = response.readUInt16BE(offset+8);

        /* Skip classes != INET */
        if (rclass != 0x01) {
            offset += rlen + 10;
            continue;
        }

        /* Parse answer rdata */
        switch (entry.type) {
            /* A Record */
            case 0x01:
                entry.type = 'A';
                entry.a = inet_ntoa(response.readUInt32BE(offset+10));
                break;

            /* NS Record */
            case 0x02:
                entry.type = 'NS';
                entry.ns = decompressLabel(response, (offset + 10)).name;
                break;

            /* CNAME Record */
            case 0x05:
                entry.type = 'CNAME';
                entry.cname = decompressLabel(response, (offset + 10)).name;
                break;

            /* SOA Record */
            case 0x06:
                entry.type = 'SOA';
                tentry = decompressLabel(response, (offset + 10));
                entry.dns = tentry.name;
                tentry = decompressLabel(response, (tentry.next));
                entry.mail = tentry.name;
                entry.serial = response.readUInt32BE(tentry.next);
                entry.refresInterval = response.readUInt32BE(tentry.next+4);
                entry.retryInterval = response.readUInt32BE(tentry.next+8);
                entry.expireLimit = response.readUInt32BE(tentry.next+12);
                entry.minTTL = response.readUInt32BE(tentry.next+16);
                break;

            /* MX Record */
            case 0x0f:
                entry.type = 'MX';
                entry.pref = response.readUInt16BE(offset+10);
                entry.mx = decompressLabel(response, (offset + 12)).name;
                break;

            /* TXT Record */
            case 0x10:
                entry.type = 'TXT';
                len = response[offset+10];
                entry.txt = response.toString('utf8', offset+11, offset+11+len);
                break;

            /* AAAA Record */
            case 0x1c:
                entry.type = 'AAAA';
                var byteArr = new Uint8Array(response.slice(offset+10, offset+26));
                entry.aaaa = ip.fromByteArray(byteArr).toString();
                break;

            /* SPF Record */
            case 0x63:
                entry.type = 'SPF';
                len = response[offset+10];
                entry.txt = response.toString('utf8', offset+11, offset+11+len);
                break;

            /* SRV Record */
            case 0x21:
                entry.type = 'SRV';
                entry.priority = response.readUInt16BE(offset+10);
                entry.weight   = response.readUInt16BE(offset+12);
                entry.port     = response.readUInt16BE(offset+14);
                entry.target   = decompressLabel(response, (offset+16)).name

        }

        delete entry.len;
        delete entry.next;
        result.answers.push(entry);
        offset += rlen + 10;
    };

    return result;
}


dns.resolveAxfrTimeout = function(milis) {
    timeout = milis;
};

dns.resolveAxfr = function(server, domain, callback) {

    const buffers = [];
    const split = domain.split('.');
    const results = { questions: [], answers: [] };
    let responses = [];
    let len = 0;
    let tlen = 0;
    const hostname = server.split(":")[0];
    const port = server.split(":", 2)[1] || 53;

    /* Build the request */
    buffers.push(Buffer.from(axfrReqProloge, 'binary'));
    split.forEach(function(elem) {
        const label = Buffer.from('\00' + elem, 'utf8');
        label.writeUInt8(elem.length, 0);
        buffers.push(label);
    });
    buffers.push(Buffer.from(axfrReqEpiloge, 'binary'));
    const buffer = Buffer.concat(buffers);

    /* Set size and transaction ID */
    buffer.writeUInt16BE(buffer.length - 2, 0);
    buffer.writeUInt16BE(Math.floor((Math.random() * 65535) + 1) , 2);

    /* Connect and send request */
    const socket = net.connect(port, hostname, function(arguments) {
        socket.write(buffer.toString('binary'), 'binary');
    });

    if (timeout)
        socket.setTimeout(timeout);

    /* Parse response */
    socket.on('data', function(data) {

        /* Get expected response length */
        if (len === 0)
            len = data.readUInt16BE(0);

        /* Save response buffers till length is reached */
        responses.push(data);
        tlen += data.length;

        /* Check if we have a complete response */
        if (tlen >= (len +2)) {

            /* Concat the buffers & parse response*/
            buf = Buffer.concat(responses, tlen);
            const tmpBuf = buf.slice(0, (len + 2));
            const res = parseResponse(tmpBuf, results);

            if (typeof res !== 'object') {
                socket.destroy();
                callback(new Error(`Invalid response, ( typeof res !== 'object' ) got ${typeof res}`, res);
            }
        }

        /* Check if response was larger than expected */
        if (tlen > (len+2)) {

            /* Start a new dns response with the remaining data */
            const tmpBuf = buf.slice(len + 2);

            len = tmpBuf.readUInt16BE(0);
            tlen = tmpBuf.length;

            responses = [];
            responses.push(tmpBuf);
        }

        socket.end();


    });

    socket.on('timeout', function timeout() {
        socket.destroy();
        callback(new Error(`Timeout after ${timeout}`));
    });

    socket.on('end', function end() {
        callback(null, results);
    });

    socket.on('error', function error(err) {
        callback(err);
    });

};

dns.axfr = function axfr(server, domain, timeout = 0){
  dns.resolveAxfrTimeout(timeout);
  return new Promise(function (resolve, reject){
    dns.resolveAxfr(server, domain, function callback(err, response){
      if (err) return reject(err);
      return resolve(response);
    });
  });
}

module.exports = dns;
