

var        ellipsis = "\u2026",
        reTime = /^((?:1[89]|2\d)?\d\d)(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])([01]\d|2[0-3])(?:([0-5]\d)(?:([0-5]\d)(?:[.,](\d{1,3}))?)?)?(Z|[-+](?:[0]\d|1[0-2])([0-5]\d)?)?$/;
function stringCut(str, len) {
    if (str.length > len)
        str = str.substring(0, len) + ellipsis;
    return str;
}


// <editor-fold defaultstate="collapsed" desc=" Stream ">
function Stream(enc, pos) {
    if (enc instanceof Stream) {
        this.enc = enc.enc;
        this.pos = enc.pos;
    } else {
        this.enc = enc;
        this.pos = pos;
    }
}
Stream.prototype.get = function(pos) {
    if (pos === undefined)
        pos = this.pos++;
    if (pos >= this.enc.length)
        throw 'Requesting byte offset ' + pos + ' on a stream of length ' + this.enc.length;
    return this.enc.charCodeAt(pos);
    //return this.enc[pos];
};
Stream.prototype.derDump = function(start, end) {
    return this.enc.substring(start, end);
};
Stream.prototype.hexDigits = "0123456789ABCDEF";
Stream.prototype.hexByte = function(b) {
    return this.hexDigits.charAt((b >> 4) & 0xF) + this.hexDigits.charAt(b & 0xF);
};
Stream.prototype.isASCII = function(start, end) {
    for (var i = start; i < end; ++i) {
        var c = this.get(i);
        if (c < 32 || c > 176)
            return false;
    }
    return true;
};
// <editor-fold defaultstate="collapsed" desc=" Parse ">
Stream.prototype.parseStringISO = function(start, end) {
    var s = "";
    for (var i = start; i < end; ++i)
        s += String.fromCharCode(this.get(i));
    return s;
};
Stream.prototype.parseStringUTF = function(start, end) {
    var s = "";
    for (var i = start; i < end; ) {
        var c = this.get(i++);
        if (c < 128)
            s += String.fromCharCode(c);
        else if ((c > 191) && (c < 224))
            s += String.fromCharCode(((c & 0x1F) << 6) | (this.get(i++) & 0x3F));
        else
            s += String.fromCharCode(((c & 0x0F) << 12) | ((this.get(i++) & 0x3F) << 6) | (this.get(i++) & 0x3F));
    }
    return s;
};
Stream.prototype.parseStringBMP = function(start, end) {
    var str = "", hi, lo;
    for (var i = start; i < end; ) {
        hi = this.get(i++);
        lo = this.get(i++);
        str += String.fromCharCode((hi << 8) | lo);
    }
    return str;
};
Stream.prototype.parseTime = function(start, end, shortYear) {
    var s = this.parseStringISO(start, end),
            m = reTime.exec(s);
    if (!m)
        return "Unrecognized time: " + s;
    if (shortYear) {
        // to avoid querying the timer, use the fixed range [1970, 2069]
        // it will conform with ITU X.400 [-10, +40] sliding window until 2030
        m[1] = +m[1];
        m[1] += (m[1] < 70) ? 2000 : 1900;
    }
    s = m[1] + "-" + m[2] + "-" + m[3] + " " + m[4];
    if (m[5]) {
        s += ":" + m[5];
        if (m[6]) {
            s += ":" + m[6];
            if (m[7])
                s += "." + m[7];
        }
    }
    if (m[8]) {
        s += " UTC";
        if (m[8] !== 'Z') {
            s += m[8];
            if (m[9])
                s += ":" + m[9];
        }
    }
    return new Date(s);
};
Stream.prototype.parseInteger = function(start, end) {
    var v = this.get(start),
            neg = (v > 127),
            pad = neg ? 255 : 0,
            len,
            s = '';
    // skip unuseful bits (not allowed in DER)
    //while (v == pad && start < end)
    //    v = this.get(++start);
    len = end - start;
    if (len === 0)
        return neg ? -1 : 0;
    if (len > 8) {
        for (var i = start; i < end; i++) {
            var b = this.get(i).toString(16);
            if (b.length % 2 > 0)
                b = "0" + b;
            s += b;
        }
        return s;
    }
    // decode the integer
    if (neg)
        v = v - 256;
    v = v * Math.pow(256, (end - start) - 1);
    for (var i = start + 1; i < end; i++) {
        v += this.get(i) * Math.pow(256, (end - i) - 1);
    }
    return v;
};
Stream.prototype.parseBitString = function(start, end, maxLength) {
    var obj = new BitString(this.enc.substring(start + 1, end), this.get(start));
    return obj;
    // not use
    var unusedBit = this.get(start),
            lenBit = ((end - start - 1) << 3) - unusedBit,
            intro = "(" + lenBit + " bit)\n",
            s = "",
            skip = unusedBit;
    for (var i = end - 1; i > start; --i) {
        var b = this.get(i);
        for (var j = skip; j < 8; ++j)
            s += (b >> j) & 1 ? "1" : "0";
        skip = 0;
        if (s.length > maxLength)
            return intro + stringCut(s, maxLength);
    }
    return intro + s;
};
Stream.prototype.parseOctetString = function(start, end, maxLength) {
    return this.enc.substring(start, end);
    if (this.isASCII(start, end))
        return stringCut(this.parseStringISO(start, end), maxLength);
    var len = end - start,
            s = "(" + len + " byte)\n";
    maxLength /= 2; // we work in bytes
    if (len > maxLength)
        end = start + maxLength;
    for (var i = start; i < end; ++i)
        s += this.hexByte(this.get(i));
    if (len > maxLength)
        s += ellipsis;
    return s;
};
Stream.prototype.parseOID = function(start, end, maxLength) {
    var s = '',
            n = new Int10(),
            bits = 0;
    for (var i = start; i < end; ++i) {
        var v = this.get(i);
        n.mulAdd(128, v & 0x7F);
        bits += 7;
        if (!(v & 0x80)) { // finished
            if (s === '') {
                n = n.simplify();
                var m = n < 80 ? n < 40 ? 0 : 1 : 2;
                s = m + "." + (n - m * 40);
            } else
                s += "." + n.toString();
            if (s.length > maxLength)
                return stringCut(s, maxLength);
            n = new Int10();
            bits = 0;
        }
    }
    if (bits > 0)
        s += ".incomplete";
    return s;
};
// </editor-fold>
// </editor-fold>

// <editor-fold defaultstate="collapsed" desc=" ASN1 ">
function ASN1(stream, header, length, tag, sub) {
    if (!(tag instanceof ASN1Tag))
        throw 'Invalid tag value.';
    this.stream = stream;
    this.header = header;
    this.length = length;
    this.tag = tag;
    this.sub = sub;
}

ASN1.prototype.encode = function() {
    return this.stream.enc.substring(this.posStart(), this.posEnd());
};

ASN1.prototype.toString = function() {
    return this.stream.enc.substring(this.posStart(), this.posEnd());
};

ASN1.prototype.className = function() {
    var asn = this;
    var result;
    trusted.objEach(ASN1TagClass, function(v, n) {
        if (asn.tag.class === v)
            result = n;
    });
    if (result === undefined)
        result = "Unknown tag class";
    return result;
};
ASN1.prototype.typeName = function() {
    var asn = this;
    var result;
    if (asn.tag.class === ASN1TagClass.UNIVERSAL)
        trusted.objEach(ASN1TagType, function(v, n) {
            if (asn.tag.number === v)
                result = n;
        });
    if (result === undefined)
        result = "Unknown tag type";
    return result;
};
ASN1.prototype.parseSimpleType = function(number, maxLength) {
    if (number === undefined)
        return null;
    if (maxLength === undefined)
        maxLength = Infinity;
    var content = this.posContent(),
            len = Math.abs(this.length);
    switch (number) {
        case 0x01: // BOOLEAN
            return (this.stream.get(content) === 0) ? false : true;
        case 0x0A: // ENUM
        case 0x02: // INTEGER
            return this.stream.parseInteger(content, content + len);
        case 0x03: // BIT_STRING
            return this.stream.parseBitString(content, content + len, maxLength);
        case 0x04: // OCTET_STRING
            return this.toString().substring(this.header);
            //case 0x05: // NULL
        case 0x06: // OBJECT_IDENTIFIER
            return this.stream.parseOID(content, content + len, maxLength);
            //case 0x07: // ObjectDescriptor
            //case 0x08: // EXTERNAL
            //case 0x09: // REAL
            //case 0x0A: // ENUMERATED
            //case 0x0B: // EMBEDDED_PDV
        case 0x10: // SEQUENCE
        case 0x11: // SET
            return this.toString().substring(this.header);
        case 0x0C: // UTF8String
            return stringCut(this.stream.parseStringUTF(content, content + len), maxLength);
        case 0x12: // NumericString
        case 0x13: // PrintableString
        case 0x14: // TeletexString
        case 0x15: // VideotexString
        case 0x16: // IA5String
            //case 0x19: // GraphicString
        case 0x1A: // VisibleString
            //case 0x1B: // GeneralString
            //case 0x1C: // UniversalString
            return stringCut(this.stream.parseStringISO(content, content + len), maxLength);
        case 0x1E: // BMPString
            return stringCut(this.stream.parseStringBMP(content, content + len), maxLength);
        case 0x17: // UTCTime
        case 0x18: // GeneralizedTime
            return this.stream.parseTime(content, content + len, (number === 0x17));
    }
    return null;
};

ASN1.prototype.content = function(maxLength) { // a preview of the content (intended for humans)
    if (this.tag === undefined)
        return null;
    if (maxLength === undefined)
        maxLength = Infinity;
    var content = this.posContent(),
            len = Math.abs(this.length);
    if (!this.tag.isUniversal()) {
        return this.stream.parseOctetString(content, content + len, maxLength);
    }
    return this.parseSimpleType(this.tag.number, maxLength);
};
//ASN1.prototype.toString = function() {
//    return this.typeName() + "@" + this.stream.pos + "[header:" + this.header + ",length:" + this.length + ",sub:" + ((this.sub === null) ? 'null' : this.sub.length) + "]";
//};
ASN1.prototype.toPrettyString = function(indent) {
    if (indent === undefined)
        indent = '';
    var s = indent + this.typeName() + " @" + this.stream.pos;
    if (this.length >= 0)
        s += "+";
    s += this.length;
    if (this.tag.constructed)
        s += " (constructed)";
    else if ((this.tag.isUniversal() && ((this.tag.number == 0x03) || (this.tag.number == 0x04))) && (this.sub !== null))
        s += " (encapsulates)";
    s += "\n";
    if (this.sub !== null) {
        indent += '  ';
        for (var i = 0, max = this.sub.length; i < max; ++i)
            s += this.sub[i].toPrettyString(indent);
    }
    return s;
};
ASN1.prototype.posStart = function() {
    return this.stream.pos;
};
ASN1.prototype.posContent = function() {
    return this.stream.pos + this.header;
};
ASN1.prototype.posEnd = function() {
    return this.stream.pos + this.header + Math.abs(this.length);
};
ASN1.decodeLength = function(stream) {
    var buf = stream.get(),
            len = buf & 0x7F;
    if (len === buf)
        return len;
    if (len > 6) // no reason to use Int10, as it would be a huge buffer anyways
        throw "Length over 48 bits not supported at position " + (stream.pos - 1);
    if (len === 0)
        return null; // undefined
    buf = 0;
    for (var i = 0; i < len; ++i)
        buf = (buf * 256) + stream.get();
    return buf;
};

ASN1.decode = function(stream) {
    if (!(stream instanceof Stream))
        stream = new Stream(stream, 0);
    var streamStart = new Stream(stream),
            tag = new ASN1Tag(stream),
            len = ASN1.decodeLength(stream),
            start = stream.pos,
            header = start - streamStart.pos,
            sub = null,
            getSub = function() {
                sub = [];
                if (len !== null) {
                    // definite length
                    var end = start + len;
                    while (stream.pos < end)
                        sub[sub.length] = ASN1.decode(stream);
                    if (stream.pos !== end)
                        throw "Content size is not correct for container starting at offset " + start;
                } else {
                    // undefined length
                    try {
                        for (; ; ) {
                            var s = ASN1.decode(stream);
                            if (s.tag.isEOC())
                                break;
                            sub[sub.length] = s;
                        }
                        len = start - stream.pos; // undefined lengths are represented as negative values
                    } catch (e) {
                        throw "Exception while decoding undefined length content: " + e;
                    }
                }
            };
    if (tag.constructed) {
        // must have valid content
        getSub();
    } else if (tag.isUniversal() && ((tag.number == 0x03) || (tag.number == 0x04))) {
        if (tag.number === 0x03)
            stream.get(); // skip BitString unused bits, must be in [0, 7]
        // sometimes BitString and OctetString do contain ASN.1
        try {
            getSub();
            for (var i = 0; i < sub.length; ++i)
                if (sub[i].tag.isEOC())
                    throw 'EOC is not supposed to be actual content.';
        } catch (e) {
            // but silently ignore when they don't
            sub = null;
        }
    }
    if (sub === null) {
        if (len === null)
            throw "We can't skip over an invalid tag with undefined length at offset " + start;
        stream.pos = start + Math.abs(len);
    }
    return new ASN1(streamStart, header, len, tag, sub);
};
// </editor-fold>

// <editor-fold defaultstate="collapsed" desc=" ASN1Tag ">
function ASN1Tag(stream) {
    var buf = stream.get();
    this.class = buf >> 6;
    this.constructed = ((buf & 0x20) !== 0);
    this.number = buf & 0x1F;
    if (this.number === 0x1F) { // long tag
        var n = new Int10();
        do {
            buf = stream.get();
            n.mulAdd(128, buf & 0x7F);
        } while (buf & 0x80);
        this.number = n.simplify();
    }
}
;
ASN1Tag.prototype.isUniversal = function() {
    return this.class === ASN1TagClass.UNIVERSAL;
};
ASN1Tag.prototype.isEOC = function() {
    return this.class === 0x00 && this.number === 0x00;
};
// </editor-fold>

