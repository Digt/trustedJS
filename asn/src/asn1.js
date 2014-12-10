//check for nodejs
if (window.module !== undefined) {
    var fs = require("fs");
} else
    console.warn("Module nodejs is not found");
var messages = {
};
var reTime = /^((?:1[89]|2\d)?\d\d)(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])([01]\d|2[0-3])(?:([0-5]\d)(?:([0-5]\d)(?:[.,](\d{1,3}))?)?)?(Z|[-+](?:[0]\d|1[0-2])([0-5]\d)?)?$/,
        reOID = /^[0-2](\.\d+)+$/g;

function Stream() {
    var BUFFER_SIZE = 1024;
    var _this = this;
    var _buf = new trusted.Buffer(BUFFER_SIZE);
    var _fd = null;
    var _pos, _curBufS, _curBufP, _curBufE;
    this.length = 0;
    this.filePointer = function() {
        return _fd;
    };
    this.print = function() {
        var str = "";
        this.get(0);
        while (!this.EOS())
            str += String.fromCharCode(this.get());
        return str;
    };
    function fileRead(start) {
        _curBufS = 0;
        _curBufP = 0;
        _buf = new Buffer(BUFFER_SIZE);
        _curBufE = fs.readSync(_fd, _buf, 0, BUFFER_SIZE, start);
        // converts nodejs Buffer to trusted.Buffer
        _buf = new trusted.Buffer(_buf);
    }

    this.load = function(obj, type, start, end) {
        switch (type) {
            case "file":
                _fd = fs.openSync(obj, "rs");
                this.length = fs.fstatSync(_fd).size;
                _pos = 0;
                fileRead(0);
                break;
            default: // binary;
                _buf = new trusted.Buffer(obj, "binary");
                this.length = _curBufE = _buf.length;
                _pos = _curBufS = _curBufP = 0;
        }
    };
    this.EOS = function() {
        return _pos === this.length;
    };
    this.position = function(v) {
        if (v !== undefined) {
            this.get(v);
        }
        return _pos;
    };
    this.get = function(v) {
        var _c;
        if (v !== undefined) {
            var l = _pos - _curBufP;
            var r = (_pos - _curBufP) + _curBufE - 1;
            if ((v < l || v > r) && !isStreamFromFile()) {
                fileRead(v);
            }
            else {
                _curBufP += v - _pos;
            }
            _pos = v;
            return _buf[_curBufP];
        }
        else {
            _c = _buf[_curBufP];
            //console.log(_curBufP+1, _c);
            if (++_curBufP >= _curBufE && !isStreamFromFile()) {
                fileRead(_pos + 1);
            }
            ++_pos;
        }
        return _c;
    };
    function isStreamFromFile() {
        return _this.length === (_curBufE - _curBufS);
    }

    function init(args) {
        if (args.length > 0)
            this.load(args[0], args[1], args[2], args[3]);
    }

    init.call(this, arguments);
}

function ASN1() {
    this.tag;
    this.length;
    this.sub = [];
    this.stream;
    var _this = this;
    this.__proto__.posStart = function() {
        return this.position;
    };
    this.__proto__.posContent = function() {
        return (this.position + this.header);
    };
    this.__proto__.posEnd = function() {
        return (this.position + this.header + this.length - 1);
    };
    this.__proto__.isNull = function() {
        return (this.tag.class === 0 && this.tag.number === 0 && this.length === 0);
    };
    this.__proto__.blob = function(enc) {
        var buf = new trusted.Buffer(this.posEnd() + 1 - this.posStart());
        this.stream.position(this.posStart());
        var i = 0;
        while (this.stream.position() <= this.posEnd()) {
            buf[i++] = this.stream.get();
        }
        if (enc !== undefined)
            return buf.toString(enc);
        return buf;
    };
    this.__proto__.content = function() {
        var buf = new trusted.Buffer(this.posEnd() - this.posContent() + 1);
        this.stream.position(this.posContent());
        var j = 0;
        for (var i = this.posContent(); i <= this.posEnd(); i++)
            buf[j++] = this.stream.get();
        return buf;
    };
    this.__proto__.toValue = function(type) {
        if (type === undefined)
            type = this.tag.type;
        if (trusted.isNumber(type))
            for (var key in ASN1TagType)
                if (ASN1TagType[key] === type) {
                    type = key;
                    break;
                }
        return ASNType[type].decode(this.content());
    };
    function decode() {
        this.tag = ASNTag.fromByte(this.stream.get());
        this.length = decodeLength(this.stream);
        this.header = this.stream.position() - this.posStart();
        if (this.tag.constructed) {
            var _end = this.posEnd() + 1;
            while ((this.stream.position() < _end || this.length === null)) {
                var asn = new ASN1(this.stream, this.stream.position());
                if (asn.isNull())
                    break;
                this.sub.push(asn);
            }
        }
        else {
            this.stream.position(this.posEnd() + 1);
        }
    }

    function decodeLength(stream) {
        var buf = stream.get(),
                len = buf & 0x7F;
        if (len === buf)
            return len;
        if (len > 6) // no reason to use Int10, as it would be a huge buffer anyrnys
            throw "Length over 48 bits not supported at position " + (stream.pos - 1);
        if (len === 0)
            return null; // undefined
        buf = 0;
        for (var i = 0; i < len; ++i)
            buf = (buf * 256) + stream.get();
        return buf;
    }

    this.toObject = function(schema) {
        return ASNToObject(this, schema);
    };


    function init(args) {
//console.log("Position(Old/new): %d - %d", _pos, args[0]);
        if (args[0] instanceof trusted.Stream)
            this.stream = args[0];
        else {
            this.stream = new trusted.Stream();
            this.stream.load(new trusted.Buffer(args[0], "binary"));
        }
        this.position = 0;
        if (args[1] !== undefined)
            this.position = args[1];
        decode.call(this);
    }

    init.call(this, arguments);
}

ASN1.fromObject = function(obj, schema) {
    var arr = ObjectToASN(obj, schema);
    return new ASN1(arr);
};

function ASNTag() {
    this.class;
    this.constructed;
    this.number;
    // return name of tag universal type
    this.__defineGetter__("type", function() {
        if (this.class === ASN1TagClass.UNIVERSAL) {
            for (var key in ASN1TagType) {
                if (ASN1TagType[key] === this.number)
                    return key;
            }
        }
        return null;
    });
    this.__proto__.isUniversal = function() {
        return this.class === ASN1TagClass.UNIVERSAL;
    };
}

ASNTag.fromByte = function(b) {
    if (!trusted.isNumber(b))
        throw "Parameter is not byte.";
    var tag = new ASNTag();
    tag.class = b >> 6;
    tag.constructed = ((b & 0x20) !== 0);
    tag.number = b & 0x1F;
    if (tag.number === 0x1F)
        throw "Long tag is not used";
    return tag;
};

var ASNType = {
    BOOLEAN: {
        decode: function(v) {
            return (v[0] === 0) ? false : true;
        },
        encode: function(v) {
            var buf = new trusted.Buffer(1);
            buf[0] = v ? 1 : 0;
            return buf;
        }
    },
    INTEGER: {
        decode: function(val) {
            var v = val[0],
                    neg = (v > 127),
                    pad = neg ? 255 : 0,
                    len,
                    s = '';
            // skip unuseful bits (not allowed in DER)
            //while (v == pad && ++start < end)
            //    v = this.get(start);
            len = val.length;
            if (len === 0)
                return neg ? -1 : 0;
            // show bit length of huge integers
            //if (len > 4) {
            //    s = v;
            //    len <<= 3;
            //    while (((s ^ pad) & 0x80) == 0) {
            //        s <<= 1;
            //       --len;
            //   }
            //   s = "(" + len + " bit)\n";
            //}
            // decode the integer
            if (neg)
                v = v - 256;
            var n = new BigInt(v);
            for (var i = 1; i < len; ++i)
                n.mulAdd(256, val[i]);
            return n;
        },
        encode: function(v) {
        }
    },
    BIT_STRING: {
        decode: function(v) {
            return new BitString(v.slice(1).toString("binary"), v[0]);
        },
        encode: function(v) {
            var bs = v;
            if (trusted.isString(v))
                bs = BitString.fromString(v);
            var buf = new trusted.Buffer(bs.encoded.length + 1);
            buf[0] = bs.unusedBit;
            for (var i = 0; i < bs.encoded.length; i++)
                buf[i + 1] = bs.encoded.charCodeAt(i);
            return buf;
        }
    },
    OCTET_STRING: {
        decode: function(v) {
            return v;
        },
        encode: function(v) {
            return new Buffer(v, "binary");
        }
    },
    OBJECT_IDENTIFIER: {
        decode: function(val) {
            val = new trusted.Buffer(val, "binary");
            var s = '',
                    n = new BigInt(),
                    bits = 0;
            for (var i = 0; i < val.length; ++i) {
                var v = val[i];
                n.mulAdd(128, v & 0x7F);
                bits += 7;
                if (!(v & 0x80)) { // finished
                    if (s === '') {
                        n = n.simplify();
                        var m = n < 80 ? n < 40 ? 0 : 1 : 2;
                        s = m + "." + (n - m * 40);
                    } else
                        s += "." + n.toString();
                    //if (s.length > maxLength)
                    //    return stringCut(s, maxLength);
                    n = new BigInt();
                    bits = 0;
                }
            }
            if (bits > 0)
                s += ".incomplete";
            return s;
        },
        encode: function(v) {

            if (!reOID.test(v))
                throw "'" + v + "' is wrong value.";
            var buf = new trusted.Buffer(1);
            v = v.split(".");
            for (var i = 0; i < v.length; i++) {
                v[i] = parseInt(v[i]);
            }
            buf[0] = v[1] + (v[0] * 40);
            for (var i = 2; i < v.length; i++) {
                var arr = encodeSID(v[i]);
                buf = buf.concat(arr);
            }
            return buf;
        }
    },
    SET: {decode: function() {
            return null;
        }, encode: function() {
            return null;
        }},
    SEQUENCE: {decode: function() {
            return null;
        }, encode: function() {
            return null;
        }},
    UTF8_STRING: {
        decode: function(v) {
            return v.toString();
        },
        encode: function(v) {
            var b = new trusted.Buffer(v);
            return b;
        }
    },
    NUMERIC_STRING: {
        decode: function(v) {
            return v.toString("binary");
        },
        encode: function(v) {
            var b = new trusted.Buffer(v, "binary");
            return b;
        }
    },
    BMP_STRING: {
        decode: function(v) {
            return v.toString("ucs2");
        },
        encode: function(v) {
            var b = new trusted.Buffer(v, "ucs2");
            return b;
        }
    },
    UTC_TIME: {
        decode: function(v) {
            return TimeParser(v, true);
        },
        encode: function(v) {
            return TimeEncoder(v, true);
        }
    },
    GENERALIZED_TIME: {
        decode: function(v) {
            return TimeParser(v, false);
        },
        encode: function(v) {
            return TimeEncoder(v, false);
        }
    }
};
ASNType.PRINTABLE_STRING = ASNType.NUMERIC_STRING;
ASNType.TELETEX_STRING = ASNType.NUMERIC_STRING;
ASNType.VIDEOTEX_STRING = ASNType.NUMERIC_STRING;
ASNType.IA5_STRING = ASNType.NUMERIC_STRING;
//case 0x19: // GraphicString
ASNType.VISIBLE_STRING = ASNType.NUMERIC_STRING;
//case 0x1B: // GeneralString
//case 0x1C: // UniversalString

function encodeSID(val) {
    var asn = [];
    var num = val;
    if (val === 0)
        return [0];
    for (var i = 5; i >= 0; i--) {
        var h;
        var n = Math.pow(128, i);
        if (n <= num) {
            h = Math.floor(num / n);
            num -= Math.pow(128, i) * h;
            if (i > 0) {
                asn.push(h | 0x80);
                if (num === 0) {
                    for (var j = i - 1; j > 0; j--)
                        asn.push(0 | 0x80);
                    asn.push(0);
                    break;
                }
            }
            else
                asn.push(h);
        }
    }
    return new trusted.Buffer(asn);
}

function TimeParser(buf, shortYear) {
    var s = buf.toString("binary"),
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
}

function TimeEncoder(v, shortYear) {
    if (shortYear === undefined)
        shortYear = true;
    if (!v instanceof Date)
        throw "encodeTime: param must be instance of Date."
    function formatNum(val) {
        var str = "";
        str = val.toString();
        if (str.length === 1)
            str = "0" + str;
        return str;
    }

    var fd = "";
    var year = v.getFullYear().toString();
    if (shortYear)
        year = year.substring(2);
    fd += year;
    fd += formatNum(v.getMonth() + 1);
    fd += formatNum(v.getDate());
    fd += formatNum(v.getHours());
    fd += formatNum(v.getMinutes());
    fd += formatNum(v.getSeconds());
    fd += "Z";
    return new trusted.Buffer(fd, "binary");
}

var max = 10000000000000; // biggest integer that can still fit 2^53 when multiplied by 256

function BigInt(value) {
    //init
    this.buf = [];
    this.buf[0] = +value || 0;
}

BigInt.prototype.mulAdd = function(m, c) {     // assert(m <= 256)
    var b = this.buf,
            l = b.length,
            i, t;
    for (i = 0; i < l; ++i) {
        t = b[i] * m + c;
        if (t < max)
            c = 0;
        else {
            c = 0 | (t / max);
            t -= c * max;
        }
        b[i] = t;
    }
    if (c > 0)
        b[i] = c;
};
BigInt.prototype.toString = function(base) {
    if ((base || 10) != 10)
        throw 'only base 10 is supported';
    var b = this.buf,
            s = b[b.length - 1].toString();
    for (var i = b.length - 2; i >= 0; --i)
        s += (max + b[i]).toString().substring(1);
    return s;
};
BigInt.prototype.toNumber = function() {
    return this.valueOf();
};
BigInt.prototype.valueOf = function() {
    var b = this.buf,
            v = 0;
    for (var i = b.length - 1; i >= 0; --i)
        v = v * max + b[i];
    return v;
};
BigInt.prototype.simplify = function() {
    var b = this.buf;
    return (b.length === 1) ? b[0] : this;
};
function BitString() {
    var e;
    var ub = 0;
    this.unusedBit = null;
    this.encoded = null;
    this.__proto__ = {
        get unusedBit() {
            return ub;
        },
        set unusedBit(v) {
            v = parseInt(v);
            if (isNaN(v) || (v < 0 && v > 7))
                throw "BitString.unusedBit: Wrang value. Value must be from 0 to 7."
            ub = v;
        },
        get encoded() {
            return e;
        },
        set encoded(v) {
            if (!trusted.isString(v) && v === '')
                throw "BitString.encoded: Wrang value. Value must be string and must has length more then 0."
            e = v;
        }
    };
    this.__proto__.toString = function() {
        var res = '';
        if (this.encoded !== undefined) {
            res += "(" + ((this.encoded.length * 8) - this.unusedBit) + ") ";
            res += Der.toHex(this.encoded);
        }
        return res;
    };
    function numberToBitString(num) {
        var bit = num.toString(2); // to Der
        var l = bit.length % 8;
        if (l > 0) {
            for (var i = 0; i < (8 - l); i++)
                bit = '0' + bit;
        }
        //console.log(bit);
        return BitString.fromString(bit);
    }

    this.__proto__.toNumber = function() {
        var n = 0;
        for (var i = 0; i < this.encoded.length; i++)
            n |= this.encoded.charCodeAt(i) << ((this.encoded.length - 1 - i) * 8);
        n = n >> this.unusedBit;
        return n;
    };
    function init(arg) {
        switch (arg.length) {
            case 0:
                throw "BitString.new: It must have 1 or more parameters.";
                break;
            case 1:
                if (!trusted.isNumber(arg[0]))
                    throw "BitString.new: Parameter must be Number."
                var bs = numberToBitString(arg[0]);
                this.encoded = bs.encoded;
                this.unusedBit = bs.unusedBit;
                break;
            default:
                this.encoded = arg[0];
                this.unusedBit = (arg[1] === undefined ? 0 : arg[1]);
        }

    }

    init.call(this, arguments);
}

BitString.fromString = function(val) {
    if (!trusted.isString(val))
        throw "BitString.fromString: Wrang value. Value must be String."
    var reg = /^[01]+$/;
    if (!reg.test(val))
        throw "BitString.fromString: Wrang value. Value must be String of Bits (01100110)."

    var ub = 8 - (val.length % 8);
    ub = (ub === 8) ? 0 : ub;
    if (ub > 0)
        for (var i = 0; i < ub; i++) // Add unused bits
            val += "1";
    var der = '';
    for (var i = 0; i < (val.length / 8); i++) { // val to DER
        var b = val.substring(i * 8, 8 + (i * 8));
        der += String.fromCharCode(parseInt(b, 2));
    }
    return new BitString(der, ub);
};
