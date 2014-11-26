(function(){
if (window.trusted===undefined)
    throw "Для работы модуля ASN необходим модуль trusted.js"

var schemas={};
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
    this.__proto__.blob = function() {
        var buf = new trusted.Buffer(this.posEnd() + 1 - this.posStart());
        this.stream.position(this.posStart());
        var i = 0;
        while (this.stream.position() <= this.posEnd()) {
            buf[i++] = this.stream.get();
        }
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
    var der = '';
    for (var i = 0; i < arr.length; i++) {
        der += String.fromCharCode(arr[i]);
    }
    return new ASN1(der);
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
/*function ASN() {
 this.structure;
 this.__proto__.toObject = function(schema) {
 if (this.structure === undefined)
 throw "ASN.toObject: ASN structure is not initialized. Call import method first."
 return ASNToObject(this.structure, schema);
 };
 this.__proto__.import = function(a) {
 if (a !== undefined) {
 this.structure = new ASN(a);
 }
 };
 this.import(arguments[0]);
 }
 
 ASN.prototype.encode = function() {
 return this.structure.toString();
 };
 ASN.fromObject = function(obj, schema) {
 var arr = ObjectToASN(obj, schema);
 var der = '';
 for (var i = 0; i < arr.length; i++) {
 der += String.fromCharCode(arr[i]);
 }
 return new ASN(der);
 };
 */
// <editor-fold defaultstate="collapsed" desc=" ASNToObject ">

/*
 *Сортирует элементы SEQUENCE по значениям index 
 */
function sortSequenceElements(schema) {
    var values = trusted.objToArray(schema.value);
    values.sort(function(a, b) {
        if (a.index > b.index)
            return 1;
        if (a.index < b.index)
            return -1;
        return 0;
    });
    return values;
}


var svt = "ASN не соответствует схеме.";
/*
 * Конвертирует ASN структуру в Object по указанной схеме
 */
function ASNToObject(asn, schema) {
    var obj;
    //try {
    if (typeof (schema) === "string")
        schema = new Schema(schema); // Получение схемы
    obj = _ASNToObject(asn, schema.value);
    //}
    //catch (e) {
    //    throw "ASNToObject: " + e.message;
    //}
    return obj;
}

function _ASNToObject(asn, schema) {
    if (schema.name === "v1")
        "";
    if (schema.type === "DistributionPointName")
        "";
    //console.log("%cSchema name: %c %s , Schema: %o; ASN deep: %i; ASN: %o", "color:#f00", "color:#000", schema.name, schema, ASNDeepCount(asn), asn);
    //console.log("Tag (c,n): ", asn.tag.class, asn.tag.number);

    var o = {};
    if (asn === undefined)
        // Пустой ASN элемент может быть только в случае OPTIONAL или DEFAULT
        if (!(schema.hasOwnProperty("optional") || schema.hasOwnProperty("default")))
            throw new SchemaValidityException("'" + schema.name + "' is not found.");

    o = atoo(asn, schema);

    return o;



    if (schema.isAny) {
        obj = asn.toString();
        return obj;
    }

    //Проверка ASN данных
    if (!isTagEquals(asn, schema))
        throw new SchemaValidityException("'" + schema.name + "' tag is not equals to ASN tag. (1)");

    return obj;
}

function atoo(a, s) {
    var o = {};
    //if (s.type === "Validity")
    //    console.log("val");
    // CONTEXT-SPECIFIC
    if ("context" in s)
        if (a.tag.class === 2 && a.tag.number === s.context) {
            //explicit
            if (s.explicit)
                a = a.sub[0]; // Взять внутренний элемент структуры
            //implicit
        } else {
            throw svt + " Ожидалось CONTEXT-SPECIFIC [" + s.context + "]";
        }

    if (s.isChoice) {
        o = validateChoice(a, s);
        return o;
    }

    if (s.hasOwnProperty("maxOccurs")) {
        o = validateMaxOccurs(a, s);
        return o;
    }

    if (s.isAny) {
        o = a.blob();
        return o;
    }

    if (!(s.context && !s.explicit) && !isTagEquals(a, s))
        throw svt + " Теги не равны.";

    if (s.tag.constructed) {
        var values;
        if (s.tag.number === 16 || "context" in s) // для составных элементов SEQUENCE делаем сортировку элементов
            values = sortSequenceElements(s);
        else
            values = trusted.objToArray(s.value);
        var step = 0;
        for (var i = 0; i < values.length; i++) {
            var value = values[i];
            var asub = a.sub[i - step];
            var _a;
            try {
                _a = _ASNToObject(asub, value);
            } catch (e) {
                step++;
                //console.warn(e);
                if (!("optional"in value || "default" in value))
                    throw svt + " Элемент ASN не соответсвует схеме " + value.name + " (" + value.type + ")";
                if ("default" in value)
                    _a = value.default;
                else {
                    o[value.name] = null;
                    continue;
                }
            }
            o[value.name] = _a;
        }
    }
    else
        o = ("context" in s) ? a.toValue(s.tag.number) : a.toValue();

    return o;
}


function validateChoice(asn, schema) {
    var hasChoice;
    var obj = {};
    var keys = Object.keys(schema.value); // получаем имена схем выбора
    for (var j = 0; j < keys.length; j++) {
        var schema_name = keys[j];
        var choice_schema = schema.value[keys[j]];
        try {
            var asnobj;
            asnobj = _ASNToObject(asn, choice_schema);
            // Совпадение найдено покидаем цикл
            obj[schema_name] = asnobj;
            hasChoice = true;
            break;
        } catch (e) {
            "";
        }
    }
    if (!hasChoice)
        throw svt + " Нет совпадений в CHOICE.";
    return obj;
}

function validateMaxOccurs(a, s) {
    var obj = [];
    if (a.sub.length > s.maxOccurs)
        throw svt + " maxOccurs превышен.";
    for (var j = 0; j < a.sub.length; j++) {
        var _s = s.value[Object.keys(s.value)[0]];
        var o = _ASNToObject(a.sub[j], _s);
        obj.push(o);
    }
    if (a.sub.length < s.minOccurs)
        throw svt + " minOccurs.";
    return obj;
}

function isTagEquals(a, s) {
    // don't check cunstructed for OCTET_STRING (it may be constructed or not constructed)
    var constructed = true;
    if (!(s.tag.class === 0 && s.tag.number === 4))
        constructed = a.tag.constructed === s.tag.constructed;
    return ((a.tag.class === s.tag.class &&
            a.tag.number === s.tag.number &&
            constructed));
    //||
    //("context"in s && a.tag.constructed === s.tag.constructed)); // для CONTENT-SPECIFIC проверить только constructed
}
// </editor-fold>

// <editor-fold defaultstate="collapsed" desc=" ObjectToASN ">
var ovt = "Объект не соответсвует схеме. ";
function ObjectToASN(o, s) {
    var a;
    s = new Schema(s).value; // Получение схемы
    a = otoa(o, s);
    return a;
}

function otoa(o, s) {
    //if (s.name === "certificates")
    //    console.log("Here!!!");
    //console.log(schema.name);

    if (s.isChoice) {
        var keys = Object.keys(o);
        if (keys.length !== 1)
            throw ovt + "Кодируемый объект может иметь только одно значение.";
        if (!(keys[0]in s.value))
            throw ovt + "Значение объект не соответствует схеме CHOICE.";
        var a = otoa(o[keys[0]], s.value[keys[0]]);
        if ("context" in s)
            a = encodeExplicit(s.context, a);
        return a;
    }

    if (s.isAny) {
        var any = encode(o, s);
        if ("context" in s) {
            any = encodeExplicit(s.context, any);
        }
        return any;
    }

    if (s.tag.constructed) {
        var values = (s.tag.class === 0 && s.tag.number === 16) ? sortSequenceElements(s) : trusted.objToArray(s.value);
        var sub = [];
        //var step = 0;
        for (var i = 0; i < values.length; i++) {
            var value = values[i];
            if (s.hasOwnProperty("maxOccurs")) {
                if (!trusted.isArray(o))
                    throw "ASN.ObjectToASN: Object isn't equals to Schema. Must be Array."
                for (var i = 0; i < o.length; i++) {
                    sub = sub.concat(otoa(o[i], value));
                }
                break;
            }

            if (!(value.name in o)) {
                if (!(value.hasOwnProperty("optional") || value.hasOwnProperty("default")))
                    throw new SchemaValidityException("'" + value.name + "' не найден в объекте.")
                //step++;
                continue;
            }

            if (value === null) {
                if (value.hasOwnProperty("optional"))
                    continue;
                else
                    return Hex.toDer("0500");
            }

            if (value.hasOwnProperty("default")) {
                if (value.default === o[value.name]) {
                    //step++;
                    continue;
                }
            }
            var a = otoa(o[value.name], value);

            sub = sub.concat(a);
        }
        return encode(sub, s);
    }
    else
    if (!(s.hasOwnProperty("default") && s.default === o))
        return encode(o, s);
}
// </editor-fold>

// <editor-fold defaultstate="collapsed" desc=" Encode ">

function encodeExplicit(number, value) {
    var asn = [];
    asn.push(encodeTag(0x02, true, number)); //tag CONTEXT-SPECIFIC CONSTRUCTED [number]
    asn = asn.concat(encodeLength(value.length)); // length
    asn = asn.concat(value); // value
    return asn;
}
function encode(obj, schema) {
    console.log(schema.type);
    if (schema.type === "INTEGER")
        "";
    var asn = [];

    if (schema.isAny) { //encode ANY
        if (obj === null)
            return [5, 0];
        var any;
        try { //Check for ASN
            any = new trusted.ASN(obj);
        } catch (e) {
            throw("ASN.encode: ANY has wrong data. It must have ASN DER string.");
        }
        for (var i = 0; i < obj.length; i++) // convert DER to NumArray
            asn.push(obj[i]);
        return asn;
    }

    switch (schema.tag.class) {
        case ASN1TagClass.UNIVERSAL:
            switch (schema.tag.number) {
                case ASN1TagType.EOC:
                    break;
                case ASN1TagType.BOOLEAN:
                    obj = [(obj ? 1 : 0)];
                    break;
                case ASN1TagType.INTEGER:
                    obj = encodeInteger(obj);
                    break;
                case ASN1TagType.BIT_STRING:
                    obj = encodeBitString(obj);
                    break;
                case ASN1TagType.OCTET_STRING:
                    obj = encodeStringOCTET(obj);
                    break;
                case ASN1TagType.NULL:
                    return [5, 0];
                    break;
                case ASN1TagType.OBJECT_IDENTIFIER:
                    obj = encodeOID(obj);
                    break;
                case ASN1TagType.OBJECT_DESCRIPTOR:
                    break;
                case ASN1TagType.EXTERNAL:
                    break;
                case ASN1TagType.REAL:
                    break;
                case ASN1TagType.ENUMERATED:
                    break;
                case ASN1TagType.EMBEDDED_PDV:
                    break;
                case ASN1TagType.UTF8_STRING:
                    obj = encodeStringUTF(obj);
                    break;
                case ASN1TagType.SEQUENCE:
                case ASN1TagType.SET:
                    break;
                case ASN1TagType.NUMERIC_STRING:
                case ASN1TagType.PRINTABLE_STRING:
                case ASN1TagType.T61_STRING:
                case ASN1TagType.VIDEOTEX_STRING:
                case ASN1TagType.IA5_STRING:
                    //case window.trusted.ASN.ASN1TagType.GRAPHIC_STRING:
                case ASN1TagType.ISO64_STRING:
                    obj = encodeStringISO(obj);
                    break;
                    //case window.trusted.ASN.ASN1TagType.GENERAL_STRING:
                    //case window.trusted.ASN.ASN1TagType.UNIVERSAL_STRING:
                case ASN1TagType.UTC_TIME:
                    obj = encodeTime(obj);
                    break;
                case ASN1TagType.GENERALIZED_TIME:
                    obj = encodeTime(obj, false);
                    break;
                case ASN1TagType.BMP_STRING:
                    obj = encodeStringBMP(obj);
                    break;
            }
//            if (schema.explicit) {
//                var ev = []; //explicit value
//                ev.push(encodeTag(schema.tag.class, schema.tag.constructed, schema.tag.number)); //tag
//                ev = ev.concat(encodeLength(obj.length)); // length
//                obj = ev.concat(obj); // value
//            }
//            if (!schema.implicit) {
//                if ("context" in schema)
//                    if (schema.explicit)
//                        asn.push(encodeTag(0x02, true, schema.context)); //tag
//                    else
//                        asn.push(encodeTag(0x02, schema.tag.constructed, schema.context)); //tag
//                else
//                    asn.push(encodeTag(schema.tag.class, schema.tag.constructed, schema.tag.number)); //tag
//                asn = asn.concat(encodeLength(obj.length)); // length
//            }
            if ("context" in schema) {
                if (schema.explicit) { //explicit
                    asn.push(encodeTag(0x02, true, schema.context)); //tag

                    var content = [];
                    content.push(encodeTag(schema.tag.class, schema.tag.constructed, schema.tag.number)); //tag
                    content = content.concat(encodeLength(obj.length)); // length

                    asn = asn.concat(encodeLength(content.length + obj.length)); // length
                    asn = asn.concat(content);
                } else { //implicit
                    asn.push(encodeTag(0x02, schema.tag.constructed, schema.context)); //tag
                    asn = asn.concat(encodeLength(obj.length)); // length
                }
            } else {
                asn.push(encodeTag(schema.tag.class, schema.tag.constructed, schema.tag.number)); //tag
                asn = asn.concat(encodeLength(obj.length)); // length
            }
            asn = asn.concat(obj); // value
            break;
    }

    return asn;
}

function encodeTag(tag_class, tag_constructed, tag_number) {
    var byte = 0;
    byte |= tag_class << 6; //class
    byte |= tag_constructed << 5; //constructed
    byte |= tag_number; //number
    return byte;
}

function encodeLength(length) {
    switch (typeof (length)) {
        case "undefined":
            break;
        case "number":
            var enc = [];
            if (length !== (length & 0x7F)) {
                var code = length.toString(16);
                var _length = Math.round(code.length / 2);
                enc[0] = _length | 0x80;
                if (Math.floor(code.length % 2) > 0)
                    code = "0" + code;
                for (var i = 0; i < code.length; i = i + 2) {
                    enc[1 + (i / 2)] = parseInt(code.substring(i, i + 2), 16);
                }
            } else {
                enc[0] = length;
            }
            return enc;
            break;
        default:
            throw "ASN1.lenfth wrong type. Must be Number."
    }
}

function encodeInteger(num) {
    var asn = [];
    if (typeof (num) === "number") {
        // number to der
        var der = [];
        var neg = false;
        if (num < 0) {
            num *= -1;
            neg = true;
        }
        var hex = num.toString(16);
        if (hex.length % 2 > 0)
            hex = '0' + hex;
        for (var i = 0; i < hex.length; i = i + 2)
            der.push(parseInt(hex.substring(i, 2 + i), 16));
        if (!neg)
            if (num < 128)
                return [num];
            else {
                asn.push(0);
                asn = asn.concat(der);
            }
        else {
            asn.push(0xff);
            var n = der.length;
            while (n > 1) {
                if (der[n - 1] !== 0)
                    break;
                n--;
            }
            n--;
            der[n] = (der[n] ^ 0xff) + 1;
            for (var i = (--n); i >= 0; i--)
                der[i] = (der[i] ^ 0xff);
            asn = asn.concat(der);
        }
    } else if (trusted.isString(num)) {
        if (!Hex.test(num))
            throw {message: "encodeInteger: Value '" + num + "' is not Hex."};
        var der = Hex.toDer(num);
        for (var i = 0; i < der.length; i++)
            asn.push(der.charCodeAt(i));
    }

    return asn;
}

function encodeBitString(val) {
    var asn = [];
    if (trusted.isString(val))
        val = BitString.fromString(val);
    asn.push(val.unusedBit);
    for (var i = 0; i < val.encoded.length; i++)
        asn.push(val.encoded.charCodeAt(i));
    return asn;
}

function encodeStringUTF(val) {
    var asn = [];
    for (var i = 0; i < val.length; i++) {
        var char = val.charCodeAt(i);
        if (char < 256) {
            asn.push(char);
        }
        else if (char < (256 * 256)) {
            asn.push((char >> 6) | 192); // 1 byte
            asn.push((char & 63) | 128); // 2 byte
        } else if (char < (256 * 256 * 256)) {
            asn.push((char >> 12) | 224); // 1 byte
            asn.push(((char >> 6) & 63) | 128); // 2 byte
            asn.push((char & 63) | 128); // 3 byte
        } else
            throw "Символ состоит более чем из трех байтов. Преобразование еще не реализовано."
    }
    return asn;
}

function encodeStringOCTET(val) {
    var res = [];
    for (var i = 0; i < val.length; i++)
        res.push(val.charCodeAt(i));
    return res;
}

function encodeOID(val) {
    var regex = /^[0-2](\.\d+)+$/g;
    if (!regex.test(val))
        throw "'" + val + "' is wrong value.";
    var asn = [];
    val = val.split(".");
    for (var i = 0; i < val.length; i++) {
        val[i] = parseInt(val[i]);
    }
    asn.push(val[1] + (val[0] * 40));
    for (var i = 2; i < val.length; i++) {
        var arr = encodeSID(val[i]);
        asn = asn.concat(arr);
    }
    return asn;
}

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
    return asn;
}

function encodeStringISO(val) {
    var asn = [];
    for (var i = 0; i < val.length; i++)
        asn.push(val.charCodeAt(i));
    return asn;
}

function encodeStringBMP(val) {
    var asn = [];
    for (var i = 0; i < val.length; i++) {
        var char = val.charCodeAt(i);
        asn.push(char >> 8);
        asn.push(char & 255);
    }
    return asn;
}

function encodeTime(val, utc) {
    if (utc === undefined)
        utc = true;
    if (!val instanceof Date)
        throw "encodeTime: param must be instance of Date."
    function formatNum(val) {
        var str = "";
        str = val.toString();
        if (str.length === 1)
            str = "0" + str;
        return str;
    }

    var fd = "";
    var year = val.getFullYear().toString();
    if (utc)
        year = year.substring(2);
    fd += year;
    fd += formatNum(val.getMonth() + 1);
    fd += formatNum(val.getDate());
    fd += formatNum(val.getHours());
    fd += formatNum(val.getMinutes());
    fd += formatNum(val.getSeconds());
    fd += "Z";
    return encodeStringISO(fd);
}

// </editor-fold>

// Base64 JavaScript decoder
// Copyright (c) 2008-2014 Lapo Luchini <lapo@lapo.it>

// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
// 
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
// ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
// OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

/*jshint browser: true, strict: true, immed: true, latedef: true, undef: true, regexdash: false */
(function(undefined) {
    "use strict";

    var Base64 = {},
            decoder;

    Base64.decode = function(a) {
        var i;
        if (decoder === undefined) {
            var b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
                    ignore = "= \f\n\r\t\u00A0\u2028\u2029";
            decoder = [];
            for (i = 0; i < 64; ++i)
                decoder[b64.charAt(i)] = i;
            for (i = 0; i < ignore.length; ++i)
                decoder[ignore.charAt(i)] = -1;
        }
        var out = [];
        var bits = 0, char_count = 0;
        for (i = 0; i < a.length; ++i) {
            var c = a.charAt(i);
            if (c === '=')
                break;
            c = decoder[c];
            if (c === -1)
                continue;
            if (c === undefined)
                throw 'Illegal character at offset ' + i;
            bits |= c;
            if (++char_count >= 4) {
                out[out.length] = (bits >> 16);
                out[out.length] = (bits >> 8) & 0xFF;
                out[out.length] = bits & 0xFF;
                bits = 0;
                char_count = 0;
            } else {
                bits <<= 6;
            }
        }
        switch (char_count) {
            case 1:
                throw "Base64 encoding incomplete: at least 2 bits missing";
            case 2:
                out[out.length] = (bits >> 10);
                break;
            case 3:
                out[out.length] = (bits >> 16);
                out[out.length] = (bits >> 8) & 0xFF;
                break;
        }
        var der = '';
        for (var i = 0; i < out.length; i++) {
            der += String.fromCharCode(out[i]);
        }
        return der;
    };

    Base64.re = /-----BEGIN [^-]+-----([A-Za-z0-9+\/=\s]+)-----END [^-]+-----|begin-base64[^\n]+\n([A-Za-z0-9+\/=\s]+)====/;
    Base64.unarmor = function(a) {
        var m = Base64.re.exec(a);
        if (m) {
            if (m[1])
                a = m[1];
            else if (m[2])
                a = m[2];
            else
                throw "RegExp out of sync";
        }
        return Base64.decode(a);
    };

    Base64.toHex = function(str) {
        return Der.toHex(Base64.toDer(str));
    };
    Base64.toDer = function(str) {
        var nums;
        if (Base64.re.test(str))
            nums = Base64.unarmor(str);
        else
            nums = Base64.decode(str);
        var s = "";
        for (var i = 0; i < nums.length; i++)
            s += String.fromCharCode(nums[i]);
        return s;
    };

    var tableStr = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    var table = tableStr.split("");
    function btoa(bin) {
        for (var i = 0, j = 0, len = bin.length / 3, base64 = []; i < len; ++i) {
            var a = bin.charCodeAt(j++), b = bin.charCodeAt(j++), c = bin.charCodeAt(j++);
            if ((a | b | c) > 255)
                throw new Error("String contains an invalid character");
            base64[base64.length] = table[a >> 2] + table[((a << 4) & 63) | (b >> 4)] +
                    (isNaN(b) ? "=" : table[((b << 2) & 63) | (c >> 6)]) +
                    (isNaN(b + c) ? "=" : table[c & 63]);
        }
        return base64.join("");
    }



    Base64.fromDer = function(str) {
        var hex = Der.toHex(str);
        return Base64.fromHex(hex);
    };
    
    Base64.fromHex = function(str) {
        return btoa(String.fromCharCode.apply(null,
                str.replace(/\r|\n/g, "").replace(/([\da-fA-F]{2}) ?/g, "0x$1 ").replace(/ +$/, "").split(" "))
                );
    };

    Base64.format = function(base64, name) {
        if (name === undefined)
            throw "Base64.format: Параметр name не может быть пустым";
        if (!trusted.isString(name))
            throw "Base64.format: Параметр name должен быть строкой";

        name = name.toUpperCase();

        var b64 = "-----BEGIN " + name + "-----\n";
        var b64_counter = 0;
        for (var i = 0; i < base64.length; i++) {
            b64 += base64.charAt(i);
            b64_counter++;
            if (b64_counter === 64) {
                b64 += "\n";
                b64_counter = 0;
            }
        }
        b64 += "\n-----END " + name + "-----\n";
        return b64;
    };

// exports

    window.Base64 = Base64;

})();
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
        var bit = num.toString(2);  // to Der
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
                this.encoded = new trusted.Buffer(arg[0], "binary");
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

    var ub = 8 - val.length % 8;
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
trusted.Buffer = (function() {

    function Buffer() {
        //init
        var data = arguments[0];
        var enc = arguments[1];
        if (enc === undefined)
            enc = "utf8";
        else
            enc = enc.toLowerCase();
        switch (typeof (data)) {
            //case "number":
            //    return new NativeBuffer(data);
            case "string":
                return fromString(data, enc);
            default:
                return new NativeBuffer(data);

        }

    }

    function fromString(v, enc) {
        checkConverter(enc);
        return StringConverter[enc].fromString(v);
    }

    function checkConverter(enc) {
        if (!StringConverter.hasOwnProperty(enc))
            throw "Using of unknown encoder: '" + enc + "'";
    }

    var NativeBuffer = Uint8Array;

    NativeBuffer.prototype.__defineGetter__("type", function() {
        return "Buffer";
    });
    NativeBuffer.prototype.toString = function(enc) {
        if (enc === undefined)
            enc = "utf8";
        enc = enc.toLowerCase();
        checkConverter(enc);
        return StringConverter[enc].toString(this);
    };

    var BinaryConverter = {
        toString: function(v) {
            var res = "";
            for (var i = 0; i < v.length; i++)
                res += String.fromCharCode(v[i]);
            return res;
        },
        fromString: function(v) {
            var buf = new NativeBuffer(v.length);
            for (var i = 0; i < v.length; i++)
                buf[i] = v.charCodeAt(i);
            return buf;
        }
    };
    var Base64Converter = {
        toString: function(v) {
            return btoa(v.toString("binary"));
        },
        fromString: function(v) {
            var buf = new Buffer(atob(v), "binary");
            return buf;
        }
    };
    var Utf8Converter = {
        toString: function(v) {
            return decodeURIComponent(escape(v.toString("binary")));
        },
        fromString: function(v) {
            return BinaryConverter.fromString(unescape(encodeURIComponent(v)));
        }
    };

    var Ucs2Converter = {
        toString: function(v) {
            var s = "", h, l;
            for (var i = 0; i < v.length; i++) {
                h = v[i];
                l = v[++i];
                s += String.fromCharCode((h << 8) | l);
            }
            return s;
        },
        fromString: function(v) {
            var buf = new NativeBuffer(v.length);
            for (var i in v)
                buf[i] = v.charCodeAt(i);
            return buf;
        }
    };

    var StringConverter = {
        "binary": BinaryConverter,
        "ascii": BinaryConverter,
        "base64": Base64Converter,
        "base-64": Base64Converter,
        "utf8": Utf8Converter,
        "utf-8": Utf8Converter,
        "ucs2": Ucs2Converter,
        "ucs-2": Ucs2Converter,
        "hex": {
            toString: function(v) {
                var res = "";
                for (var i = 0; i < v.length; i++) {
                    var c = v[i].toString(16);
                    if (c % 2 !== 0)
                        res += '0';
                    res += c;
                }
                return res;
            },
            fromString: function(v) {
                var buf = new NativeBuffer(v.length / 2);
                var j = 0;
                for (var i = 0; i < v.length; i++)
                    buf[j++] = parseInt(v[i] + v[++i], 16);
                return buf;
            }
        }
    };

    //---------------------------------------------------------------------------------

    /**
     * Returns JSON string of BufferArray
     * @returns {String}
     */
    NativeBuffer.prototype.toJSON = function() {
        var s = "[";
        for (var i = 0; i < this.length; i++)
            s += this[i].toString() + (i === (this.length - 1) ? "" : ",");
        s += "]";
        return s;
    };
    /**
     * Concatinates to BofferArrays
     * @param {BufferArray} buf BufferArray object each must be concatinate to 
     * this BufferArray
     * @returns {BufferArray} new instance of BufferArray
     */
    NativeBuffer.prototype.concat = function(buf) {
        var bufSize = this.length + buf.length;
        var b = new NativeBuffer(bufSize);
        var j = 0;
        for (var i = 0; i < this.length; i++) {
            b[j] = this[i];
            j++;
        }
        for (var i = 0; i < buf.length; i++) {
            b[j] = buf[i];
            j++;
        }
        return b;
    };
    /**
     * Create new instance of BufferArray with data copy
     * @returns {Buffer}
     */
    NativeBuffer.prototype.copy = function() {
        var b = new NativeBuffer(this.length);
        for (var i = 0; i < this.length; i++)
            b[i] = this[i];
        return b;
    };

    /**
     * Select elements from an array
     * @param {type} s Index of start [0 based]
     * @param {type} e Index of end [0 based]
     * @returns {Buffer} New instance of BufferArray
     */
    NativeBuffer.prototype.slice = function(s, e) {
        if (s === undefined)
            s = 0;
        if (e === undefined)
            e = this.length;
        var bs = (e - s);
        var b = new NativeBuffer(bs);
        var j = 0;
        for (var i = s; i < e; i++)
            b[j++] = this[i];
        return b;
    };
    /**
     * Writes value to BufferArray
     * @param {String|Buffer} v Sets string value
     * @param {Number} s Sets start index for inserting data. Default 0
     * @param {Number} l Sets length of bytes for writing. Default buffer.length
     * @param {String} enc Sets encoder type of string value. Default UTF-8
     * @returns {undefined}
     */
    NativeBuffer.prototype.write = function(v, s, l, enc) {
        if (s === undefined)
            s = 0;
        if (l === undefined)
            l = this.length;
        var e = s + l - 1;
        if (e > this.length)
            e = this.length;
        var buf = new buffer(v, enc);
        var j = 0;
        for (var i = s; i < this.length && i <= e; i++)
            this[i] = buf[j++];
    };

    return Buffer;
})();var Der = {};
Der.toHex = function(der) {
    if (der === undefined || der === null)
        return null;
    var hex = '';
    for (var i = 0; i < der.length; i++) {
        var char = der.charCodeAt(i).toString(16);
        if ((char.length % 2) > 0)
            char = "0" + char;
        hex += char;
    }
    return hex.toUpperCase();
};
Der.fromNumArray = function(numArray) {
    var der = '';
    if (!trusted.isArray(numArray))
        throw "Der.fromNumArray: Параметр должен быть массивом";
    for (var i = 0; i < numArray.length; i++) {
        if (!trusted.isNumber(numArray[i]))
            throw "Der.fromNumArray: Элемент массива дожен быть Числом";
        der += String.fromCharCode(numArray[i]);
    }
    return der;
};
Der.fromUint8Array = function(buf){
  return String.fromCharCode.apply(null, new Uint8Array(buf))  
};

Der.toUint8Array = function(der) {
    var buf = new ArrayBuffer(der.length);
    var bufView = new Uint8Array(buf);
    for (var i = 0; i < der.length; i++)
        bufView[i] = der.charCodeAt(i);
    return buf;
};var Hex = {}, hex_decoder;
Hex.toDer = function(a) {
    if (!Hex.test(a))
        throw "Hex.toDer: param is not Hex."
    var s = '';
    for (var i = 0; i < a.length; i = i + 2)
        s += String.fromCharCode(parseInt(a.charAt(i) + a.charAt(i + 1), 16));
    return s;
};
Hex.fromDER = function(a) {
    Hex.decode(a);
};
Hex.decode = function(a) {
    var i;
    if (hex_decoder === undefined) {
        var hex = "0123456789ABCDEF",
                ignore = " \f\n\r\t\u00A0\u2028\u2029";
        hex_decoder = [];
        for (i = 0; i < 16; ++i)
            hex_decoder[hex.charAt(i)] = i;
        hex = hex.toLowerCase();
        for (i = 10; i < 16; ++i)
            hex_decoder[hex.charAt(i)] = i;
        for (i = 0; i < ignore.length; ++i)
            hex_decoder[ignore.charAt(i)] = -1;
    }
    var out = [],
            bits = 0,
            char_count = 0;
    for (i = 0; i < a.length; ++i) {
        var c = a.charAt(i);
        if (c === '=')
            break;
        c = hex_decoder[c];
        if (c === -1)
            continue;
        if (c === undefined)
            throw 'Illegal character at offset ' + i;
        bits |= c;
        if (++char_count >= 2) {
            out[out.length] = bits;
            bits = 0;
            char_count = 0;
        } else {
            bits <<= 4;
        }
    }
    if (char_count)
        throw "Hex encoding incomplete: 4 bits missing";
    return out;
};
Hex.test = function(val) {
    var reHex = /^\s*(?:[0-9A-Fa-f][0-9A-Fa-f]\s*)+$/;
    return reHex.test(val);
};

Hex.toUint8Array = function(hex) {
    if (!Hex.test(hex))
        throw "Hex.toDer: param is not Hex.";
    var der = Hex.toDer(hex);
    return Der.toUint8Array(der);
};
Hex.fromUint8Array = function(buf) {
    var der = Der.fromUint8Array(buf);
    return Der.toHex(der);
};
// Big integer base-10 printing library
// Copyright (c) 2014 Lapo Luchini <lapo@lapo.it>

// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
// 
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
// ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
// OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

/*jshint browser: true, strict: true, immed: true, latedef: true, undef: true, regexdash: false */
(function () {
"use strict";

var max = 10000000000000; // biggest integer that can still fit 2^53 when multiplied by 256

function Int10(value) {
    this.buf = [+value || 0];
}

Int10.prototype.mulAdd = function (m, c) {
    // assert(m <= 256)
    var b = this.buf,
        l = b.length,
        i, t;
    for (i = 0; i < l; ++i) {
        t = b[i] * m + c;
        if (t < max)
            c = 0;
        else {
            c = 0|(t / max);
            t -= c * max;
        }
        b[i] = t;
    }
    if (c > 0)
        b[i] = c;
};

Int10.prototype.toString = function (base) {
    if ((base || 10) != 10)
        throw 'only base 10 is supported';
    var b = this.buf,
        s = b[b.length - 1].toString();
    for (var i = b.length - 2; i >= 0; --i)
        s += (max + b[i]).toString().substring(1);
    return s;
};

Int10.prototype.valueOf = function () {
    var b = this.buf,
        v = 0;
    for (var i = b.length - 1; i >= 0; --i)
        v = v * max + b[i];
    return v;
};

Int10.prototype.simplify = function () {
    var b = this.buf;
    return (b.length == 1) ? b[0] : this;
};

// export globals
if (typeof module !== 'undefined') { module.exports = Int10; } else { window.Int10 = Int10; }
})();

// <editor-fold defaultstate="collapsed" desc=" Constants ">
var ASN1TagClass = {
    UNIVERSAL: 0x00,
    APPLICATION: 0x01,
    CONTEXT: 0x02,
    PRIVATE: 0x03
};
var ASN1TagType = {
    EOC: 0x00,
    BOOLEAN: 0x01,
    INTEGER: 0x02,
    BIT_STRING: 0x03,
    OCTET_STRING: 0x04,
    NULL: 0x05,
    OBJECT_IDENTIFIER: 0x06,
    OBJECT_DESCRIPTOR: 0x07,
    EXTERNAL: 0x08,
    REAL: 0x09,
    ENUMERATED: 0x0A,
    EMBEDDED_PDV: 0x0B,
    UTF8_STRING: 0x0C,
    SEQUENCE: 0x10,
    SET: 0x11,
    NUMERIC_STRING: 0x12,
    PRINTABLE_STRING: 0x13,
    T61_STRING: 0x14,
    VIDEOTEX_STRING: 0x15,
    IA5_STRING: 0x16,
    UTC_TIME: 0x17,
    GENERALIZED_TIME: 0x18,
    GRAPHIC_STRING: 0x19,
    ISO64_STRING: 0x1A, //VISIBLE_STRING
    GENERAL_STRING: 0x1B,
    UNIVERSAL_STRING: 0x1C,
    BMP_STRING: 0x1E
};
// </editor-fold>

// <editor-fold defaultstate="collapsed" desc=" Basic Schemas ">
(function() {
    schemas = {};
    trusted.objEach(ASN1TagType, function(prop, propName) {
        schemas[propName] = {
            type: propName,
            tag: {
                constructed: (prop === ASN1TagType.SEQUENCE || prop === ASN1TagType.SET) ? true : false,
                number: prop,
                class: ASN1TagClass.UNIVERSAL
            },
            isSimpleType: true
        };
    });
    schemas.SEQUENCE.value = {};
    schemas.SET.value = {};
    schemas.CHOICE = {
        isChoice: true,
        explicit: true,
        type: "CHOICE",
        isSimpleType: true,
        value: {}
    };
    schemas.ANY = {
        type: "ANY",
        isAny: true,
        isSimpleType: true,
        value: {}
    };
})();
// </editor-fold>

function Schema() {
    this.value = null;

    function init(arg) {
        switch (arg.length) {
            case 0:
                throw "Schema.new: Параметр не может быть undefined."
            case 1:
                if (trusted.isString(arg[0])) {
                    this.value = compile(arg[0]);
                    break;
                }
                throw "Schema.new: Неверный тип параметра."
            default:
                throw "Schema.new: Неверное количество параметров."
        }
    }

    this.__proto__.load = function(s) {
        if (!trusted.isString(arg[0])) {
            throw "Schema.load: Неверный тип параметра."
        }
        this.value = compile(arg[0]);
    };

    function getSchema(s) {
        if (trusted.isString(s)) {
            if (s in schemas) {
                s = schemas[s];
            } else
                throw "Schema '" + s + "' was not found.";
        }
        if (trusted.isObject(s)) {
            verify(s);
            return s;
        } else
            throw "Schema has wrong data type.";
    }

    function compile(s) {
        s = getSchema(s);
        if (("type" in s) && (!s.isSimpleType)) {
            var ns = compile(s.type);
            trusted.objUnion(s, ns);
        }
        if ("value" in s) {
            trusted.objEach(s.value, function(o, n) {
                trusted.objUnion(o, compile(o));
                o.name = n;
            });
        }
        return s;
    }

    // Элкменты схемы не могут иметь атрибуты отличные от указанных
    var regWords = {
        value: null,
        type: null,
        context: null,
        default: null,
        minOccurs: null,
        maxOccurs: null,
        optional: null,
        index: null,
        constructed: null,
        isSimpleType: null,
        isChoice: null,
        isAny: null,
        tag: null,
        name: null,
        implicit: null,
        explicit: null,
        length: null
    };

    function verify(schema) {
        // Каждый элемент схемы должен иметь атрибут 'type'
        if (!schema.hasOwnProperty("type"))
            throw "Schema '" + schema.name + "' does not have attribute 'type'.";
        // Элементы типа SEQUENCE, SET, CHOICE, ANY дожны иметь атрибут 'value'
        if ((schema.hasOwnProperty("CHOICE") ||
                schema.hasOwnProperty("ANY") ||
                (schema.hasOwnProperty("SEQUENCE") || (schema.tag_class === 0 && schema.tag_number === 16)) ||
                (schema.hasOwnProperty("SET") || (schema.tag_class === 0 && schema.tag_number === 17))) &&
                !schema.hasOwnProperty("value")
                )
            throw "Schema '" + schema.name + "' does not have attribute 'value'.";
        if (("value" in schema) && !trusted.isObject(schema.value))
            throw "Schema '" + schema.name + "' value must be Object.";
        var keys = Object.keys(schema);
        for (var i = 0; i < keys.length; i++)
            if (!(keys[i] in regWords))
                throw "Schema '" + schema.name + "' has wrong value '" + keys[i] + "'";
        trusted.objEach(schema.value, function(v, n) {
            if (!trusted.isObject(v))
                throw "Schema value '" + n + "' must be Object.";
            verify(v);
        });
        if (schema.isSimpleType)
            return;
    }

    init.call(this, arguments);
}

//export
trusted.schemas = schemas;

trusted.PKI = {};

//trusted.ASN = ASN;
trusted.ASN = ASN1;
trusted.Schema= Schema;
trusted.Stream= Stream;

//window.Der = Der;
//window.Hex = Hex;
//window.Base64 = Base64;
trusted.BigInt = BigInt;
trusted.BitString = BitString;

trusted.MAX = Number.MAX_VALUE;

})();
