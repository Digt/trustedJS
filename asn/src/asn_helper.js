function ASN() {
    this.structure;
    this.__proto__.toObject = function(schema) {
        if (this.structure === undefined)
            throw "ASN.toObject: ASN structure is not initialized. Call import method first."
        return ASNToObject(this.structure, schema);
    };
    this.__proto__.import = function(a) {
        if (a !== undefined) {
            if (typeof (a) !== "string")
                throw "ASN.toObject: param must be String.";
            this.structure = ASN1.decode(a);
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
    
    if (s.isAny){
        o = a.encode();
        return o;
    }

    if (!isTagEquals(a, s))
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
                if (!("optional"in value || "default" in value))
                    throw svt + " Элемент ASN не соответсвует схеме";
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
        o = ("context" in s) ? a.parseSimpleType(s.tag.number) : a.content();

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
    return ((a.tag.class === s.tag.class &&
            a.tag.number === s.tag.number &&
            a.tag.constructed === s.tag.constructed) ||
            ("context"in s && a.tag.constructed === s.tag.constructed)); // для CONTENT-SPECIFIC проверить только constructed
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
    if (s.name === "bool")
        "";
    //console.log(schema.name);

    if (s.isChoice) {
        var keys = Object.keys(o);
        if (keys.length !== 1)
            throw ovt + "Кодируемый объект может иметь только одно значение.";
        if (!(keys[0]in s.value))
            throw ovt + "Значение объект не соответствует схеме CHOICE.";
        var a = otoa(o[keys[0]], s.value[keys[0]]);
        if ("context" in s)
            a=encodeExplicit(s.context, a);
        return a;
    }
    
    if (s.isAny){
        return encode(o,s);
    }

    if (s.tag.constructed) {
        var values = (s.tag.class === 0 && s.tag.number === 16) ? sortSequenceElements(s) : trusted.objToArray(s.value);
        var sub = [];
        var step = 0;
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
                step++;
                continue;
            }

            if (value.hasOwnProperty("default")) {
                if (value.default === o[value.name]) {
                    step++;
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
    if (schema.name==="ch1")
        "";
    var asn = [];
    
    if (schema.isAny) { //encode ANY
        try { //Check for ASN
            new trusted.ASN(obj);
        } catch (e) {
            throw("ASN.encode: ANY has wrong data. It must have ASN DER string.");
        }
        for (var i = 0; i < obj.length; i++) // convert DER to NumArray
            asn.push(obj.charCodeAt(i));
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
            if (schema.explicit) {
                var ev = []; //explicit value
                ev.push(encodeTag(schema.tag.class, schema.tag.constructed, schema.tag.number)); //tag
                ev = ev.concat(encodeLength(obj.length)); // length
                obj = ev.concat(obj); // value
            }
            if (!schema.implicit) {
                if ("context" in schema)
                    if (schema.explicit)
                        asn.push(encodeTag(0x02, true, schema.context)); //tag
                    else
                        asn.push(encodeTag(0x02, schema.tag.constructed, schema.context)); //tag
                else
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
    fd += formatNum(val.getMonth());
    fd += formatNum(val.getDate());
    fd += formatNum(val.getHours());
    fd += formatNum(val.getMinutes());
    fd += formatNum(val.getSeconds());
    fd += "Z";
    return encodeStringISO(fd);
}

// </editor-fold>

