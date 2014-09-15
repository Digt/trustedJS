
trusted.PKI.GeneralNameType = {
    OtherName: 0,
    RFC822Name: 1,
    DNSName: 2,
    X400Address: 3,
    DirectoryName: 4,
    EDIPartyName: 5,
    UniformResourceIdentifier: 6,
    IPAddress: 7,
    RegisteredID: 8
};

(function(undefined) {

    // <editor-fold defaultstate="collapsed" desc=" RDNAttribute ">
    function RDNAttribute() {
        var obj;
        this.__proto__ = {
            set type(v) {
            },
            get type() {
                return obj.type;
            },
            set OID(v) {
            },
            get OID() {
                return obj.type;
            },
            set value(v) {
            },
            get value() {
                return obj.value;
            },
            get text() {
                return valueToString(this.value, '+');
            }
        };

        this.__proto__.toObject = function() {
            return {type: this.type.value, value: this.value};
        };

        this.__proto__.format = function(seporator, oids) {
            if (trusted.isObject(seporator) && oids === undefined) {
                oids = seporator;
                seporator = undefined;
            }
            if (seporator === undefined)
                seporator = '+';
            var str = '';
            str = valueToString(this.value, seporator);
            var oidName = this.type.value; //Если oids задан, то использовать только его значения
            if (trusted.isObject(oids)) {
                if (oidName in oids)
                    oidName = oids[oidName];
            } else
                oidName = this.type.name;
            return  oidName + "=" + str;
        };
        this.__proto__.toString = function() {
            return this.format();
        };


        function valueToString(v, seporator) {
            var res = '';
            var asn = new trusted.ASN(v).structure;
            if (asn.tag.isUniversal())
                if (!asn.tag.constructed) // Определение простого типа
                    switch (asn.tag.number) {
                        case 0x02: // INTEGER
                            res = asn.content().toString();
                            break;
                        case 0x0C: // UTF8String
                        case 0x12: // NumericString
                        case 0x13: // PrintableString
                        case 0x14: // TeletexString
                        case 0x15: // VideotexString
                        case 0x16: // IA5String
                            //case 0x19: // GraphicString
                        case 0x1A: // VisibleString
                            //case 0x1B: // GeneralString
                            //case 0x1C: // UniversalString
                        case 0x1E: // BMPString
                        case 0x17: // UTCTime
                        case 0x18: // GeneralizedTime
                            res = asn.content();
                            break;
                        default:
                            res = "trusted: Unknown type";
                    }
                else {
                    for (var i = 0; i < asn.sub.length; i++) { // структуру выводим в виде массива через разделитель.
                        var content = asn.sub[i].content();
                        res += (i !== 0) ? seporator + content : content;
                    }
                }
            return res;
        }
        //Counstructor
        function init(v) {
            // Проверка аргумента
            if (v === undefined)
                throw "RDNAttribute.new: parameter can not be undefined."
            if (typeof (v) === "string")
                v = (new trusted.ASN(v)).toObject("AttributeTypeAndValue");
            if (typeof (v) !== "object" &&
                    !(v.hasOwnProperty("type") || v.hasOwnProperty("value")))
                throw "RDNAttribute.new: parameter is not valid."
            if (trusted.isString(v.type))
                v.type = new trusted.PKI.OID(v.type);
            obj = v;
        }


        init.call(this, arguments[0]);
    }
    trusted.PKI.RDNAttribute = RDNAttribute;
    // </editor-fold>

    // <editor-fold defaultstate="collapsed" desc=" RDN ">
    function RDN() {
        var obj;
        this.__proto__ = {
            set attributes(v) {
            },
            get attributes() {
                return obj;
            }
        };
        this.__proto__.toObject = function() {
            var obj = [];
            for (var i = 0; i < this.attributes.length; i++)
                obj.push(this.attributes[i].toObject());
            return obj;
        };
        this.__proto__.format = function(seporator, oids) {
            if (trusted.isObject(seporator) && oids === undefined) {
                oids = seporator;
                seporator = undefined;
            }
            if (seporator === undefined)
                seporator = ";";
            var str = "";
            for (var i = 0; i < obj.length; i++) {
                var attr = obj[i].format("+", oids);
                str += (i !== 0) ? seporator + attr : attr;
            }
            return str;
        };
        this.__proto__.toString = function() {
            return this.format();
        };

        this.__proto__.getAttributes = function(oid) {
            if (trusted.isString(oid))
                oid = new trusted.PKI.OID(oid);
            if (!(trusted.isObject(oid)))
                throw "Name.getAttribute: Параметр oid имеет неверное значение"
            var res = [];
            for (var i = 0; i < this.attributes.length; i++) {
                if (this.attributes[i].type.value === oid.value)
                    res.push(this.attributes[i]);
            }
            return res;
        };

        function init(v) {
            // Проверка аргумента
            if (v === undefined)
                throw "RDN.new: parameter can not be undefined."
            if (trusted.isString(v))
                v = (new trusted.ASN(v)).toObject("RelativeDistinguishedName");
            if (!trusted.isObject(v) && !trusted.isArray(v) ||
                    v.length === 0 ||
                    (v.length !== 0 &&
                            !(v[0].hasOwnProperty("type") || v[0].hasOwnProperty("value"))))
                throw "RDN.new: parameter is not valid."
            obj = [];
            for (var i = 0; i < v.length; i++)
                obj.push(new trusted.PKI.RDNAttribute(v[i]));
        }

        init.call(this, arguments[0]);
    }
    trusted.PKI.RDN = RDN;
    // </editor-fold>

    // <editor-fold defaultstate="collapsed" desc=" Name ">
    function Name() {
        var obj;

        this.__proto__ = {
            set RDNs(v) {
            },
            get RDNs() {
                return obj;
            }
        };

        this.__proto__.toObject = function() {
            var obj = [];
            for (var i = 0; i < this.RDNs.length; i++)
                obj.push(this.RDNs[i].toObject());
            return {rdnSequence: obj};
        };

        this.__proto__.format = function(seporator, oids) {
            if (trusted.isObject(seporator) && oids === undefined) {
                oids = seporator;
                seporator = undefined;
            }
            if (seporator === undefined)
                seporator = ";";
            var str = "";
            for (var i = 0; i < obj.length; i++) {
                var attr = obj[i].format("+", oids);
                str += (i !== 0) ? seporator + attr : attr;
            }
            return str;
        };
        this.__proto__.toString = function() {
            return this.format();
        };

        this.__proto__.getAttributes = function(oid) {
            var res = [];
            for (var i = 0; i < this.RDNs.length; i++) {
                res = res.concat(this.RDNs[i].getAttributes(oid));
            }
            return res;
        };

        function init(v) {
            // Проверка аргумента
            if (v === undefined)
                throw "Name.new: parameter can not be undefined."
            if (trusted.isString(v)) {
                var asn = new trusted.ASN(v);
                v = asn.toObject("Name");
            }
            if (!("rdnSequence" in v) && !trusted.isArray(v.rdnSequence) &&
                    v.length !== 0)
                throw "Name.new: parameter is not valid."
            obj = [];
            for (var i = 0; i < v.rdnSequence.length; i++)
                obj.push(new trusted.PKI.RDN(v.rdnSequence[i]));
        }

        init.call(this, arguments[0]);
    }

    trusted.PKI.Name = Name;
    // </editor-fold>

    // <editor-fold defaultstate="collapsed" desc=" GeneralName ">

    function GeneralName() {
        var obj;
        var directoryName;
        var registeredID;

        this.__proto__ = {
            set name(v) {
            },
            get name() {
                switch (this.type) {
                    case trusted.PKI.GeneralNameType.OtherName:
                        return new trusted.PKI.OtherName(obj.otherName);
                    case trusted.PKI.GeneralNameType.RFC822Name:
                        return obj.rfc822Name;
                    case trusted.PKI.GeneralNameType.DNSName:
                        return obj.dNSName;
                    case trusted.PKI.GeneralNameType.DirectoryName:
                        //cache
                        if (directoryName === undefined)
                            directoryName = new trusted.PKI.Name(obj.directoryName);
                        return directoryName;
                    case trusted.PKI.GeneralNameType.UniformResourceIdentifier:
                        return obj.uniformResourceIdentifier;
                    case trusted.PKI.GeneralNameType.IPAddress:
                        var ip = obj.iPAddress;
                        ip.__proto__.toString = function() {
                            return Der.toHex(ip);
                        };
                        return ip;
                    case trusted.PKI.GeneralNameType.RegisteredID:
                        if (registeredID === undefined)
                            registeredID = new trusted.PKI.OID(obj.registeredID);
                        return registeredID;
                }
            },
            set type(v) {
            },
            get type() {
                var key = Object.keys(obj)[0];
                switch (key) {
                    case "otherName":
                        return trusted.PKI.GeneralNameType.OtherName;
                    case "rfc822Name":
                        return trusted.PKI.GeneralNameType.RFC822Name;
                    case "dNSName":
                        return trusted.PKI.GeneralNameType.DNSName;
                    case "x400Address":
                        return trusted.PKI.GeneralNameType.X400Address;
                    case "directoryName":
                        return trusted.PKI.GeneralNameType.DirectoryName;
                    case "ediPartyName":
                        return trusted.PKI.GeneralNameType.ediPartyName;
                    case "uniformResourceIdentifier":
                        return trusted.PKI.GeneralNameType.UniformResourceIdentifier;
                    case "iPAddress":
                        return trusted.PKI.GeneralNameType.IPAddress;
                    case "registeredID":
                        return trusted.PKI.GeneralNameType.RegisteredID;
                    default:
                        throw "GeneralName.type: Unknown type '" + key + "'";
                }
            }
        };

        this.__proto__.toObject = function() {
            switch (this.type) {
                case trusted.PKI.GeneralNameType.OtherName:
                    return {otherName: this.name.toObject()};
                case trusted.PKI.GeneralNameType.RFC822Name:
                    return {rfc822Name: this.name};
                case trusted.PKI.GeneralNameType.DNSName:
                    return {dNSName: this.name};
                case trusted.PKI.GeneralNameType.DirectoryName:
                    return {directoryName: this.name.toObject()};
                case trusted.PKI.GeneralNameType.UniformResourceIdentifier:
                    return {uniformResourceIdentifier: this.name};
                case trusted.PKI.GeneralNameType.IPAddress:
                    return {iPAddress: this.name};
                case trusted.PKI.GeneralNameType.RegisteredID:
                    return {registeredID: this.name.value};
            }
        };

        function init(v) {
            // Проверка аргумента
            if (v === undefined)
                throw "GeneralName.new: parameter can not be undefined."
            if (trusted.isString(v)) {
                var asn = new trusted.ASN(v);
                v = asn.toObject("GeneralName");
            }
            if (!trusted.isObject(v) && !trusted.isArray(v) &&
                    v.length !== 0)
                throw "GeneralName.new: parameter is not valid."
            obj = v;
            this.type; // check for known types only
        }

        function createIsFunctions(v) {
            var keys = Object.keys(v);
            for (var i = 0; i < keys.length; i++) {
                var index = i; // Создаем копию i, иначе все функции будут использовать i = keys.
                this.__proto__["is" + keys[index]] = new Function("return this.type===" + v[keys[index]]);
            }
        }

        createIsFunctions.call(this, trusted.PKI.GeneralNameType);

        this.__proto__.toString = function() {
            switch (this.type) {
                case trusted.PKI.GeneralNameType.RFC822Name:
                case trusted.PKI.GeneralNameType.DNSName:
                case trusted.PKI.GeneralNameType.UniformResourceIdentifier:
                    return this.name;
                case trusted.PKI.GeneralNameType.OtherName:
                case trusted.PKI.GeneralNameType.DirectoryName:
                case trusted.PKI.GeneralNameType.RegisteredID:
                    return this.name.toString();
                case trusted.PKI.GeneralNameType.IPAddress:
                    return this.name.toString();
            }
        };

        init.call(this, arguments[0]);
    }

    trusted.PKI.GeneralName = GeneralName;
    // </editor-fold>

    // <editor-fold defaultstate="collapsed" desc=" GeneralNames ">
    function GeneralNames() {
        var obj;
        this.__proto__ = {
            set generalNames(v) {
            },
            get generalNames() {
                return obj;
            },
            set items(v){},
            get items(){
                return this.generalNames();
            }
        };
        this.__proto__.toString = function() {
            var s = '';
            for (var i = 0; i < this.generalNames.length; i++)
                s += this.generalNames[i].toString() + ((i !== (this.generalNames.length - 1)) ? ";" : "");
            return s;
        };

        this.__proto__.toObject = function() {
            var obj = [];
            for (var i = 0; i < this.generalNames.length; i++)
                obj.push(this.generalNames[i].toObject());
            return obj;
        };

        function init(v) {
            // Проверка аргумента
            if (v === undefined)
                throw "GeneralNames.new: parameter can not be undefined."
            if (trusted.isString(v))
                v = (new trusted.ASN(v)).toObject("GeneralNames");
            if (!(trusted.isArray(v) && v.length !== 0))
                throw "GeneralNames.new: parameter is not valid."
            obj = [];
            for (var i = 0; i < v.length; i++)
                obj.push(new trusted.PKI.GeneralName(v[i]));
        }

        init.call(this, arguments[0]);
    }
    trusted.PKI.GeneralNames = GeneralNames;
    // </editor-fold>

    // <editor-fold defaultstate="collapsed" desc=" OtherName ">
    function OtherName() {
        var obj, tid;

        this.__proto__ = {
            set typeID(v) {
            },
            get typeID() {
                if (tid === undefined)
                    tid = new trusted.PKI.OID(obj.typeId);
                return tid;
            },
            set OID(v) {
            },
            get OID() {
                return this.typeID;
            },
            set value(v) {
            },
            get value() {
                return obj.value;
            }
        };

        this.__proto__.toString = function() {
            return this.typeID.name + "=" + Der.toHex(this.value);
        };

        this.__proto__.toObject = function() {
            return {typeId: this.typeID.value, value: this.value};
        };

        function init(v) {
            // Проверка аргумента
            if (v === undefined)
                throw "OtherName.new: parameter can not be undefined."
            if (trusted.isString(v)) {
                var asn = new trusted.ASN(v);
                v = asn.toObject("OtherName");
            }
            if (!(trusted.isObject(v) && ("typeId" in v) && ("value" in v)))
                throw "OtherName.new: parameter is not valid."
            obj = v;
        }

        init.call(this, arguments[0]);
    }
    trusted.PKI.OtherName = OtherName;
    // </editor-fold>

})();


