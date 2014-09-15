function SignerAttribute() {
    var obj;
    var a;
    var cache;

    // pubkic properties
    this.__proto__ = {
        get signed() {
            return a;
        },
        get OID() {
            if (cache.OID === undefined) {
                cache.OID = new trusted.PKI.OID(obj.type);
            }
            return cache.OID;
        },
        get value() {
            if (cache.value === undefined) {
                cache.value = obj.values[0];
            }
            return cache.value;
        }
    };

    this.__proto__.toObject = function() {
        var o = {
            type: this.OID.value,
            values: [this.value]

        };
        return o;
    };

    this.__proto__.toString = function() {
        var s = "Attribute: OID=" + this.OID.toString();
        s += "; signed=" + (this.signed ? "true" : "false");
        s += "; value=" + Der.toHex(this.value);
        return s;
    };

    function init(args) {
        switch (args.length) {
            case 0:
                throw "SignerAttribute.new: Параметр не может быть Undefined."
            default:
                if (args.length === 1)
                    a = false;
                else
                    a = args[1];
                if (trusted.isString(args[0])) {
                    var asn = new trusted.ASN(args[0]);
                    args[0] = asn.toObject("Attribute");
                }
                if (!(trusted.isObject(args[0]) && ("values" in args[0] && "type" in args[0])))
                    throw "SignerAttribute.new: Неверный параметр."
        }
        obj = args[0];
        cache = {};
    }

    init.call(this, arguments);
}