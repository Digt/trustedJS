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
