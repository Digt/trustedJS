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
})();