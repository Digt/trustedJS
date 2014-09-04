(function() {

    function PublicKey() {
        var obj, alg;

        this.__proto__ = {
            set algorith(v) {
            },
            get algorithm() {
                if (alg === undefined)
                    alg = new trusted.PKI.Algorithm(obj.algorithm);
                return alg;
            },
            set key(v) {
            },
            get key() {
                return obj.subjectPublicKey;
            }
        };

        this.__proto__.toString = function() {
            var res = '';
            switch (this.algorithm.OID.value) {
                case "1.2.840.113549.1.1.1":
                    var asn = new trusted.ASN(this.key.encoded);
                    var RSAPublicKey = asn.toObject("RSAPublicKey");
                    var r = /(00)*([A-F0-9]+)/i;
                    var m = r.exec(RSAPublicKey.modulus);
                    res = " (" + (((m[m.length - 1].length) / 2) * 8) + " Bits)";
                    break;
                case "1.2.643.2.2.19":
                    var asn = new trusted.ASN(this.key.encoded);
                    var GOSTPublicKey = asn.toObject("GOSTPublicKey");
                    res = " (" + (((GOSTPublicKey.length) / 2) * 8) + " Bits)";
                    break;
                default:
                    res = this.key.toString();
            }
            return this.algorithm.OID.toString() + res;
        };

        this.__proto__.toObject = function() {
            var o = {
                algorithm: this.algorithm.toObject(),
                subjectPublicKey: this.key
            };
            return o;
        };

        function init(v) {
            // Проверка аргумента
            if (v === undefined)
                throw "PublicKey.new: parameter can not be undefined."
            if (trusted.isString(v)) {
                var asn = new trusted.ASN(v);
                v = asn.toObject("AlgorithmIdentifier");
            }
            if (!((trusted.isObject(v)) && ("algorithm" in v) && ("subjectPublicKey" in v)))
                throw "PublicKey.new: parameter is not valid."
            obj = v;
        }

        init.call(this, arguments[0]);
    }
    ;

    trusted.PKI.PublicKey = PublicKey;

})();