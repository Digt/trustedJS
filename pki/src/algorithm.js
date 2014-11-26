(function() {
    function Algorithm() {
        var obj;
        var cache;
        var alg;

        this.__proto__ = {
            set OID(v) {
            },
            get OID() {
                if (alg === undefined)
                    alg = new trusted.PKI.OID(obj.algorithm);
                return alg;
            },
            get name() {
                if (obj.name !== undefined)
                    return obj.name;
                return this.OID.name;
            },
            get hash() {
                if (cache.hash === undefined) {
                    cache.hash = null;
                    if (obj.hash !== undefined)
                        cache.hash = Algorithm.fromName(obj.hash);
                }
                return cache.hash;
            },
            get params() {
                if (this.hasParams() && obj.parameters !== Hex.toDer("0500"))
                    return obj.parameters;
                return null;
            },
            get type() {
                return "Algorithm";
            }
        };

        this.__proto__.hasParams = function() {
            return obj.parameters !== undefined;
        };

        this.__proto__.toString = function() {
            return this.OID.name;
        };

        this.__proto__.toObject = function() {
            var o = {
                algorithm: this.OID.toObject(),
                parameters: (Der.toHex(this.params) === "0500" ? Hex.toDer("0500") : this.params),
                //name: this.name,
                //hash: {name: this.hash}
            };
            return o;
        };

        this.__proto__.toCrypto = function() {
            var err_t = "Algorithm.toCrypto: ";
            switch (trusted.Crypto.type) {
                case "webcrypto":
                    var a = trusted.Algorithms.getAlgorithm(this.name);
                    var o = {
                        name: a.n.wc
                    };
                    if ("h" in a)
                        o.hash = {name: a.h.n.wc};
                    return o;
                case "nodejs":
                    return trusted.Algorithms.getAlgorithm(this.name).n.njs;
                default:
                    throw err_t + "Unknown algorithm type";
            }
        };

        function init(v) {
            // Проверка аргумента
            if (v === undefined)
                throw "Algorithm.new: parameter can not be undefined."
            cache = {};
            v = objFromBuffer(v, "AlgorithmIdentifier");
            if (!((trusted.isObject(v)) && ("algorithm" in v)))
                throw "Algorithm.new: parameter is not valid."
            try {
                var alg = AlgorithmFromOID(v.algorithm);
                if (alg !== null)
                    v = alg;
            } catch (e) {
                console.error(e);

            }
            obj = v;
        }

        init.call(this, arguments[0]);
    }

    AlgorithmFromName = function(name) {
        var err_t = "Algorithm.fromName: ";
        if (name === undefined)
            throw err_t + "Parameter 'name' can't be undefined"
        var a = trusted.Algorithms.getAlgorithm(name);
        var o = {
            algorithm: a.o,
            parameters: null,
            name: a.n.f
        };
        if ("h" in a) // has hash algorithm
            o.hash = a.h.n.f;
        return o;
    };

    Algorithm.fromName = function(name) {
        return new Algorithm(AlgorithmFromName(name));
    };

    function AlgorithmFromOID(oid) {
        var err_t = "Algorithm.fromOID: ";
        if (!trusted.isObject(oid))
            oid = new trusted.PKI.OID(oid);
        if (oid.type !== "OID")
            throw err_t + "Parameter 'oid' must be OID type"
        var keys = Object.keys(trusted.Algorithms);
        for (var i = 0; i < keys.length; i++) {
            var alg = trusted.Algorithms[keys[i]];
            if (typeof (alg) !== "function" && trusted.isObject(alg))
                if (alg.o === oid.value)
                    return AlgorithmFromName(keys[i]);
        }
        return null;
    }

    Algorithm.fromOID = function(oid) {
        return new Algorithm(AlgorithmFromOID(oid));
    };

    trusted.PKI.Algorithm = Algorithm;
})();
