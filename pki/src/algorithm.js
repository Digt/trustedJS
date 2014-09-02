(function(){
    function Algorithm() {
        var obj;
        var alg;

        this.__proto__ = {
            set algorithm(v) {
            },
            get algorithm() {
                if (alg === undefined)
                    alg = new trusted.PKI.OID(obj.algorithm);
                return alg;
            },
            set params(v) {
            },
            get params() {
                if (this.hasParams())
                    return obj.parameters;
                return null;
            }
        };
        
        this.__proto__.hasParams = function(){
            return obj.parameters !== undefined;
        };
        
        this.__proto__.toString=function(){
            return this.algorithm.name;
        };

        function init(v) {
            // Проверка аргумента
            if (v === undefined)
                throw "Algorithm.new: parameter can not be undefined."
            if (trusted.isString(v)) {
                var asn = new trusted.ASN(v);
                v = asn.toObject("AlgorithmIdentifier");
            }
            if (!((trusted.isObject(v)) && ("algorithm" in v)))
                throw "Algorithm.new: parameter is not valid."
            obj = v;
        }

        init.call(this, arguments[0]);
    }
    
    trusted.PKI.Algorithm = Algorithm;
})();
