(function() {

    function BasicConstraints() {
        var obj, cache = {};
        this.__proto__ = {
            set CA(v) {
            },
            get CA() {
                return obj.cA;
            },
            set pathLength(v) {
            },
            get pathLength() {
                if (cache.pl === undefined) {
                    cache.pl = null;
                    if (obj.pathLenConstraint !== undefined)
                        cache.pl = obj.pathLenConstraint;
                }
                return cache.pl;
            }
        };

        this.__proto__.toObject = function() {
            return {cA: this.CA, pathLenConstraint: this.pathLength};
        };

        function init(v) {
            // Проверка аргумента
            if (v === undefined)
                throw "BasicConstraints.new: parameter can not be undefined."
            v = objFromBuffer(v, "BasicConstraints");
            if (!trusted.isObject(v) && !("cA" in v))
                throw "BasicConstraints.new: parameter is not valid."
            obj = v;
        }

        init.call(this, arguments[0]);
    }

    trusted.PKI.BasicConstraints = BasicConstraints;
})();

