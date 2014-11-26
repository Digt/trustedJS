(function() {

    function ExtendedKeyUsage() {
        var obj;
        this.__proto__ = {
            set anyExtendedKeyUsage(v) {
            },
            get anyExtendedKeyUsage() {
                return obj;
            },
            set items(v) {
            },
            get items() {
                return obj;
            }
        };

        this.__proto__.toObject = function() {
            var o = [];
            for (var i = 0; i < this.anyExtendedKeyUsage.length; i++)
                o.push(this.anyExtendedKeyUsage[i].value);
            return o;
        };

        this.__proto__.toString = function() {
            var s = '';
            var l = this.anyExtendedKeyUsage.length;
            for (var i = 0; i < l; i++)
                s += this.anyExtendedKeyUsage[i].toString() + (i !== (l - 1) ? ';' : '');
            return s;
        };

        function init(v) {
            if (v === undefined)
                throw "ExtendedKeyUsage.new: parameter can not be undefined."
            v = objFromBuffer(v, "ExtKeyUsageSyntax");
            if (!(trusted.isObject(v)) && trusted.isArray(v))
                throw "ExtendedKeyUsage.new: parameter is not valid."
            obj = [];
            for (var i = 0; i < v.length; i++) {
                obj.push(new trusted.PKI.OID(v[i]));
            }
        }

        init.call(this, arguments[0]);
    }

    trusted.PKI.ExtendedKeyUsage = ExtendedKeyUsage;
})();

