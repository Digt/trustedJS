(function() {
    function AccessDescription() {
        var obj;
        var cache = {};

        //location
        Object.defineProperty(this.__proto__, "location", {
            get: function() {
                if (cache.l === undefined) {
                    cache.l = new trusted.PKI.GeneralName(obj.accessLocation);
                }
                return cache.l;
            },
            set: function(v) {
            },
            enumerable: true,
            configurable: true
        });
        //  method
        Object.defineProperty(this.__proto__, "method", {
            get: function() {
                if (cache.m === undefined) {
                    cache.m = new trusted.PKI.OID(obj.accessMethod);
                }
                return cache.m;
            },
            set: function(v) {
            },
            enumerable: true,
            configurable: true
        });

        this.__proto__.toObject = function() {
            var o = {};
            o.accessLocation = this.location.toObject();
            o.accessMethod = this.method.toObject();
            return o;
        };

        //method

        // Inicialization
        function init(v) {
            if (v === undefined)
                throw "AccessDescription.new: parameter can not be undefined."
            if (trusted.isString(v))
                v = (new trusted.ASN(v)).toObject("AccessDescription");
            if (!trusted.isObject(v) && !("accessLocation" in v && "accessMethod" in v))
                throw "AccessDescription.new: parameter is not valid."
            obj = v;
        }

        init.call(this, arguments[0]);
    }

    function InfoAccess() {
        var obj;

        // description
        Object.defineProperty(this.__proto__, "descriptions", {
            get: function() {
                return obj;
            },
            set: function(v) {
            },
            enumerable: true
        });

        this.__proto__.toObject = function() {
            var o = [];

            for (var i = 0; i < obj.length; i++)
                o.push(this.descriptions[i]);

            return o;
        };

        // Inicialization
        function init(v) {
            if (v === undefined)
                throw "InfoAccess.new: parameter can not be undefined."
            if (trusted.isString(v))
                v = (new trusted.ASN(v)).toObject("AuthorityInfoAccessSyntax");
            if (!trusted.isArray(v))
                throw "AuthorityInfoAccess.new: parameter is not valid."

            obj = [];
            for (var i = 0; i < v.length; i++)
                obj.push(new AccessDescription(v[i]));
        }

        init.call(this, arguments[0]);
    }

    // export
    trusted.PKI.AccessDescription = AccessDescription;
    trusted.PKI.AuthorityInfoAccess = InfoAccess;
    trusted.PKI.SubjectInfoAccess = InfoAccess;
})();


