(function() {
    function AccessDescription() {
        var obj;
        var cache = {};

        this.__proto__ = {
            get location() {
                if (cache.l === undefined) {
                    cache.l = new trusted.PKI.GeneralName(obj.accessLocation);
                }
                return cache.l;
            },
            set location(v) {
            },
            get method() {
                if (cache.m === undefined) {
                    cache.m = new trusted.PKI.OID(obj.accessMethod);
                }
                return cache.m;
            },
            set method(v) {
            }
        };

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
            if (!(trusted.isObject(v) && ("accessLocation" in v && "accessMethod" in v)))
                throw "AccessDescription.new: parameter is not valid."
            obj = v;
        }

        init.call(this, arguments[0]);
    }

    function InfoAccess() {
        var obj;

        this.__proto__ = {
            get descriptions() {
                return obj;
            },
            set descriptions(v) {
            }
        };

        this.__proto__.toObject = function() {
            var o = [];

            for (var i = 0; i < this.descriptions.length; i++)
                o.push(this.descriptions[i].toObject());

            return o;
        };

        // Inicialization
        function init(v) {
            if (v === undefined)
                throw "InfoAccess.new: parameter can not be undefined."
            v = objFromBuffer(v, "AuthorityInfoAccessSyntax");
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


