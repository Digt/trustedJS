(function() {

    function IssuerAlternativeName() {
        var obj, version, gns;
        this.__proto__ = {
            set generalNames(v) {
            },
            get generalNames() {
                if (gns === undefined) {
                    switch (this.version) {
                        case 1:
                            gns = new trusted.PKI.GeneralNames([{directoryName:obj}]);
                            break;
                        default:
                            gns = new trusted.PKI.GeneralNames(obj);
                    }
                }
                return gns.generalNames;
            },
            set version(v) {
            },
            get version() {
                return version;
            }
        };

        this.__proto__.toString = function() {
            this.generalNames;
            return gns.toString();
        };

        this.__proto__.toObject = function() {
            switch (this.version) {
                case 1:
                    return this.generalNames[0].name.toObject();
                default:
                    this.generalNames;
                    return gns.toObject();
            }
        };

        function init(v, oid) {
            if (oid === undefined)
                oid = "2.5.29.18";
            var schema;
            switch (oid) {
                case "2.5.29.8":
                    schema = "IssuerAlternativeName1";
                    version = 1;
                    break;
                default:
                    schema = "IssuerAlternativeName2";
                    version = 2;
            }
            // Проверка аргумента
            if (v === undefined)
                throw "IssuerName.new: parameter can not be undefined."
            v = objFromBuffer(v, schema);
            if (!trusted.isObject(v) && !trusted.isArray(v))
                throw "IssuerAlternativeName.new: parameter is not valid."
            obj = v;
        }

        init.call(this, arguments[0], arguments[1]);
    }

    trusted.PKI.IssuerAlternativeName = IssuerAlternativeName;
})();

