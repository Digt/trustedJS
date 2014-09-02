(function() {
    function IssuerSignTool() {
        var obj;

        this.__proto__ = {
            set signTool(v) {
            },
            get signTool() {
                return obj.signTool;
            },
            set CATool(v) {
            },
            get CATool() {
                return obj.cATool;
            },
            set signToolCert(v) {
            },
            get signToolCert() {
                return obj.signToolCert;
            },
            set CAToolCert(v) {
            },
            get CAToolCert() {
                return obj.cAToolCert;
            }
        };

        this.__proto__.toObject = function() {
            var obj = {
                cAToolCert: this.CAToolCert,
                signToolCert: this.signToolCert,
                cATool: this.CATool,
                signTool: this.signTool
            };
            return obj;
        };

        this.__proto__.toString = function() {
            var s = 'Extension SubjectSignTool(1.2.643.100.111):';
            s += 'CAToolCert=' + this.CAToolCert + ';';
            s += 'signToolCert=' + this.signToolCert + ';';
            s += 'CATool=' + this.CATool + ';';
            s += 'signTool=' + this.signTool;
            return s;
        };

        function init(v) {
            if (v === undefined) {
                throw "IssuerSignTool.new: parameter can not be undefined."
            }
            if (trusted.isString(v)) {
                var asn = new trusted.ASN(v);
                v = asn.toObject("IssuerSignTool");
            }
            if (!(trusted.isObject(v) && (("signTool" in v) || ("cATool" in v) ||
                    ("signToolCert" in v) || ("cAToolCert" in v))))
                throw "IssuerSignTool.new: parameter is not valid."
            obj = v;
        }

        init.call(this, arguments[0]);
    }

    trusted.PKI.IssuerSignTool = IssuerSignTool;
})();