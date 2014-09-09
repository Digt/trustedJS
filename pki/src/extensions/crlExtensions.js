trusted.PKI.CRLReason = {
    Unspecified: 0,
    KeyCompromise: 1,
    CACompromise: 2,
    AffiliationChanged: 3,
    Superseded: 4,
    CessationOfOperation: 5,
    CertificateHold: 6,
    RemoveFromCRL: 8,
    PrivilegeWithdrawn: 9,
    AACompromise: 10
};

(function() {

    function CRLNumber() {
        var obj;

        this.__proto__ = {
            set value(v) {
            },
            get value() {
                return obj;
            }
        };

        this.__proto__.toObject = function() {
            var o = this.value;
            return o;
        };

        function init(v) {
            if (v === undefined)
                throw "CRLNumber.new: parameter can not be undefined."
            if (trusted.isString(v) && !Hex.test(v)) {
                var asn = new trusted.ASN(v);
                v = asn.toObject("CRLNumber");
            }
            if (!(trusted.isNumber(v) || trusted.isString(v)))
                throw "CRLNumber.new: parameter is not valid."
            obj = v;
        }

        init.call(this, arguments[0]);
    }

    function IssuingDistributionPoint() {
        var obj;
        var cache;

        this.__proto__ = {
            set pointName(v) {
            },
            get pointName() {
                if (cache.pn === undefined) {
                    cache.pn = null;
                    if (obj.distributionPoint !== null) {
                        cache.pn = obj.distributionPoint.fullName;
                    }
                }
                return cache.pn;
            },
            set onlyContainsUserCerts(v) {
            },
            get onlyContainsUserCerts() {
                return obj.onlyContainsUserCerts;
            },
            set onlyContainsCACerts(v) {
            },
            get onlyContainsCACerts() {
                return obj.onlyContainsCACerts;
            },
            set onlySomeReasons(v) {
            },
            get onlySomeReasons() {
                if (cache.rs === undefined) {
                    cache.rs = null;
                    if (obj.onlySomeReasons !== null)
                        cache.rs = obj.onlySomeReasons.toNumber();
                }
                return cache.rs;
            },
            set indirectCRL(v) {
            },
            get indirectCRL() {
                return obj.indirectCRL;
            },
            set onlyContainsAttributeCerts(v) {
            },
            get onlyContainsAttributeCerts() {
                return obj.onlyContainsAttributeCerts;
            }
        };

        this.__proto__.toObject = function() {
            var o = {};
            if (this.pointName !== null)
                o.distributionPoint = {fullName: this.pointName};
            if (this.onlyContainsUserCerts !== null)
                o.onlyContainsUserCerts = this.onlyContainsUserCerts;
            if (this.onlyContainsCACerts !== null)
                o.onlyContainsCACerts = this.onlyContainsCACerts;
            if (this.onlySomeReasons !== null)
                o.onlySomeReasons = new BitString(this.onlyContainsCACerts);
            if (this.indirectCRL !== null)
                o.indirectCRL = this.indirectCRL;
            if (this.onlyContainsAttributeCerts !== null)
                o.onlyContainsAttributeCerts = this.onlyContainsAttributeCerts;
            return o;
        };

        function init(v) {
            if (v === undefined)
                throw "IssuingDistributionPoint.new: parameter can not be undefined."
            if (trusted.isString(v) && !Hex.test(v)) {
                var asn = new trusted.ASN(v);
                v = asn.toObject("IssuingDistributionPoint");
            }
            if (!(trusted.isObject(v)))
                throw "IssuingDistributionPoint.new: parameter is not valid."

            cache = {};
            obj = v;
        }

        init.call(this, arguments[0]);
    }

    // revoced cert extensions
    //RevocedCode 2.5.29.21
    function ReasonCode() {
        var obj;

        this.__proto__ = {
            set value(v) {
            },
            get value() {
                return obj;
            }
        };

        this.__proto__.toObject = function() {
            return this.value;
        };

        this.__proto__.toString = function() {
            return ReasonCode.reasonName(this.value);
        };

        function init(v) {
            if (v === undefined)
                throw "ReasonCode.new: parameter can not be undefined."
            if (trusted.isString(v)) {
                var asn = new trusted.ASN(v);
                v = asn.toObject("ReasonCode");
            }
            if (!(trusted.isNumber(v)))
                throw "ReasonCode.new: parameter is not valid."
            obj = v;
        }

        init.call(this, arguments[0]);
    }
    ReasonCode.reasonName = function(num){
        if (!trusted.isNumber(num)){
            "ResasonCode.reasonName: Параметр должен быть числом.";
        }
        var keys = Object.keys(trusted.PKI.CRLReason);
            for (var i = 0; i < keys.length; i++) {
                var val = trusted.PKI.CRLReason[keys[i]];
                if (val === num)
                    return keys[i];
            }
            return "Unknown reason";
    };
    
    //InvalidityDate 2.5.29.24
    function InvalidityDate() {
        var obj;

        this.__proto__ = {
            set value(v) {
            },
            get value() {
                return obj;
            }
        };

        this.__proto__.toObject = function() {
            return this.value;
        };

        this.__proto__.toString = function() {
            return obj.toString();
        };

        function init(v) {
            if (v === undefined)
                throw "InvalidityDate.new: parameter can not be undefined."
            if (trusted.isString(v)) {
                var asn = new trusted.ASN(v);
                v = asn.toObject("InvalidityDate");
            }
            if (!(trusted.isObject(v)))
                throw "InvalidityDate.new: parameter is not valid."
            obj = v;
        }

        init.call(this, arguments[0]);
    }
    
    //Certificate Issuer 2.5.29.29

    // exports
    trusted.PKI.CRLNumber = CRLNumber;
    trusted.PKI.BaseCRLNumber = CRLNumber;
    trusted.PKI.IssuingDistributionPoint = IssuingDistributionPoint;
    // revoced cert extensions
    trusted.PKI.ReasonCode = ReasonCode;
    trusted.PKI.InvalidityDate = InvalidityDate;
    trusted.PKI.CertificateIssuer = trusted.PKI.GeneralNames;

})();


