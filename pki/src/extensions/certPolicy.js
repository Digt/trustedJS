(function() {

// <editor-fold defaultstate="collapsed" desc=" CertificatePolicies ">
    function CertificatePolicies() {
        var obj, pis;
        this.__proto__ = {
            set policies(v) {
            },
            get policies() {
                if (pis === undefined) {
                    pis = [];
                    for (var i = 0; i < obj.length; i++)
                        pis.push(new trusted.PKI.PolicyInformation(obj[i]));
                }
                return pis;
            }
        };

        this.__proto__.toObject = function() {
            var o = [];
            for (var i = 0; i < this.policies.length; i++)
                o.push(this.policies[i].toObject());
            return o;
        };

        function init(v) {
            if (v === undefined)
                throw "CertificatePolicies.new: parameter can not be undefined."
            if (trusted.isString(v)) {
                var asn = new trusted.ASN(v);
                v = asn.toObject("CertificatePolicies");
            }
            if (!(trusted.isArray(v) && v.length > 0))
                throw "CertificatePolicies.new: parameter is not valid."
            obj = v;
        }

        init.call(this, arguments[0]);
    }
    trusted.PKI.CertificatePolicies = CertificatePolicies;
    // </editor-fold>

    function PolicyInformation() {
        var obj;
        var idf;
        var qlf;

        this.__proto__ = {
            set OID(v) {
            },
            get OID() {
                if (idf === undefined)
                    idf = new trusted.PKI.OID(obj.policyIdentifier);
                return idf;
            },
            set qualifiers(v) {
            },
            get qualifiers() {
                if (qlf === undefined) {
                    if (obj.policyQualifiers !== undefined) {
                        qlf = [];
                        for (var i = 0; i < obj.policyQualifiers.length; i++) {
                            var pq = obj.policyQualifiers[i];
                            qlf.push(new trusted.PKI.QualifierInfo(pq));
                        }
                    } else
                        qlf = null;
                }
                return qlf;
            }
        };

        this.__proto__.toObject = function() {
            var o = {};
            o.policyIdentifier = this.OID.value;
            if (this.qualifiers !== null) {
                o.policyQualifiers = [];
                for (var i = 0; i < this.qualifiers.length; i++)
                    o.policyQualifiers.push(this.qualifiers[i].toObject());
            }
            return o;
        };

        function init(v) {
            if (v === undefined)
                throw "PolicyInformation.new: parameter can not be undefined."
            if (trusted.isString(v))
                v = (new trusted.ASN(v)).toObject("PolicyInformation");
            if (!(trusted.isObject(v)) && ("policyIdentifier" in v))
                throw "PolicyInformation.new: parameter is not valid."
            obj = v;
        }

        init.call(this, arguments[0]);
    }
    trusted.PKI.PolicyInformation = PolicyInformation;

    function QualifierInfo() {
        var obj, pqid, cps, un;

        this.__proto__ = {
            set OID(v) {
            },
            get  OID() {
                if (pqid === undefined) {
                    pqid = new trusted.PKI.OID(obj.policyQualifierId);
                }
                return pqid;
            },
            set CPSPointer(v) {
            },
            get CPSPointer() {
                if (cps === undefined) {
                    cps = null;
                    if (this.OID.value === "1.3.6.1.5.5.7.2.1") {
                        var asn = new trusted.ASN(this.encoded);
                        cps = asn.toObject("CPSuri");
                    }
                }
                return cps;
            },
            set encoded(v) {
            },
            get encoded() {
                if (trusted.isString(obj.qualifier)) {
                    return obj.qualifier;
                }
                return null;
            },
            set organizationName(v) {
            },
            get organizationName() {
                if (getUserNotice.call(this) !== null) {
                    if (un.noticeRef !== undefined) {
                        var key = Object.keys(un.noticeRef.organization);
                        return un.noticeRef.organization[key];
                    }
                }
                return null;
            },
            set noticeNumbers(v) {
            },
            get noticeNumbers() {
                if (getUserNotice.call(this) !== null) {
                    if (un.noticeRef !== undefined) {
                        return un.noticeRef.noticeNumbers;
                    }
                }
                return null;
            },
            set explicitText(v) {
            },
            get explicitText() {
                if (getUserNotice.call(this) !== null) {
                    if (un.explicitText !== undefined) {
                        var key = Object.keys(un.explicitText);
                        return un.explicitText[key];
                    }
                }
                return null;
            }
        };

        function getUserNotice() {
            if (un === undefined) {
                un = null;
                if (this.policyQualifierID.value === "1.3.6.1.5.5.7.2.2") {
                    var asn = new trusted.ASN(this.encoded);
                    un = asn.toObject("UserNotice");
                }
            }
            return un;
        }

        this.__proto__.toObject = function() {
            var o = {};
            switch (this.OID.value) {
                case "1.3.6.1.5.5.7.2.1":
                    o.qualifier = trusted.ASN.fromObject(this.CPSPointer, "CPSuri").encode();
                    break
                case "1.3.6.1.5.5.7.2.2":
                    var o1;
                    if (this.organizationName !== null) {
                        o1.noticeRef = {};
                        o1.noticeRef.organization = {};
                        o1.noticeRef.organization.utf8String = this.organizationName;
                        o1.noticeRef.noticeNumbers = this.noticeNumbers;
                    }
                    if (this.explicitText !== null) {
                        o1.explicitText = {};
                        o1.explicitText.utf8String = this.explicitText;
                    }
                    if (this.encoded === null) {
                        o.qualifier = trusted.ASN.fromObject(o, "UserNotice").encode();
                    }
                    break
                default:
                    o.qualifier = this.encoded;
            }
            o.policyQualifierId = this.OID.value;
            return o;
        };

        function init(v) {
            if (v === undefined)
                throw "QualifierInfo.new: parameter can not be undefined."
            if (trusted.isString(v))
                v = (new trusted.ASN(v)).toObject("PolicyQualifierInfo");
            if (!(trusted.isObject(v) && (("policyQualifierId" in v) && ("qualifier" in v))))
                throw "QualifierInfo.new: parameter is not valid."
            obj = v;
        }

        init.call(this, arguments[0]);
    }
    trusted.PKI.QualifierInfo = QualifierInfo;

})();

