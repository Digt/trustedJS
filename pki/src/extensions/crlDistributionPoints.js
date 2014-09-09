// <editor-fold defaultstate="collapsed" desc=" ReasonFlags ">
trusted.PKI.ReasonFlags = {
    Unused: 0x01, //(0)
    KeyCompromise: 0x02, //(1)
    CACompromise: 0x04, //(2)
    AffiliationChanged: 0x08, //(3)
    Superseded: 0x10, //(4)
    CessationOfOperation: 0x20, //(5)
    CertificateHold: 0x40, //(6)
    PrivilegeWithdrawn: 0x80, //(7)
    AACompromise: 0x100 //(8)
};
// </editor-fold>

(function() {



    // <editor-fold defaultstate="collapsed" desc=" DistributionPoints ">
    function CRLDistributionPoints() {
        var obj, dps;
        this.__proto__ = {
            set distributionPoints(v) {
            },
            get distributionPoints() {
                if (dps === undefined) {
                    dps = [];
                    for (var i = 0; i < obj.length; i++)
                        dps.push(new trusted.PKI.DistributionPoint(obj[i]));
                }
                return dps;
            }
        };

        this.__proto__.toObject = function() {
            var o = [];
            for (var i = 0; i < this.distributionPoints.length; i++)
                o.push(this.distributionPoints[i].toObject());
            return o;
        };

        function init(v) {
            if (v === undefined)
                throw "CRLDistributionPoints.new: parameter can not be undefined."
            if (trusted.isString(v)) {
                var asn = new trusted.ASN(v);
                v = asn.toObject("CRLDistributionPoints");
            }
            if (!trusted.isObject(v) && !trusted.isArray(v))
                throw "CRLDistributionPoints.new: parameter is not valid."
            obj = v;
        }

        init.call(this, arguments[0]);
    }
    trusted.PKI.CRLDistributionPoints = CRLDistributionPoints;
    // </editor-fold>

    // <editor-fold defaultstate="collapsed" desc=" DistributionPointName ">
    function DistributionPointName() {
        var obj;
        var fullName;
        var relName;

        this.__proto__ = {
            set fullName(v) {

            },
            get fullName() {
                if (fullName === undefined)
                    if (obj.fullName === null)
                        fullName = null;
                    else
                        fullName = new trusted.PKI.GeneralNames(obj.fullName);
                return fullName;
            },
            set relativeName(v) {

            },
            get relativeName() {
                if (relName === undefined)
                    if (obj.nameRelativeToCRLIssuer === undefined)
                        relName = null;
                    else
                        relName = new trusted.PKI.RDN(obj.nameRelativeToCRLIssuer);
                return relName;
            }
        };

        this.__proto__.toObject = function() {
            var o = {};
            if (this.fullName !== null)
                o.fullName = this.fullName.toObject();
            if (this.relativeName !== null)
                o.nameRelativeToCRLIssuer = this.relativeName.toObject();
            return o;
        };

        function init(v) {
            if (v === undefined)
                throw "DistributionPointName.new: parameter can not be undefined."
            if (trusted.isString(v)) {
                var asn = new trusted.ASN(v);
                v = asn.toObject("DistributionPointName");
            }
            if (!(trusted.isObject(v) && ("fullName" in v || "nameRelativeToCRLIssuer" in v)))
                throw "DistributionPointName.new: parameter is not valid."

            obj = v;
        }

        init.call(this, arguments[0]);
    }
    trusted.PKI.DistributionPointName = DistributionPointName;
    // </editor-fold>

    // <editor-fold defaultstate="collapsed" desc=" DistributionPoint ">
    function DistributionPoint() {
        var obj;
        var crlIssuer;
        var distPoint;
        var r; //reasons

        this.__proto__ = {
            set CRLIssuer(v) {

            },
            get CRLIssuer() {
                if (crlIssuer === undefined)
                    if (obj.cRLIssuer === null)
                        crlIssuer = null;
                    else
                        crlIssuer = new trusted.PKI.GeneralNames(obj.cRLIssuer);
                return crlIssuer;
            },
            set distributionPoint(v) {

            },
            get distributionPoint() {
                if (distPoint === undefined)
                    if (obj.distributionPoint === null)
                        distPoint = null;
                    else
                        distPoint = new trusted.PKI.DistributionPointName(obj.distributionPoint);
                return distPoint;
            },
            set name(v) {
            },
            get name() {
                return this.distributionPoint;
            },
            set reasons(v) {
            },
            get reasons() {
                if (r === undefined) {
                    if (obj.reasons === null)
                        r = null;
                    else {
                        r = obj.reasons.toNumber();
                    }
                }
                return r;
            }
        };
        
        function createIsFunctions(v) {
            var keys = Object.keys(v);
            for (var i = 0; i < keys.length; i++) {
                var index = i; // Создаем копию i, иначе все функции будут использовать i = keys.
                this.__proto__["is" + keys[index]] = new Function("return ((this.reasons&" + v[keys[index]] + ")>0)?true:false;");
            }
        }

        createIsFunctions.call(this, trusted.PKI.ReasonFlags);

        this.__proto__.toObject = function() {
            var o = {};
            if (this.CRLIssuer !== null)
                o.cRLIssuer = this.CRLIssuer.toObject();
            if (this.distributionPoint !== null)
                o.distributionPoint = this.distributionPoint.toObject();
            if (this.reasons !== null)
                o.reasons = new BitString(this.reasons);
            return o;
        };

        this.__proto__.getURL = function() {
            if (this.distributionPoint === null)
                return null;
            if (this.distributionPoint.fullName !== null)
                return this.distributionPoint.fullName.toString();
            return this.CRLIssuer + this.distributionPoint.relativeName;
        };

        function init(v) {
            if (v === undefined)
                throw "DistributionPointName.new: parameter can not be undefined."
            if (trusted.isString(v)) {
                var asn = new trusted.ASN(v);
                v = asn.toObject("DistributionPoint");
            }
            if (!trusted.isObject(v) && !("cRLIssuer" in v || "distributionPoint" in v || "reasons" in v))
                throw "DistributionPointName.new: parameter is not valid.";
            obj = v;
        }

        init.call(this, arguments[0]);
    }
    trusted.PKI.DistributionPoint = DistributionPoint;
    // </editor-fold>
})();

