(function() {
    /*    
     id-ce-authorityKeyIdentifier OBJECT IDENTIFIER ::=  { id-ce 35 }
     
     AuthorityKeyIdentifier ::= SEQUENCE {
     keyIdentifier             [0] KeyIdentifier           OPTIONAL,
     authorityCertIssuer       [1] GeneralNames            OPTIONAL,
     authorityCertSerialNumber [2] CertificateSerialNumber OPTIONAL  }
     
     KeyIdentifier ::= OCTET STRING
     */

    function AuthorityKeyIdentifier() {
        var obj;
        var authorityCertIssuer;
        var version;

        this.__proto__ = {
            set keyIdentifier(v) {
            },
            get keyIdentifier() {
                return obj.keyIdentifier === undefined ? null : obj.keyIdentifier;
            },
            set issuerName(v) {
            },
            get issuerName() {
                if (authorityCertIssuer === undefined)
                    if (obj.authorityCertIssuer !== undefined)
                        switch (version) {
                            case 1:
                                authorityCertIssuer = new trusted.PKI.GeneralNames(
                                        [{directoryName: {rdnSequence: obj.authorityCertIssuer.rdnSequence}}]
                                        );
                                break;
                            default:
                                authorityCertIssuer = new trusted.PKI.GeneralNames(obj.authorityCertIssuer);
                        }
                    else
                        authorityCertIssuer = null;
                return authorityCertIssuer;
            },
            set serialNumber(v) {
            },
            get serialNumber() {
                return obj.authorityCertSerialNumber === undefined ? null : obj.authorityCertSerialNumber;
            },
            set version(v) {
            },
            get version() {
                return version;
            }
        };

        this.__proto__.toObject = function() {
            var obj = {};
            if (this.issuerName !== null) {
                var aci;
                switch (this.version) {
                    case 1:
                        aci = this.issuerName[0].toObject();
                        break;
                    default:
                        aci = this.issuerName.toObject();
                }
                obj.authorityCertIssuer = aci;
            }
            if (this.serialNumber !== null) {
                obj.authorityCertSerialNumber = this.serialNumber;
            }
            if (this.keyIdentifier !== null) {
                obj.keyIdentifier = this.keyIdentifier;
            }
            return obj;
        };

        function init(v, oid) {
            if (oid === undefined)
                oid = "2.5.29.35";
            var schema;
            switch (oid) {
                case "2.5.29.1":
                    schema = "AuthorityKeyIdentifier1";
                    version = 1;
                    break;
                default:
                    schema = "AuthorityKeyIdentifier2";
                    version = 2;
            }
            if (v === undefined)
                throw "AuthorityKeyIdentifier.new: parameter can not be undefined."
            v = objFromBuffer(v, schema);
            if (!(trusted.isObject(v)) && (("keyIdentifier" in v) || ("authorityCertIssuer" in v) || ("authorityCertSerialNumber" in v)))
                throw "AuthorityKeyIdentifier.new: parameter is not valid."

            //v.keyIdentifier = Der.toHex(v.keyIdentifier);

            obj = v;
        }

        init.call(this, arguments[0], arguments[1]);
    }

    trusted.PKI.AuthorityKeyIdentifier = AuthorityKeyIdentifier;
})();

