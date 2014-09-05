
(function() {

    function SubjectKeyIdentifier() {
        var obj;
        this.__proto__ = {
            set keyIdentifier(v) {
            },
            get keyIdentifier() {
                return obj;
            }
        };

        function init(v) {
            if (v === undefined)
                throw "SubjectKeyIdentifier.new: parameter can not be undefined."
            if (trusted.isString(v))
                v = (new trusted.ASN(v)).toObject("SubjectKeyIdentifier");

            obj = Der.toHex(v);
        }

        init.call(this, arguments[0]);
    }

    trusted.PKI.SubjectKeyIdentifier = SubjectKeyIdentifier;
})();

