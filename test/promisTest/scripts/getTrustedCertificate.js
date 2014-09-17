//Получение подписанных сертификатов

ctl.getTrustCertificates(ctl.certificates).then(
        function (v) {
            if (v.length !== 4) {
                print("getTrustCertificates", "Не все сертификаты получены", "fail", "Тест на существующие сертификаты");
                return Promise.resolve();
            }
            var numberOfTrusted = 0;
            for (var i = 0; i < ctl.certificates.length; i++) {
                var j = 0;
                while (j < v.length) {
                    if (ctl.certificates[i].equals(v[j])) {
                        numberOfTrusted++;
                        break;
                    }
                    else
                        j++;
                }
            }
            if (numberOfTrusted !== v.length) {
                print("getTrustCertificates", "Получены не верные сертификаты", "fail", "Тест на существующие сертификаты");
            }
        },
        function (err) {
            print("getTrustCertificates", "Что-то пошло не так: " + err, "error", "Тест на существующие сертификаты");
        }
);