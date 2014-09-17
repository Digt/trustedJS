ctl.hasCertificate(ctl.certificates[0]).then(
        function (v) {
            if (v.result !== true) {
                print("hasCertificate", "Сертификат не получен из коллекции", "fail", "Тест на существование сертификата в коллекции");
                return Promise.resolve();
            }
            if (!ctl.certificates[0].equals(v.cert)) {
                print("hasCertificate", "Полученый сертификат не соответствует запрашиваемому", "fail", "Тест на существование сертификата в коллекции");
            }
        },
        function (err) {
            print("hasCertificate", "Что-то пошло не так: " + err, "error", "Тест на существование сертификата в коллекции");
        }
);