//ВЕРИФИКАЦИЯ СЕРТИФИКАТОВ
//Самоподписанный сертификат
cert1.verify(cert1).then(
        function (v) {
            var testName = "Верификация сертификатов";
            var testCase = "Самоподписанный сертификат";
            if (!v)
                print(testName, "Верификация не пройдена!", "fail", testCase);
        },
        function (err) {
            var testName = "Верификация сертификатов";
            var testCase = "Разные сертификаты";
            print(testName, "В процессе тестирования произошла ошибка: " + err, "error", testCase);
        }
);
//Другой сертификат
cert1.verify(cert2).then(
        function (v) {
            var testName = "Верификация сертификатов";
            var testCase = "Разные сертификаты";
            if (v)
                print(testName, "Верификация прошла успешно!", "fail", testCase);
        },
        function (err) {
            var testName = "Верификация сертификатов";
            var testCase = "Разные сертификаты";
            print(testName, "В процессе тестирования произошла ошибка: " + err, "error", testCase);
        }

);
signeedData.verify().then(
        function (result) {

            var testName = "Верификация signeed Data";
            var testcase = "Без";
            print(testName, "В процессе тестирования произошла ошибка:", "fail", testcase);
        },
        function (error) {
            var str = "В процессе тестирования произошла ошибка: SignedData.verify: Указаны не все сертификаты подписчиков.";
            if (error === str)
            {
            }
            else
                print(testName, "В процессе тестирования произошла ошибка: " + result, "fail", testcase);

        }
);
signeedData2.verify().then(
        function (result) {
            var testName = "Верификация signeed Data";
            var testcase = "2";
            if (!result.status)
                print(testName, "Верификация не пройдена!", "fail", testcase);
        },
        function (error) {
            var testName = "Верификация signeed Data";
            var testcase = "";
            print(testName, "В процессе тестирования произошла ошибка: " + error, "error", testcase);
        }
);
signeedData3.verify().then(
        function (result) {
            var testName = "Верификация signeed Data";
            var testcase = "3";
            if (result.status)
                print(testName, "Верификация не пройдена!", "fail", testcase);
        },
        function (error) {
            var testName = "Верификация signeed Data";
            var testcase = "";
            print(testName, "В процессе тестирования произошла ошибка: " + error, "error", testcase);
        }
);