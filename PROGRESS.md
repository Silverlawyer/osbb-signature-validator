# Стан проєкту: авторизація по КЕП (ДСТУ) для ОСББ Дніпровського району

Оновлено: 23.07.2026 (Claude, сесія автоматизації браузера)

## Інфраструктура

- Google Cloud проект: osbb-kep
- VM: osbb-kep-vm, зона us-central1-a, зовнішній IP 136.115.148.18
- ОС: Debian, nginx (порт 80) проксує на 127.0.0.1:8080
- Бекенд: /opt/kep-server - Python/Flask + gunicorn, керується через systemd unit kep-server.service (enabled, autostart, Restart=always)
- Секретний ключ Flask лежить в /etc/kep-server.env (KEP_SECRET_KEY), права 600

## Що вже реалізовано на сервері (/opt/kep-server)

- app.py - маршрути: / (index), /verify (POST, приймає signed_file або signed_data), /documents/<file>, /download/<file>, /terms
- eusign_wrapper.py - обгортка над офіційною бібліотекою АТ IIT (ctypes, /opt/iit/eu/sw), функція verify_internal() використовує EUVerifyDataInternal
- logger.py - пише в SQLite /opt/kep-server/data/audit.db, таблиця audit_log: ts, session_id, full_name, drfo_code, edrpou_code, ip_address, action, path, file_name, user_agent, result
- templates/terms.html - повний текст угоди (доданий 23.07.2026, раніше був відсутній, маршрут /terms падав з помилкою 500)
- templates/index.html - ЗАГЛУШКА (просто textarea для вставки base64 підпису вручну), немає віджета підпису в браузері

## Що ще потрібно зробити (пріоритет 1: довести що авторизація по КЕП технічно працює)

1. Встановити офіційну Web-бібліотеку підпису АТ IIT (EUSignWeb) на сервер, щоб відвідувач міг обрати файловий ключ і пароль прямо в браузері (зараз цього віджета немає взагалі)
2. Переробити templates/index.html - нормальна форма входу з віджетом підпису замість textarea
3. Провести наскрізний тест з реальним файлом ключа користувача

## Плани далі (після успішного тесту)

- Структура даних для будинків (адреса область/район/місто/вулиця плюс назва управителя ОСББ/ЖБК/КК)
- Адмін-панель для внесення будинків і документів
- Публічний каталог з випадаючими списками вибору будинку і управителя
- Групи документів: статутні, протоколи зборів і правлінь, технічна документація

## Важливо для наступної сесії Claude

- Термінал Cloud Shell (xterm) НЕ приймає кирилицю при прямому наборі тексту через синтетичні keyboard events (символи губляться). Файли з українським текстом треба спочатку створювати через GitHub-редактор (він кирилицю приймає нормально), закомітити, а потім тягнути на сервер через git clone або git pull. Для довгого тексту вводити частинами по кілька абзаців з паузами, інакше можуть губитись пробіли.
- Окрема вкладка SSH-в-браузері (кнопка SSH у списку VM instances) відкривається довго і не завжди одразу зʼявляється в списку вкладок. Надійніше користуватись вбудованим Cloud Shell (кнопка Activate Cloud Shell у Google Cloud Console) і командою: gcloud compute ssh osbb-kep-vm --zone=us-central1-a


## Оновлення 23.07.2026 (продовження сесії)

terms.html вже задеплоєно на сервер (git clone + copy), systemd unit kep-server.service активний і працює.

Дослідив офіційну документацію IIT (EUSignJavaScriptD.doc, EUSignWebOManual.doc) через antiword на сервері.

Важливий висновок про архітектуру браузерного підпису:

- "Пряме підписання в браузері" НЕ є простою JS/WASM бібліотекою, яку можна поставити тільки на наш сервер.
- - Воно вимагає від відвідувача встановленого локального агента ІІТ ("Кінцевий користувач ЦСК", EUInstall.exe/pkg або euswi для Linux).
  - - Агент працює як локальний процес: JSON-RPC на localhost, або Native Messaging + розширення браузера, або NPAPI/ActiveX для старих браузерів.
    - - Наш сайт вбудовує тонку JS-обгортку (euscp.js/euscpm.js/euscpt.js), яка звертається саме до цього локального агента.
     
      - - Пароль від ключа НІКОЛИ не приходить на наш сервер - вводиться у вікні локального агента/віджета, не в нашій HTML-формі.
        - - Файл euscp.js на публічній сторінці завантажень iit.com.ua поки не знайдено, потрібне уточнення у виробника або пошук альтернативного джерела.
          - - Наявний зараз /opt/kep-server/eusign_wrapper.py коректно робить іншу, теж критично важливу річ: серверну перевірку вже готового підпису (verify_internal), включно з ПІБ і РНОКПП/ЄДРПОУ з сертифіката.
           
            - 


## Onovlennya: index.html gotoviy, smoke-test proyshov

templates/index.html perepysano cherez paste-event trick (obhid GitHub auto-close bahu) - normalna forma z fayl/base64 signed_data, checkbox agree, posylannya na /terms. Zadeployeno na server.
