# cert-helper

Вспомогательный демон докачки/проверки сертификатов для `tls-mitm`: живые
OCSP-запросы, скачивание CRL, докачка недостающих промежуточных
сертификатов по AIA (`caIssuers`). Реализован по исходному ТЗ «cert-helper
— вспомогательный демон докачки сертификатов для tls-mitm», с
последующим изменением по отдельному запросу: **транспорт IPC — D-Bus**,
а не Unix domain socket, как было в первой версии.

Реализована **часть 1** исходного ТЗ целиком (сам демон, кэш, IPC,
клиентская библиотека, тесты, эксплуатационные артефакты) — она
самодостаточна и не требует изменений в `tls-mitm`. **Часть 2** (доработка
самой библиотеки `tls-mitm` для реального использования AIA-докачки в
процессе верификации цепочки) в этом репозитории **не реализована** — это
отдельный, более рискованный этап, требующий исходников
`tls-mitm-project`, которые не были доступны на момент реализации.

## Транспорт: D-Bus

Демон реализован как D-Bus сервис на **sd-bus** (часть `libsystemd`) —
выбран вместо `libdbus-1`/GDBus как наиболее естественный вариант для
демона, который и так управляется systemd (см. `deploy/cert-helper.service`,
`Type=dbus`), с минимальным набором зависимостей (без GLib/GObject) и
удобным низкоуровневым API для синхронных вызовов, которые здесь и нужны.

- **Well-known имя:** `org.certhelper.CertHelper1`
- **Путь объекта:** `/org/certhelper/CertHelper1`
- **Интерфейс:** `org.certhelper.CertHelper1`
- **Методы:**
  - `FetchOcsp(s responder_url, ay request_der, u timeout_ms) -> (y status, ay payload_der, b from_cache)`
  - `FetchOcspBatch(a(sayu) requests) -> (a(yayb) responses)` — батчинг
    нескольких OCSP-запросов в один вызов (ROADMAP.md, раздел 2, пункт
    14); `requests`/`responses` — один-к-одному по индексу, элемент
    структуры запроса — `(s responder_url, ay request_der, u timeout_ms)`,
    ответа — `(y status, ay payload_der, b from_cache)`, см. раздел
    «Доработки по ROADMAP.md» ниже за деталями и важным нюансом про
    одинаковый `payload_der` для нескольких элементов из одной группы.
  - `FetchCrl(s distribution_point_url, u timeout_ms) -> (y status, ay payload_der, b from_cache)`
  - `FetchIntermediateCert(s aia_url, u timeout_ms) -> (y status, ay payload_der, b from_cache)`
  - `HealthCheck() -> (b healthy, t cache_entries, t cache_size_bytes)`

`status` кодирует `cert_helper::protocol::FetchStatus`: `0=Ok, 1=Timeout,
2=NetworkError, 3=InvalidResponse`.

По умолчанию демон и клиент подключаются к **системной шине** (обычный
выбор для системного демона). Для тестов/нестандартных окружений оба
принимают явный адрес шины (`--bus-address` у демона и CLI,
конструктор `cert_helper::Client(bus_address)` у библиотеки).

### Модель конкурентности при работе через D-Bus (важно, отличается от UDS-версии)

sd-bus требует, чтобы одно соединение обрабатывалось (`sd_bus_process`/
`sd_bus_wait`) из одного потока. Поэтому у демона один выделенный
bus-поток крутит цикл обработки событий шины и только *диспетчеризует*
вызовы, а сама работа (HTTP-запрос, обращение к кэшу) выполняется в пуле
воркеров, как и раньше в UDS-версии — обработчик метода берёт ссылку на
входящее `sd_bus_message`, кладёт задачу в очередь и возвращает
управление немедленно; ответ воркер отправляет позже через `sd_bus_send()`
(документированный sd-bus паттерн асинхронного ответа). Это сохраняет
параллельную обработку нескольких одновременных запросов — проверено
отдельным регрессионным тестом
(`test_concurrent_fetches_do_not_serialize_on_slow_request`), который
специально стабит "медленный" URL и проверяет, что параллельный "быстрый"
запрос не ждёт его завершения.

### Контроль доступа

Права клиентов регулируются **D-Bus policy-файлом**
(`deploy/org.certhelper.CertHelper1.conf`), а не правами файла сокета, как
было в UDS-версии — концептуально та же модель (выделенная группа для
клиентов, отдельный пользователь для демона), просто в терминах D-Bus:
кто может `own()` well-known имя, и кто может слать ему вызовы методов.
NGFW-процесс должен быть в группе `cert-helper-clients` (см. комментарии
в файле политики).

## Сборка

```
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=RelWithDebInfo
make -j$(nproc)
ctest --output-on-failure   # 6 тестовых бинарей, все проходят
```

Зависимости: C++17, OpenSSL (`libssl-dev`), pthreads, **libsystemd**
(`libsystemd-dev`, для sd-bus), **Boost.ProgramOptions**
(`libboost-program-options-dev`, для разбора аргументов командной строки
у `cert-helper`/`cert-helper-cli`/`cert-helper-cache-tool`). Для
сборки/тестов также используется `dbus-daemon` (пакет `dbus`) —
интеграционный тест поднимает свой приватный dbus-daemon, не трогая
системную/сессионную шину хоста.

## Разбор аргументов командной строки

Демон (`src/daemon_main.cpp`), утилита `cert-helper-cli`
(`examples/standalone_fetch_cli.cpp`) и `cert-helper-cache-tool`
(`examples/cache_tool_cli.cpp`, ROADMAP.md раздел 2 пункт 16) используют
`boost::program_options` вместо самодельного цикла по `argv` — даёт
автоматическую генерацию `--help`, единообразную обработку ошибок
(`missing argument`, `unrecognised option` и т.п. с ненулевым кодом
возврата), опции с несколькими значениями (`--allowed-ports 80 8080`,
через `multitoken()`) и повторяемые опции (`--allow-cidr A --allow-cidr
B`, через `composing()`).

У `cert-helper-cli` команда (`health`/`fetch-crl`/`fetch-intermediate`) —
позиционный аргумент (`positional_options_description`), остальные флаги
— именованные. `cert-helper-cache-tool` — тот же паттерн для команды
(`export`/`import`).

**Особенность, о которой стоит знать:** алгоритм переноса строк в
автогенерируемом `--help` у `boost::program_options` считает *байты*, а не
символы — на многобайтовом UTF-8 (кириллица в описаниях опций) это может
разрезать текст посередине символа и испортить вывод. Оба файла явно
передают большую `line_length` в конструктор `options_description`
(`kHelpLineLength = 4096`), чтобы перенос практически никогда не
срабатывал — это осознанный обход конкретного повода для порчи вывода, а
не общая заглушка "на всякий случай".

## Запуск

```
./cert-helper \
    --cache-dir /var/lib/cert-helper/cache \
    --min-worker-threads 2 \
    --max-worker-threads 16 \
    --max-cache-entries 100000 \
    --max-cache-bytes 536870912 \
    --mem-cache-max-entries 20000 \
    --mem-cache-max-bytes 67108864 \
    --aia-ttl-seconds 604800 \
    --max-ocsp-ttl-seconds 86400 \
    --max-crl-ttl-seconds 604800 \
    --max-ocsp-response-bytes 262144 \
    --max-aia-response-bytes 262144 \
    --max-crl-response-bytes 16777216
# подключится к системной шине и запросит имя org.certhelper.CertHelper1
```

Полный список флагов — `./cert-helper --help`; в частности флаги сетевой
политики (`--allow-private-destinations`, `--allow-cidr`, `--deny-cidr`,
`--allowed-ports`) описаны в разделе «Доработки по итогам анализа Squid»
ниже, а `--max-ocsp-ttl-seconds`/`--max-crl-ttl-seconds`/
`--max-*-response-bytes`/`--allow-https`/`--https-ca-bundle`/
`--allow-ldap`/`--max-retries`/`--retry-base-delay-ms`/
`--circuit-breaker-*`/`--dns-cache-ttl-seconds`/`--warmup-file` — в
разделе «Доработки по ROADMAP.md».

Диагностика уже запущенного демона:

```
./cert-helper-cli health
./cert-helper-cli fetch-crl --url http://crl.example.com/ca.crl --out /tmp/ca.crl
```

`health` теперь показывает разбивку по диск/memory-кэшу и по типу запроса
(OCSP/CRL/AIA) — см. пример вывода в разделе ниже.

Для приватной/тестовой шины оба принимают `--bus-address`, например
`--bus-address "unix:path=/tmp/test-bus.sock"`.

Пример подключения из NGFW — см. комментарий в
`include/cert_helper/client.hpp`:

```cpp
cert_helper::Client helper_client; // системная шина D-Bus по умолчанию

tls_mitm::RevocationFetchers fetchers;
fetchers.ocsp = helper_client.ocsp_fetcher();
fetchers.crl  = helper_client.crl_fetcher();
config.revocation_fetchers = fetchers;
```

Публичный интерфейс `cert_helper::Client` не изменился при переходе на
D-Bus — только внутренний транспорт (`src/client_impl/dbus_client.hpp`
вместо прежнего `uds_client.hpp`). Код, однажды написанный против
`cert_helper::Client`, менять не нужно.

## Доработки по итогам анализа демона докачки сертификатов в Squid

По запросу был проанализирован аналогичный механизм в Squid (докачка
intermediate-сертификатов по AIA + `ssl_crt_validator`) и внедрено пять
доработок. Подробное обоснование каждой — в комментариях над
соответствующим кодом; здесь — краткая сводка и как это включается.

### 1. HTTP Cache-Control/Expires от AIA/CRL/OCSP-сервера уважаются

`src/http_client.hpp::SimpleHttpFetcher` разбирает `Cache-Control`
(`no-store`, `no-cache`, `max-age=N`) и `Expires` из ответа сервера.
`request_router.hpp::apply_http_cache_hints()` комбинирует эти подсказки
с нашим собственным TTL (из `nextUpdate` для OCSP/CRL, из
`aia_ttl_seconds` для AIA) так, что сервер может TTL только **укоротить**,
никогда не удлинить сверх того, что мы и так считаем безопасным.
`no-store`/`no-cache` от сервера отключают кэширование этого конкретного
ответа полностью. Работает всегда, без отдельного флага.

### 2. Двухуровневый кэш: память + диск

`src/cache/two_tier_cache.hpp` добавляет in-memory LRU-слой
(`MemoryLruCache`) перед персистентным `FileCacheStore` — по аналогии с
раздельными `dynamic_cert_mem_cache_size` (память) и `-M` (диск) у Squid.
Запись сначала пишется в диск (источник истины), затем прогревает память;
чтение сначала проверяет память и только при промахе идёт на диск.
Управляется флагами `--mem-cache-max-entries`/`--mem-cache-max-bytes`
(`0` записей отключает эффект memory-слоя, не убирая его из кода).

### 3. Политика destination'ов для исходящих fetch-запросов (SSRF-защита)

`src/net_policy.hpp::NetworkPolicy` — по умолчанию блокирует
loopback/link-local (включая облачный metadata-эндпоинт
`169.254.169.254`)/RFC1918 private/CGNAT/multicast/зарезервированные
диапазоны для трафика, инициируемого URL'ами **из содержимого чужого
сертификата** (AIA/OCSP/CDP) — то же соображение, что стоит за
Squid-овским `transaction_initiator certificate-fetching` + отдельный ACL
для этого класса трафика. Проверка выполняется **после** резолва DNS-имени
в IP (не обходится DNS rebinding). Управляется флагами
`--allow-private-destinations` (полностью отключить дефолтную блокировку),
`--allow-cidr CIDR` (точечное исключение, приоритетнее deny), `--deny-cidr
CIDR` (дополнительный запрет), `--allowed-ports LIST` (по умолчанию
только `80` — демон и так умеет только `http://`).

### 4. Эластичный пул воркеров

`src/ipc/dbus_server.hpp/.cpp` — раньше был фиксированный `worker_threads`,
теперь диапазон `[min_worker_threads, max_worker_threads]` (по аналогии с
`children N startup=... idle=...` у хелперов Squid): демон стартует с
минимума, добавляет воркеров при накоплении очереди задач вплоть до
максимума, и лишние сверх минимума самозавершаются после
`worker_idle_timeout_ms` простоя. Флаги: `--min-worker-threads`,
`--max-worker-threads`, `--worker-idle-timeout-ms`.

### 5. Разбивка наблюдаемости по типу запроса

`HealthCheck` теперь возвращает не только общий размер кэша, но и
отдельные счётчики (`requests`/`cache_hits`/`errors`) для OCSP/CRL/AIA, а
также размер memory-кэша отдельно от диска — аналог того, что Squid делает
маркировкой AIA-трафика отдельным `transaction_initiator`, позволяя
администратору видеть и фильтровать этот класс запросов отдельно. Пример
вывода `cert-helper-cli health`:

```
healthy=true
disk cache:   entries=1 size_bytes=25
memory cache: entries=1 size_bytes=25
ocsp:  requests=0 cache_hits=0 errors=0
crl:   requests=1 cache_hits=0 errors=0
aia:   requests=0 cache_hits=0 errors=0
```

## Доработки по ROADMAP.md

### 1. [P0] TTL AIA-сертификата клампится по его собственному notAfter

`request_router.hpp::clamp_ttl_to_cert_not_after()` — TTL кэша для
докачанного по AIA промежуточного сертификата больше не может пережить
`notAfter` самого сертификата. Раньше TTL был
`min(aia_ttl_seconds, HTTP cache hints)` без учёта срока действия
сертификата: если сертификат истекал раньше, чем `aia_ttl_seconds` (по
умолчанию неделя), демон продолжал бы отдавать уже просроченный
сертификат из кэша ещё до нескольких дней. Теперь дополнительно
клампится: `ttl = min(ttl, notAfter - now)`; если `notAfter` уже в
прошлом на момент фетча — сертификат вообще не кладётся в кэш (но всё
равно возвращается вызвавшему клиенту как успешный результат фетча — то,
что делать с просроченным сертификатом при построении цепочки, решает
tls-mitm, не демон). Работает всегда, без отдельного флага. Тесты:
`tests/test_client_server_roundtrip.cpp::test_intermediate_cert_ttl_clamped_to_cert_not_after`
и `::test_intermediate_cert_already_expired_not_cached` (фикстуры
`test_certs/leaf_expires_soon.der`, `test_certs/leaf_already_expired.der`
— см. `test_certs/README.md`).

### 2. [P0] Верхняя граница TTL для OCSP/CRL, независимая от `nextUpdate`

Раньше TTL кэша для OCSP/CRL брался только из `nextUpdate` ответа/CRL без
ограничения сверху: недобросовестный или скомпрометированный responder
мог указать `nextUpdate` через год, и демон год отдавал бы устаревший
статус отзыва (cache poisoning с очень долгим действием). Теперь
`request_router.hpp::clamp_ocsp_ttl()`/`clamp_crl_ttl()` дополнительно
клампят вычисленный TTL сверху константами `max_ocsp_ttl_seconds`
(по умолчанию 24 часа) и `max_crl_ttl_seconds` (по умолчанию 7 дней) —
управляются флагами `--max-ocsp-ttl-seconds`/`--max-crl-ttl-seconds`.
Клампинг применяется независимо от источника TTL (и от `nextUpdate`, и
от собственного `default_ocsp_ttl_seconds`/`default_crl_ttl_seconds`,
если те заданы больше максимума). Тесты:
`test_ocsp_ttl_clamped_to_max_ocsp_ttl` и `test_crl_ttl_clamped_to_max_crl_ttl`
в `tests/test_client_server_roundtrip.cpp` (фикстуры
`test_certs/ocsp_response_far_future.der`,
`test_certs/crl_far_future.der`, заявляющие `nextUpdate` через ~400 дней
— см. `test_certs/README.md`).

### 3. [P1] Ключ OCSP-кэша через CertID, устойчивый к nonce (RFC 8954)

Раньше кэш OCSP ключевался фингерпринтом всего тела запроса
(`request_der`) целиком — если tls-mitm добавит в OCSP-запрос
nonce-расширение (RFC 8954, защита от replay), каждый запрос по одному и
тому же сертификату давал бы разный DER, и кэш вообще переставал
срабатывать. Теперь `request_router.hpp::ocsp_request_cache_fingerprint()`
разбирает `OCSP_REQUEST`, достаёт `OCSP_CERTID` (issuer name hash + issuer
key hash + serialNumber) первого `OCSP_ONEREQ` и ключует по нему,
игнорируя nonce, который лежит отдельно в `tbsRequest.requestExtensions`,
а не внутри `CertID`. Если `request_der` не разбирается как валидный
`OCSP_REQUEST` (тестовые "сырые" байты и т.п.) — поведение откатывается
на прежний фингерпринт всего DER, без регрессии для таких клиентов.
Работает всегда, без отдельного флага (батчинг из пункта 14 ещё не
реализован — берётся первый `OCSP_ONEREQ`). Тест:
`test_ocsp_cache_key_ignores_nonce_but_distinguishes_certid` в
`tests/test_client_server_roundtrip.cpp` (фикстуры
`test_certs/ocsp_request_certid_a_nonce1.der`,
`ocsp_request_certid_a_nonce2.der`, `ocsp_request_certid_b_nonce1.der` —
см. `test_certs/README.md`).

### 4. [P1] Лимиты размера ответа по типу запроса

Раньше `SimpleHttpFetcher::recv_all` ограничивал любой HTTP-ответ одной
константой (32 МиБ) независимо от типа запроса — OCSP-ответ и AIA-сертификат
легитимно весят единицы-сотни КБ, разрешать им 32 МиБ было лишней
поверхностью для исчерпания памяти/диска ответом от недобросовестного или
скомпрометированного сервера. Теперь `max_response_bytes` — обязательный
параметр `IHttpFetcher::fetch()`, и `RequestRouter` передаёт разные
значения по типу запроса: `Config::max_ocsp_response_bytes` и
`Config::max_aia_response_bytes` (по умолчанию 256 КиБ каждый),
`Config::max_crl_response_bytes` (по умолчанию 16 МиБ, CRL легитимно может
быть большим). Управляются флагами `--max-ocsp-response-bytes`/
`--max-aia-response-bytes`/`--max-crl-response-bytes`. Тесты:
`test_response_exceeding_max_bytes_is_rejected`/
`test_response_within_max_bytes_is_accepted` в
`tests/test_http_cache_hints.cpp` (реальный TCP-сокет — проверяют сам
enforcement в `SimpleHttpFetcher::recv_all`), и
`test_response_size_limits_differ_per_request_type` в
`tests/test_client_server_roundtrip.cpp` (через `StubHttpFetcher` —
проверяет, что router передаёт РАЗНЫЕ пределы для OCSP/AIA/CRL, а не одно
и то же значение).

**Побочная находка при работе над этим пунктом:** тест на лимит для CRL с
телом 1 МиБ обнаружил не связанный напрямую с этим пунктом, но реальный
use-after-free в `client_impl/dbus_client.hpp::call_and_parse_fetch()` —
`sd_bus_message_unref(reply)` вызывался ДО того, как указатель на payload
(который `sd_bus_message_read_array` отдаёт без копирования, прямо
внутрь буфера сообщения) копировался в `result.payload_der`. Для мелких
ответов (единицы байт, как во всех более ранних тестах) это годами
оставалось незамеченным — освобождённая память часто не успевает быть
переиспользована до `assign()`; на реалистичном для CRL размере (сотни
КБ — единицы МБ) баг воспроизводился надёжно и тихо портил часть байт
ответа без каких-либо ошибок или падений. Исправлено: копирование теперь
происходит до `unref`. См. коммент в самом файле для деталей.

### 5. [P1] Singleflight-дедупликация параллельных одинаковых запросов

Раньше, если много TLS handshake одновременно упирались в один и тот же
URL при промахе кэша (типичное «громкое стадо» на старте демона, когда
кэш ещё пуст), каждый вызов `handle_ocsp`/`handle_crl`/
`handle_intermediate_cert` независимо инициировал свой HTTP-запрос —
N одновременных запросов давали N сетевых походов вместо одного. Теперь
`RequestRouter::singleflight_execute()` оборачивает вызов
`handle_*_impl()`: первый поток с данным ключом (тип + cache-key)
становится «лидером» и выполняет обычную логику без изменений
(`кэш -> сеть -> запись в кэш`); все остальные потоки, пришедшие с тем же
ключом, пока лидер ещё не закончил, блокируются на
`std::condition_variable` и получают копию его результата вместо
повторного похода в сеть. Работает всегда, без отдельного флага — это
чистая внутренняя оптимизация, не меняющая наблюдаемый контракт
запрос/ответ. Реализация не сериализует НЕ связанные ключи (мьютекс над
in-flight map держится только на операции с самой map, не на время
выполнения запроса) — подтверждено уже существующим
`test_concurrent_fetches_do_not_serialize_on_slow_request`. Тест:
`test_singleflight_deduplicates_concurrent_identical_requests` в
`tests/test_client_server_roundtrip.cpp` — 8 одновременных запросов к
одному URL с искусственной 300мс задержкой у «сети» дают ровно один
реальный HTTP-вызов вместо восьми, и все 8 клиентов получают корректный
результат.

### 6. [P2] PKCS#7 "degenerate" контейнер как формат ответа `caIssuers`

Раньше поддерживался только голый DER X.509 — PKCS#7-контейнер
(`application/pkcs7-mime`, который используют некоторые CA для
caIssuers) трактовался как `InvalidResponse`. Теперь
`request_router.hpp::extract_single_der_certificate()` сначала пробует
разобрать ответ как обычный `X509` (`d2i_X509`), а если не выходит — как
PKCS#7 SignedData (`d2i_PKCS7`) и достаёт сертификат(ы) из
`p7->d.sign->cert`. Content-Type ответа сервера не используется для
выбора ветки разбора — структурная проверка (`d2i_X509`/`d2i_PKCS7`)
надёжнее и не зависит от того, что сервер заявил в заголовке; сами
ASN.1-структуры `Certificate` и PKCS#7 `ContentInfo` взаимно исключающи,
так что перепутать их невозможно. Если в контейнере несколько
сертификатов (некоторые CA кладут туда весь оставшийся хвост цепочки, а
не только непосредственного эмитента) — берётся первый в стеке (по
конвенции порядка, как в TLS `Certificate` message); у демона нет
информации об ожидаемом issuer для более точного выбора — это
осознанное ограничение (`FetchIntermediateCertRequest` эту информацию не
передаёт), не забытый край. Извлечённый сертификат всегда
перекодируется через `i2d_X509` в чистый DER — дальше по цепочке
(клампинг TTL по notAfter, кэш, D-Bus payload) ничего не знает, был ли
исходный ответ PKCS#7 или голым DER. Тесты:
`test_intermediate_cert_accepts_pkcs7_single_cert` и
`test_intermediate_cert_accepts_pkcs7_multi_cert_takes_first` в
`tests/test_client_server_roundtrip.cpp` (фикстуры
`test_certs/aia_pkcs7_single_cert.der`,
`test_certs/aia_pkcs7_multi_cert.der` — см. `test_certs/README.md`, в
том числе про важный нюанс с порядком сертификатов внутри стека).

### 7. [P2] Поддержка https:// в HTTP-клиенте

Раньше `SimpleHttpFetcher` умышленно поддерживал только `http://` —
`https://` URL в AIA/OCSP/CDP (нестандартно, но не запрещено RFC)
трактовался как `NetworkError`. Теперь поддержка добавлена, но
**сознательно выключена по умолчанию** флагом `--allow-https` (то же
обоснование, что и раньше: TLS-стек внутри демона — тот же класс
поверхности атаки, от которого мы изолируемся, обрабатывая недоверенные
внешние ответы, а сами AIA/OCSP/CRL и так защищены на уровне
X.509/подписи, так что TLS-транспорт для их скачивания почти никогда не
добавляет защиты). Если администратор явно включил поддержку:

- Устанавливается настоящее TLS-соединение (`TLS_client_method`,
  минимум TLS 1.2) с проверкой сертификата сервера (`SSL_VERIFY_PEER`) —
  никогда не отключается тихой деградацией, даже при ошибках
  конфигурации (если доверенный набор корневых сертификатов не удалось
  загрузить — `https://`-запросы явно проваливаются, а не идут без
  проверки).
- Проверяется соответствие имени/адреса хоста сертификату (RFC 6125):
  `X509_VERIFY_PARAM_set1_ip_asc` для IP-литералов в URL,
  `X509_VERIFY_PARAM_set1_host` для доменных имён — простой `set1_host`
  для IP не сработал бы, т.к. он матчит только `dNSName`/CN и не видит
  `iPAddress`-записи SAN вообще (это и обнаружил соответствующий тест).
- `--https-ca-bundle` позволяет задать доверенный набор явно (например,
  приватный corporate CA) СТРОГО ВМЕСТО системного набора, а не в
  дополнение к нему.
- При включении `--allow-https` не забыть также добавить порт 443 в
  `--allowed-ports` (сетевая политика назначения не меняется этим
  пунктом).

Тесты — `tests/test_https_support.cpp`, отдельный бинарник с настоящим
TLS-сервером на 127.0.0.1 (не заглушка): `https:// выключен по
умолчанию → запрос отклоняется до попытки подключения`, `https со
доверенным CA bundle → успех`, `https без доверенного CA → отказ, а не
тихий пропуск`. Фикстуры — `test_certs/https_test_ca_cert.pem`,
`test_certs/https_test_server_cert.pem`,
`test_certs/https_test_server_key.pem` (см. `test_certs/README.md`).

### 8. [P2] Delta CRL (RFC 5280 §5.2.4)

Ключевое наблюдение, определившее объём этой доработки: докачка
delta-CRL по HTTP — это буквально то же самое, что докачка обычного
(полного) CRL — GET по URL, разбор `X509_CRL`, TTL по `nextUpdate`, кэш
по URL, лимит размера ответа. `RequestRouter::handle_crl()` и протокол
(`FetchCrlRequest`/`FetchResponse`) уже умели это без единого изменения —
отдельный "FetchDeltaCrl"-путь, который предполагался в исходной
формулировке пункта, не нужен: с точки зрения HTTP-докачки delta CRL от
обычного CRL неотличим. Единственное, чего не хватало — способа
**найти** URL delta-CRL (разбор расширения `freshestCRL`) и
**убедиться**, что скачанный по этому URL CRL действительно является
delta (расширение `deltaCRLIndicator`), а не, скажем, обычным полным
CRL, случайно оказавшимся по тому же URL.

Добавлен `src/crl_delta.hpp` — по аналогии с уже существующим `aia.hpp`
(та же логика для `caIssuers` URL сертификата): самостоятельные,
тестируемые утилиты разбора ASN.1, доступные для переиспользования
вызывающей стороной (`tls-mitm`), а не встроенные в основной путь
`RequestRouter` — ровно как `extract_ca_issuers_url()` не встроена в
`handle_intermediate_cert_impl()` (URL туда уже приходит готовым в самом
запросе):

- `extract_freshest_crl_url_from_crl()`/`_der` — `freshestCRL` на самом
  (полном) CRL, типичное место в реальных PKI.
- `extract_freshest_crl_url_from_cert()`/`_der` — то же расширение на
  сертификате (альтернативное место по RFC 5280 — позволяет обнаружить
  delta-CRL, не скачивая сначала полный CRL целиком).
- `extract_delta_crl_base_number()`/`_der` — `deltaCRLIndicator`;
  присутствует только в самой delta CRL и содержит номер базового CRL
  (`BaseCRLNumber`), на который она ссылается; `nullopt` содержательно
  означает "это обычный полный CRL, а не delta".

Реальный поток использования: `tls-mitm` скачивает полный CRL через
`fetch_crl(cdp_url)`, парсит его через
`extract_freshest_crl_url_from_crl_der()`, при наличии URL — докачивает
delta тем же самым `fetch_crl(delta_url)`, затем опционально проверяет
через `extract_delta_crl_base_number_der()`, что это действительно
delta CRL и на какой `BaseCRLNumber` он ссылается, прежде чем применять
его поверх уже имеющегося полного CRL. Тесты —
`tests/test_crl_delta_extraction.cpp` (фикстуры
`test_certs/crl_with_freshest_crl_ext.der`, `test_certs/delta_crl.der`,
`test_certs/leaf_with_freshest_crl.der` — см. `test_certs/README.md`).

### 9. [P3] Поддержка `ldap://` для CRL distribution points

Ряд корпоративных и государственных PKI (типичный пример — Active
Directory Certificate Services) публикуют CRL через LDAP, а не HTTP —
DN конкретного объекта-контейнера CRL плюс имя атрибута
(`certificateRevocationList;binary`), а не URL для GET. Этот пункт явно
помечен в ROADMAP.md как "делать только при реальной потребности"
(в системе нет `libldap`, реализация — минимальный протокольный клиент с
нуля); тем не менее реализован по явному запросу.

Добавлен `src/ldap_client.hpp` — минимальный LDAPv3-клиент (RFC 4511)
поверх сырых сокетов с собственным BER-кодеком (X.690 definite-length
TLV), тем же интерфейсным подходом, что `IHttpFetcher`/
`SimpleHttpFetcher`: `ILdapFetcher`/`SimpleLdapFetcher`. Поддерживает
только то, что реально нужно для докачки одного известного объекта по
известному DN: anonymous simple bind, baseObject-поиск, разбор
`SearchResultEntry`/`SearchResultDone`, ограниченное подмножество LDAP
Filter (RFC 4515) — presence (`attr=*`) и equality (`attr=value`),
включая через `&`/`|`/`!`; substring-фильтры с wildcard внутри значения,
`>=`/`<=`/`~=` и extensible match не реализованы. Как и `https://`
(п.7), **выключено по умолчанию** — флаг `--allow-ldap`: разбор BER от
недоверенного сервера — новая, неаудированная поверхность атаки.

**Явное и содержательное ограничение** (не техническая деталь, а
реальный пробел): LDAP URL с пустым host (`ldap:///CN=...`) не
поддерживается. RFC 4516 формально это разрешает — клиент должен сам
знать, к какому серверу обращаться (например, через DNS-based service
discovery домена Active Directory), — но у cert-helper нет и не будет
такой domain-awareness. Значительная часть реальных AD-публикуемых CDP
LDAP URL используют именно пустой host; для них эта реализация не
поможет без дополнительной интеграции (сконфигурированный
администратором дефолтный LDAP-сервер либо resolver Kerberos/AD).

`RequestRouter::handle_crl_impl()` диспетчеризует `ldap://` URL на
`ILdapFetcher` (если сконфигурирован — иначе `NetworkError`), запрашивая
атрибут `certificateRevocationList;binary` (RFC 4523 §2.2, используется
во всех практических реализациях LDAP CDP). Кэш (по URL) и TTL-политика
(по `nextUpdate` самого CRL, включая `max_crl_ttl_seconds`) — те же, что
и для `http://`: транспорт не влияет на то, что происходит с байтами
CRL после получения.

**Методология проверки протокола** (см. подробный комментарий в начале
`tests/test_ldap_support.cpp`): помимо автоматических тестов с лёгким
встроенным поддельным LDAP-сервером, реализация была вручную
верифицирована против настоящего OpenLDAP-сервера (`slapd`) в реальном
сеансе разработки — создана тестовая база, добавлена запись с
`certificateRevocationList;binary`, `SimpleLdapFetcher::fetch()`
выполнил anonymous bind + search и получил значение, побайтово идентичное
оригинальному CRL DER (`cmp` подтвердил); отдельно проверены
equality/AND-фильтры (совпадающие и нет), запрос несуществующего DN и
отсутствующего атрибута. Автоматические тесты —
`tests/test_ldap_support.cpp` (URL/фильтр-парсинг без сети + протокол
через встроенный поддельный сервер) и
`test_crl_via_ldap_rejected_when_not_configured`/
`test_crl_via_ldap_succeeds_when_configured_and_http_path_unaffected` в
`tests/test_client_server_roundtrip.cpp` (диспетчеризация на уровне
`RequestRouter`/D-Bus).

### 10. [P1] Retry с backoff для транзиентных сетевых ошибок

Раньше любая сетевая ошибка (`HttpResult::ok == false` — отказ
соединения, таймаут, TLS-хендшейк и т.п.) сразу возвращалась как
`NetworkError` без единой повторной попытки — единичный дропнутый
пакет/RST на нестабильной сети означал, что весь TLS handshake в
`tls-mitm` проваливался, хотя следующая же попытка почти наверняка
прошла бы успешно.

Реализовано в `RequestRouter::retry_with_backoff()`/`fetch_with_retry()`:
все три HTTP-based fetch'а (OCSP/CRL/AIA) при транспортной ошибке
повторяются до `config.max_retries` раз (по умолчанию 2, т.е. до 3
попыток всего) с экспоненциальным backoff и **full jitter**
(равномерная случайная задержка между 0 и `base*2^(attempt-1)`, а не
фиксированная экспонента — лучше "размазывает" повторные попытки многих
одновременных клиентов и не создаёт синхронизированных "волн" на
восстанавливающийся сервер, см. AWS Architecture Blog "Exponential
Backoff And Jitter"). Управляется флагами `--max-retries`/
`--retry-base-delay-ms`.

**Важное architectural-ограничение, соблюдённое при реализации:**
retry-бюджет вписывается ВНУТРЬ общего таймаута, который передал
вызвавший клиент (`req.timeout_ms`), а не умножает его — `DbusClient`
использует то же самое значение как таймаут всего `sd_bus_call()` (см.
`dbus_client.hpp`), так что если бы демон ретраил, не считаясь с этим
бюджетом, D-Bus-вызов клиента истёк бы раньше, чем демон успел бы
завершить повторные попытки, и клиент увидел бы таймаут вместо
результата ретрая. `retry_with_backoff()` вычисляет remaining-time перед
каждой попыткой и перед каждой задержкой backoff, останавливаясь, если
бюджета уже не осталось.

**Явная граница пункта 10** (не забытый край): retry применяется ТОЛЬКО
к сбоям транспорта (`ok == false`), не к завершённым HTTP-ответам с
кодом ошибки (4xx/5xx, `ok == true`) — определённый ответ сервера "нет"
не то же самое, что оборванное соединение, и его повторять бессмысленно
(а для перегруженного сервера потенциально и вредно — см. пункт 11,
circuit breaker). Путь `ldap://` (пункт 9) тоже не обёрнут в retry —
аналогичное расширение несложно добавить отдельно при необходимости.

Тесты в `tests/test_client_server_roundtrip.cpp`:
`test_crl_fetch_succeeds_after_transient_failures_within_retry_budget`
(2 провала подряд, 3-я попытка успешна — итоговый результат `Ok`),
`test_crl_fetch_gives_up_after_exhausting_retry_budget` (провал на всех
3 попытках — `NetworkError`, ровно 3 обращения к "сети", не больше и не
меньше), `test_successful_transport_response_is_not_retried_even_with_error_status_code`
(HTTP 500 не ретраится — ровно 1 обращение).

### 11. [P1] Circuit breaker per-host для проблемных responder'ов

Раньше, если конкретный OCSP-responder/CDP-хост был устойчиво недоступен
или систематически отвечал ошибками, демон продолжал биться в него на
каждый TLS handshake (пусть и с retry из пункта 10) — это увеличивает
задержку для пользователя и нагрузку на и без того проблемный сервер.

Реализовано в `RequestRouter`: классический трёхсостоятельный паттерн
(Closed/Open/Half-Open), ключуемый по `host:port` из URL
(`host_port_key()`). Дополняет retry, а не дублирует его: retry борется
с одиночными транзиентными сбоями ВНУТРИ одного запроса, circuit
breaker — с устойчиво недоступным хостом НА ПРОТЯЖЕНИИ многих запросов.
После `circuit_breaker_failure_threshold` (по умолчанию 5) подряд
неудачных ЗАПРОСОВ (не отдельных попыток ретрая — breaker считает
исход каждого запроса целиком, уже после исчерпания его внутренних
retry, иначе он открывался бы после первого же запроса) — breaker
переходит в Open: следующие `circuit_breaker_cooldown_seconds` (по
умолчанию 30) все запросы к этому хосту отклоняются немедленно
(`NetworkError`) без единой попытки соединения. По истечении cooldown —
Half-Open: пропускает запрос как пробу; успех закрывает breaker
(сброс счётчика), неудача открывает его снова со свежим cooldown.
Управляется флагами `--circuit-breaker-failure-threshold`/
`--circuit-breaker-cooldown-seconds`/`--circuit-breaker-max-tracked-hosts`.

**Осознанные упрощения** (не забытые края):
- Half-Open пропускает ВСЕ конкурентные запросы к хосту, пришедшиеся на
  этот момент, а не строго один пробный запрос, как в классическом
  паттерне — под нагрузкой несколько проб могут уйти одновременно вместо
  одной. Корректность не страдает (если хост всё ещё недоступен, все они
  просто провалятся и снова откроют breaker), только чуть смягчается
  экономия в первый момент восстановления. Полная реализация с ровно
  одним пробным запросом потребовала бы отдельного состояния "проба уже
  в полёте" — сложность, не оправданная для этого случая.
- Карта breaker'ов НЕ ограничена строгим LRU (в отличие от
  `FileCacheStore::Limits`) — при достижении
  `circuit_breaker_max_tracked_hosts` новый хост вытесняет произвольную
  запись, не обязательно наименее используемую. URL приходят из
  AIA/OCSP/CDP расширений сертификата, предъявляемого потенциально
  недобросовестным сервером при перехвате TLS — то есть ключ карты
  частично под контролем атакующего; без предела карта росла бы
  неограниченно. Точная LRU здесь избыточна — это защита от
  неограниченного роста памяти, а не производительный кэш.
- Путь `ldap://` (пункт 9), как и в retry, не покрыт circuit breaker'ом —
  та же осознанная граница объёма работы.

Тесты в `tests/test_client_server_roundtrip.cpp`:
`test_circuit_breaker_opens_after_threshold_failures_and_fails_fast`
(после порога — следующие запросы не доходят до сети вообще, `call_count`
не растёт) и
`test_circuit_breaker_recovers_after_cooldown_on_successful_probe`
(после cooldown пробный запрос проходит и при успехе закрывает breaker).

### 12. [P1] HTTP keep-alive / пул соединений к часто запрашиваемым хостам

Раньше каждый вызов `fetch()` открывал новое TCP(+TLS)-соединение и
всегда слал `Connection: close` — framing ответа определялся чтением до
закрытия соединения сервером. При высокой частоте запросов к одному и
тому же CA/OCSP-responder (типичный сценарий — несколько крупных
публичных CA обслуживают большую часть трафика) это означает лишнее
TCP+TLS-рукопожатие на каждый запрос — заметная задержка и нагрузка на
CA.

Реализовано в `SimpleHttpFetcher` **полностью прозрачно** для
`IHttpFetcher`/`RequestRouter` — интерфейс не изменился, пул живёт
только внутри `SimpleHttpFetcher`:

- Запрос теперь шлёт `Connection: keep-alive`; framing ответа
  определяется по `Content-Length` или инкрементальному разбору
  `Transfer-Encoding: chunked` (`recv_and_parse_response()`/
  `try_decode_chunked_incremental()`), а не по EOF — это ключевая
  техническая предпосылка для keep-alive: соединение можно переиспользовать
  только если мы точно знаем конец предыдущего ответа, не дожидаясь,
  чтобы сервер его закрыл. Инкрементальный разбор chunked идёт строго
  по заявленным размерам чанков, никогда не ищет байтовые паттерны
  внутри непрозрачных данных — иначе бинарный CRL/OCSP-ответ, случайно
  содержащий подстроку вроде `"0\r\n\r\n"`, мог бы дать ложное
  срабатывание "конец найден".
- Пул простаивающих соединений (`PooledConnection`, RAII — закрывает
  fd/SSL при уничтожении), ключ — `host:port`, отдельно для `http://`/
  `https://`. Соединение НЕ переиспользуется, если framing неоднозначен
  (ни `Content-Length`, ни chunked — тогда пришлось читать до EOF, и
  сервер его и так уже закрыл), сервер прислал `Connection: close`, или
  это HTTP/1.0 без `Connection: keep-alive` (для HTTP/1.0 keep-alive не
  дефолтен).
- **Протухшие соединения** — ожидаемый, не ошибочный race для
  connection-пулов: сервер может закрыть простаивающее соединение по
  своему idle-таймауту в любой момент между тем, как мы вернули его в
  пул, и следующим использованием. При неудаче на переиспользованном
  соединении (`send` не прошёл, либо `recv` оборвался НЕ по таймауту)
  `fetch()` прозрачно и **без backoff** открывает новое соединение и
  повторяет запрос ровно один раз — это отдельный механизм от
  `retry_with_backoff()` из пункта 10: тот борется с сетевыми ошибками
  между демоном и сервером, этот — с локальной особенностью пула,
  которая с точки зрения "работает ли сеть" вообще не является сбоем.
- Лимиты пула (`kMaxIdleConnectionsPerHost=4`, `kMaxTotalIdleConnections=64`)
  — фиксированные константы, не вынесены в CLI-флаги: внутренний параметр
  производительности, не то, что реально требует тюнинга в проде (в
  отличие от security-relevant лимитов вроде `max_response_bytes`/
  `max_retries`, которые настраиваются явно).

Тесты — отдельный бинарник `tests/test_http_keepalive.cpp` с настоящим
персистентным TCP-сервером на 127.0.0.1 (не заглушка): переиспользование
соединения для двух запросов подряд (`accept()` ровно один раз),
корректность chunked-разбора при keep-alive, `Connection: close`
корректно предотвращает переиспользование, прозрачное восстановление
после протухшего пулированного соединения (сервер закрыл его первым),
и неоднозначный framing по-прежнему разбирается через чтение до EOF (и
не пытается переиспользоваться).

### 13. [P2] DNS-кэш для имён из AIA/OCSP/CDP URL

Раньше каждый запрос заново резолвил DNS-имя из URL, даже при частых
повторных обращениях к одному и тому же CA/OCSP-responder.

Реализовано в новом `src/dns_cache.hpp` — `DnsCache`, общий для
`SimpleHttpFetcher` и `SimpleLdapFetcher` (у каждого свой экземпляр, не
разделяемый — в реальном использовании HTTP- и LDAP-хосты, как правило,
разные, и делить кэш между ними не даёт заметной выгоды при
дополнительной сложности). По ходу вынес в этот же файл общие
`ResolvedAddress`/`make_sockaddr()` — раньше `connect_with_timeout()`
был почти дословно продублирован в `http_client.hpp` и
`ldap_client.hpp`.

**Явное ограничение и его обоснование:** `getaddrinfo()` (по-прежнему
используемый для самого резолвинга) не отдаёт TTL DNS-записи — это
доступно только через разбор сырого DNS-ответа (поле TTL в resource
record), что потребовало бы писать собственный DNS-клиент поверх
UDP/TCP — сопоставимый по объёму работы с LDAP-клиентом из пункта 9, и
неоправданный для этого пункта. Вместо этого используется
**фиксированный, консервативно короткий TTL** (по умолчанию 60 секунд,
флаг `--dns-cache-ttl-seconds`) — ровно второй из двух вариантов, явно
допущенных формулировкой пункта 13 ("нужен либо короткий TTL, либо
повторная проверка адреса при использовании кэша").

**Критичное для безопасности свойство, тоже прямо оговорённое в пункте
13:** кэширование IP-адресов само по себе не должно давать способ
обойти `NetworkPolicy`. `DnsCache` ничего не знает о политике — он
только отдаёт список IP-адресов на каждый вызов `resolve()`; политика
проверяется вызывающим кодом (`connect_with_timeout()` в
`http_client.hpp`/`ldap_client.hpp`) **для каждого адреса при каждом
вызове**, независимо от того, пришёл ли адрес из кэша или свежего
резолва — кэш не помнит и не влияет на то, проходил ли адрес
проверку раньше.

Тесты — `tests/test_dns_cache.cpp` (внедряемый `ResolverFn` вместо
реального `getaddrinfo()` — детерминированная проверка попадания/
промаха кэша, истечения TTL, того, что неудачный резолв не кэшируется,
независимости разных хостов друг от друга; плюс один тест реального
резолвинга `localhost`) и
`test_dns_cache_does_not_bypass_policy_on_repeated_use` в
`tests/test_http_cache_hints.cpp` (поведенческая проверка: второй запрос
к уже закэшированному хосту всё равно получает отказ политики, а не
тихо проходит).

**Побочная находка при подготовке этой сессии:** обнаружился (уже
дважды) ложный сбой `test_intermediate_cert_ttl_clamped_to_cert_not_after`/
`test_intermediate_cert_already_expired_not_cached` из-за того, что их
тестовые фикстуры (`test_certs/leaf_expires_soon.der`/
`leaf_already_expired.der`) были статическими файлами с датами вида
"+2 суток от момента генерации" — между рабочими сессиями, разделёнными
реальными днями, такая фикстура естественным образом старела и
переставала соответствовать своему названию. Исправлено: оба
сертификата теперь генерируются **во время выполнения теста**,
относительно текущего момента, через
`tests/test_util.hpp::generate_self_signed_cert_der()` (OpenSSL C API
напрямую, без Python) — эти статические файлы удалены из
`test_certs/`, задача такого рода в принципе не может быть корректно
решена статическим файлом. См. `test_certs/README.md`.

### 14. [P2] Батчинг OCSP-запросов

RFC 6960 §4.1 допускает несколько `Request` (`CertID`) в одном
`OCSPRequest`. Раньше tls-mitm, желая проверить статус нескольких
сертификатов цепочки (типичный случай — вся цепочка, полученная за один
TLS handshake), делал по одному отдельному D-Bus-вызову и HTTP
round-trip на каждый сертификат, даже если все они проверяются у одного
и того же responder'а.

Добавлен новый D-Bus метод `FetchOcspBatch(a(sayu)) -> a(yayb)` и
клиентский метод `DbusClient::fetch_ocsp_batch()`. `RequestRouter::
handle_ocsp_batch()`:

1. Проверяет кэш для каждого запроса батча индивидуально (тем же
   `CertID`-based ключом, что и одиночный `fetch_ocsp`) — попадания
   обслуживаются немедленно, без сети.
2. Группирует промахи по `responder_url`. Группа из одного элемента —
   обычный одиночный путь (через тот же `singleflight_execute()`, что и
   `handle_ocsp()`). Группа из нескольких — **один** комбинированный
   `OCSP_REQUEST` (`build_combined_ocsp_request()`, через
   `OCSP_request_add0_id()` — RFC 6960 позволяет прямо это), **один**
   HTTP POST через тот же `fetch_with_retry_and_circuit_breaker()`, что
   и у одиночных запросов (то же состояние circuit breaker для батчевых
   и обычных запросов к одному хосту).
3. При успехе — кэширует полученный комбинированный блок под
   **собственным** ключом каждого исходного запроса группы, с
   **индивидуальным** TTL, вычисленным по его же `CertID`
   (`OCSP_resp_find()` внутри `ocsp_response_ttl_seconds()` — простое
   "взять nextUpdate первого `SingleResponse`" было бы неверно для
   второго и далее сертификата группы, у каждого свой `nextUpdate`).
4. Если сборка комбинированного запроса не удалась — откат на
   независимые одиночные `fetch` для этой группы, не провал всего батча.

**Ключевое архитектурное решение, зафиксированное в `protocol.hpp`:**
несколько результатов из одной группы получают **побайтово идентичный**
`payload_der` — общий комбинированный блок, а не синтезированный
"персональный" ответ на каждый сертификат. Это не упрощение, а
необходимость: подпись responder'а покрывает `tbsResponseData` целиком
(все `SingleResponse` вместе), так что вырезать один `SingleResponse` в
отдельный "поддельный" `OCSPResponse` сделало бы его подпись невалидной.
Вызывающая сторона и так умеет находить нужный `SingleResponse` по
своему `CertID` внутри ответа — той же логикой, что и для одиночного
`fetch_ocsp`, если бы responder сам решил вернуть несколько
`SingleResponse` на один `Request` (RFC 6960 это не запрещает).

Тесты в `tests/test_client_server_roundtrip.cpp` (фикстуры —
настоящие OCSP-запросы/комбинированный ответ, генерируются во время
выполнения теста через `test_util::generate_ocsp_batch_fixtures()` —
OpenSSL C API напрямую, т.к. Python `cryptography` не поддерживает
несколько `SingleResponse` в одном ответе; см. также раздел про
`generate_self_signed_cert_der()` ниже про то, почему подобные
"осмысленные только относительно текущего момента" фикстуры не должны
быть статическими файлами):
объединение двух запросов к одному responder'у в один HTTP round-trip,
индивидуальное кэширование результатов батча, индивидуальный расчёт TTL
по `CertID` каждого элемента (не по первому попавшемуся), и полное
обслуживание из кэша при повторном батче без единого HTTP-запроса.

### 15. [P3] Прогрев кэша (cache warm-up) при старте

Раньше первые запросы сразу после рестарта/деплоя демона всегда были
"холодными" — каждый бил в сеть, даже если тот же самый URL уже
запрашивался миллион раз до рестарта.

Добавлен новый файл `src/cache_warmup.hpp` и флаг `--warmup-file
<путь>`: построчный текстовый файл с записями `crl:<url>`, `aia:<url>`
и `ocsp:<responder_url>:<cert_path>:<issuer_path>` (пустые строки и
строки, начинающиеся с `#`, игнорируются). Прогрев запускается **в
фоновом потоке сразу после старта D-Bus сервера** — не блокирует
готовность демона отвечать на обычные запросы (само наполнение кэша
происходит через `RequestRouter::handle_crl`/`handle_intermediate_cert`/
`handle_ocsp` — те же точки входа, что и обычные D-Bus-запросы, так что
прогретые записи оказываются в том же кэше с теми же правилами TTL).

**Почему `ocsp:` требует ДВА файла сертификатов, а не просто URL** (в
отличие от `crl:`/`aia:`, для которых URL — это всё, что нужно для
обычного GET): OCSP-запрос — это не "GET по URL", это POST с телом,
которое содержит `CertID` (issuer name hash + issuer key hash +
serialNumber) конкретного проверяемого сертификата (RFC 6960 §4.1). URL
одного responder'а сам по себе не говорит, статус какого именно
сертификата нужно прогреть. cert-helper строит `CertID` сам через
`OCSP_cert_to_id()`, но для этого ему нужны оба сертификата (subject +
issuer) — это прямое следствие самого протокола OCSP, не упущение в
дизайне. Файлы сертификатов принимаются и в PEM, и в DER (пробуем PEM
первым — у него распознаваемый текстовый заголовок).

Ошибки по отдельным записям (недоступный сервер, битый файл сертификата
и т.п.) не прерывают прогрев остальных записей — считаются отдельно от
нераспознанных строк файла и печатаются в stderr; итоговая сводка
(успешно/неудачно/нераспознанных строк) тоже идёт в stderr.

Тесты — `tests/test_cache_warmup.cpp`, напрямую через `RequestRouter`
(без D-Bus): `crl:`/`aia:` записи реально наполняют кэш, `ocsp:` запись
строит `CertID` из пары файлов сертификатов и кэширует результат,
нераспознанные строки (нет `:`, неизвестный тип, неверное число частей у
`ocsp:`) пропускаются без прерывания остальной обработки, сетевые сбои
отдельной записи учитываются отдельно от нераспознанных строк,
отсутствующий файл прогрева не приводит к падению. По ходу разработки
тест на `ocsp:`-записи поймал реальный баг парсинга: `responder_url`
сам содержит `:` (схема `http://`), и наивный `split` по всем
двоеточиям разрезал бы его неправильно — парсинг переписан «с конца»
строки (последние два `:`-сегмента — пути к файлам, всё, что осталось
слева, — `responder_url` целиком).

### 16. [P3] Экспорт/импорт кэша между хостами

Для миграции/клонирования инсталляции (например, при горизонтальном
масштабировании NGFW) не было способа перенести уже прогретый кэш на
новый хост — каждый узел приходилось "прогревать" с нуля.

**Ключевое наблюдение, упростившее реализацию:** файлы `FileCacheStore`
на диске уже хостонезависимы сами по себе — имя файла это
`sha256(kind|cache_key)` (чистая функция от типа запроса и URL/CertID,
не зависящая от хоста, на котором вычислена), а содержимое — просто
`(fetched_at, valid_until, payload)` без каких-либо host-specific
полей. Формально `cp -r`/`rsync` каталога кэша между хостами уже
сработал бы сам по себе, без единой строчки нового кода —
`FileCacheStore::load_index()` при следующем старте демона на целевом
хосте подхватит любые `*.bin` файлы, откуда бы они ни взялись.

Тем не менее просто скопировать директорию — не то же самое, что
предоставить безопасный, эргономичный инструмент: нужно (а) не тащить
уже просроченные записи (бессмысленный балласт), (б) дать администратору
один переносимый файл вместо "не забудь скопировать именно эту
директорию целиком, ничего лишнего не прихватив", (в) дать понятную
сводку. Добавлены `src/cache_export.hpp` (собственный простой
портируемый формат-контейнер поверх уже существующего on-disk формата
отдельной записи — не тянем libarchive ради одного узкого случая
использования) и отдельный, самостоятельный CLI-бинарник
`cert-helper-cache-tool`:

```
cert-helper-cache-tool export --cache-dir /var/lib/cert-helper/cache --file export.chcache
cert-helper-cache-tool import --cache-dir /var/lib/cert-helper/cache --file export.chcache
```

**Почему отдельный бинарник, а не подкоманда `cert-helper-cli`:**
`cert-helper-cli` — это D-Bus клиент, говорящий с ЗАПУЩЕННЫМ демоном;
экспорт/импорт — файловая операция на каталоге кэша напрямую, не
требующая ни демона, ни D-Bus вообще — и по этой же причине
`cert-helper-cache-tool` не линкуется с sd-bus/OpenSSL, они ему не
нужны.

**Экспорт/импорт работает НАПРЯМУЮ с файлами каталога кэша, в обход
интерфейса `ICacheStore`/`FileCacheStore`** — сознательное решение:
у экспорта/импорта нет доступа к исходным `cache_key` (только к их
хешам-именам файлов), так что расширять `ICacheStore` под этот узкий
сценарий CLI-утилиты означало бы раздувать интерфейс, которым
`RequestRouter` не пользуется.

Записи, уже просроченные **на момент экспорта** (лежали на диске
нетронутыми с момента последней проверки), не попадают в портируемый
файл вовсе; записи, ещё валидные на момент экспорта, но успевшие
протухнуть **к моменту импорта** (например, файл переносился между
хостами достаточно долго), не кладутся в целевой кэш при импорте —
проверка на просрочку выполняется на обеих сторонах.

**Снимок, а не транзакция:** если демон продолжает работать во время
экспорта, возможна гонка с записью новых файлов кэша — экспорт в
худшем случае не подхватит запись, дописанную после начала обхода
каталога (не крашится и не портит данные: запись отдельного файла в
`FileCacheStore` атомарна через temp-файл+`rename()`, та же гарантия
используется и при импорте). Для строго консистентного снимка следует
останавливать демон перед экспортом, но это не обязательно для
корректности — просто снимок может быть на мгновение отстающим от
актуального состояния.

Тесты — `tests/test_cache_export.cpp`: полный round-trip
экспорт→импорт с проверкой через настоящий `FileCacheStore::get()` на
"целевом" каталоге (не только побайтовое сравнение файлов), экспорт
пропускает уже просроченные записи, импорт пропускает записи,
протухшие с момента экспорта, файл не в нашем формате отклоняется
целиком, экспорт из пустого каталога не падает.

## Структура проекта


```
cert-helper/
├── CMakeLists.txt
├── proto/cert_helper.proto            # схема-документация исходного (уже не актуального) формата IPC
├── include/cert_helper/
│   ├── client.hpp                     # публичный клиентский API (OcspFetcher/CrlFetcher-совместимый)
│   └── protocol.hpp                   # плоские структуры запросов/ответов (без сериализации — её делает D-Bus)
├── src/
│   ├── daemon_main.cpp
│   ├── request_router.hpp             # маршрутизация запросов, TTL-политика (+HTTP cache hints), наблюдаемость
│   ├── http_client.hpp                # минимальный HTTP/1.1-клиент (interface IHttpFetcher), Cache-Control/Expires
│   ├── net_policy.hpp                 # политика destination'ов исходящего трафика (SSRF-защита)
│   ├── aia.hpp                        # извлечение caIssuers URL из X.509 (AIA)
│   ├── cache/
│   │   ├── cache_store.hpp            # файловый кэш с TTL/LRU (interface ICacheStore)
│   │   └── two_tier_cache.hpp         # in-memory LRU слой поверх файлового кэша
│   ├── ipc/
│   │   ├── dbus_interface.hpp         # имя шины/путь/интерфейс/имена методов — общие для сервера и клиента
│   │   └── dbus_server.hpp/.cpp       # D-Bus сервис поверх sd-bus, эластичный пул воркеров
│   └── client_impl/dbus_client.hpp    # синхронный D-Bus клиент (sd_bus_call)
├── tests/                             # 6 тестовых бинарей, включая интеграционный (приватный dbus-daemon)
├── examples/standalone_fetch_cli.cpp
├── test_certs/                        # тестовые сертификаты для test_aia_extraction
└── deploy/
    ├── cert-helper.service              # systemd unit, Type=dbus, BusName=
    └── org.certhelper.CertHelper1.conf  # D-Bus system bus policy (контроль доступа)
```

## Решения по открытым вопросам исходного ТЗ

Актуально для того, что осталось от первоначального дизайна после перехода
на D-Bus (сериализация сообщений и модель IPC-фрейминга сняты сами
собой, т.к. это теперь ответственность D-Bus):

1. **Бэкенд кэша: файловая директория**, не SQLite
   (`src/cache/cache_store.hpp`). Обоснование — в комментарии в начале
   файла.
2. **HTTP-клиент: минимальный HTTP/1.1 поверх BSD-сокетов**, не libcurl
   (`src/http_client.hpp`), с явной поддержкой только `http://`.
3. **Модель конкурентности: пул потоков** воркеров поверх одного
   bus-потока sd-bus (см. раздел «Транспорт: D-Bus» выше) — не полностью
   асинхронный event loop.
4. **`RevocationFetchers` не переименована** — новый тип
   `IntermediateCertFetcher`/`CertificateFetchers` вводится в рамках части
   2 (доработка `tls-mitm`, не в этом репозитории).
5. **Плагинная архитектура бэкендов — не реализована**, но `ICacheStore` и
   `IHttpFetcher` вынесены за интерфейсы.

## Соглашение об именовании

Приватные члены классов называются без trailing underscore (`config`, не
`config_`) и без префикса `m_`. Там, где это создавало бы конфликт имён
между членом и параметром конструктора в одной и той же
member-initializer-list записи, используется стандартный для C++ паттерн
`member(member)` (например, `RequestRouter::config`, `DbusServer::router`)
— компилятор однозначно разрешает такую запись (слева от скобки — имя
инициализируемого члена, внутри скобки — то, что видно по обычным
правилам области видимости, т.е. параметр конструктора). Там, где по
имени член совпадал бы с соседним namespace (`cache::`, `http::`) или с
уже существующим методом того же класса (`port()`), выбрано отдельное,
недвусмысленное имя (`cache_store`/`http_fetcher` в `RequestRouter`,
`listening_port` в тестовом `OneShotHttpServer`), а не голое совпадение с
одной только целью "убрать подчёркивание".

## Тестирование

- `tests/test_cache.cpp` — TTL-протухание, LRU-вытеснение по числу записей
  и по суммарному размеру, отсутствие коллизий между типами записей,
  персистентность между «перезапусками» демона.
- `tests/test_aia_extraction.cpp` — извлечение `caIssuers` URL из
  AIA-расширения: есть AIA, нет AIA, AIA только с OCSP (без caIssuers),
  битый DER, пустой вход.
- `tests/test_net_policy.cpp` — дефолтный deny-список (loopback, включая
  cloud metadata `169.254.169.254`, RFC1918 private, CGNAT, multicast),
  явные allow/deny-дополнения и их приоритет, порт-allowlist, разбор
  некорректных CIDR-строк.
- `tests/test_two_tier_cache.cpp` — memory-хит не бьёт в диск повторно
  (проверено обёрткой, считающей реальные обращения к диску), disk-хит
  прогревает память, разные типы записей не путаются в memory-слое,
  LRU-вытеснение и TTL в самом memory-слое, `CacheStats` отражает оба
  уровня.
- `tests/test_http_cache_hints.cpp` — разбор `Cache-Control: max-age`/
  `no-store`/`no-cache` и `Expires` из настоящего HTTP-ответа (поднимает
  собственный одноразовый HTTP-сервер на сырых сокетах прямо в тесте, без
  внешних зависимостей), плюс регрессия на то, что дефолтная сетевая
  политика блокирует loopback даже для этого фетчера.
- `tests/test_client_server_roundtrip.cpp` — интеграционный тест:
  поднимает приватный `dbus-daemon` (изолированный от системной шины
  хоста, через fork/exec с явным управлением жизненным циклом дочернего
  процесса), реальный `DbusServer` и реальный `DbusClient`/публичный
  `cert_helper::Client` поверх него, HTTP застаблен (`StubHttpFetcher`, без
  выхода в реальную сеть). Проверяет: health-check, кэширование успешного
  OCSP-ответа, отсутствие кэширования сетевой ошибки CRL, валидацию DER
  для докачанного промежуточного сертификата, контракт «пустой вектор при
  ошибке» на уровне публичного `Client`, устойчивость клиента к
  недоступной шине, и отдельно — что конкурентные fetch-запросы не
  сериализуются на одном "медленном" запросе (регрессия на архитектурное
  решение о пуле воркеров поверх одного bus-потока).

Дополнительно проведена ручная сквозная проверка: настоящий бинарь
`cert-helper`, поднятый на приватной шине, реальный HTTP-сервер на
localhost (отдающий `Cache-Control: max-age=60`) и `cert-helper-cli` —
полный путь клиент → D-Bus → демон → HTTP → кэш → обратно отработал
корректно, включая заполнение обоих уровней кэша и корректный инкремент
per-type счётчиков (видно через `health`).

## Что осталось за рамками этой реализации

Подробный, структурированный план всех выявленных направлений
дальнейшей доработки (безопасность/корректность, надёжность,
наблюдаемость, тестирование, упаковка, интеграция с `tls-mitm`), включая
актуальный статус (что уже сделано, отмечено **[СДЕЛАНО]**, что нет) —
см. [`ROADMAP.md`](./ROADMAP.md). Раздел 1 (безопасность и корректность
TTL/кэша) реализован целиком (пункты 1–9), из раздела 2 (надёжность и
производительность) реализованы пункты 10–16 (retry с backoff, circuit
breaker, HTTP keep-alive, DNS-кэш, батчинг OCSP, прогрев кэша,
экспорт/импорт кэша) — см.
README.md, раздел «Доработки по ROADMAP.md» выше.
Ключевое из оставшегося:

- Часть 2 исходного ТЗ — интеграция AIA-докачки в саму `tls-mitm`.
- Криптографическая проверка подписи OCSP-ответа/CRL внутри демона —
  сознательно оставлена `tls-mitm`.
- D-Bus service-activation файл (`/usr/share/dbus-1/system-services/...`)
  для запуска демона "по требованию" при первом вызове — не реализован
  сознательно: демон рассчитан на постоянную работу под управлением
  systemd (`deploy/cert-helper.service`, обычный `systemctl enable`), а не
  на активацию по факту первого D-Bus-запроса. Если это понадобится в
  будущем — файл активации несложно добавить поверх уже имеющегося
  `Type=dbus`/`BusName=` в unit-файле.
- Надёжность (retry/circuit breaker/keep-alive/DNS-кэш), наблюдаемость
  (Prometheus/структурные логи), упаковка (.deb/.rpm/Docker) — все
  P1–P3, см. `ROADMAP.md` за деталями и обоснованием приоритета каждого.
