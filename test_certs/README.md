# Тестовые сертификаты

Самоподписанные сертификаты, используемые только в `tests/test_aia_extraction.cpp`
для проверки разбора расширения Authority Information Access. Не являются
частью какой-либо реальной цепочки доверия, не содержат секретов (приватные
ключи не сохранены — сгенерированы и сразу удалены, в фикстурах остались
только публичные сертификаты в DER).

Сгенерированы так:

```
# leaf_with_aia.der — caIssuers + OCSP
openssl req -x509 -newkey rsa:2048 -nodes -keyout /tmp/k.pem -out /tmp/c.pem -days 3650 \
  -subj "/CN=leaf-with-aia.example.test" \
  -addext "authorityInfoAccess=caIssuers;URI:http://ca.example.test/intermediate.cer,OCSP;URI:http://ocsp.example.test/"
openssl x509 -in /tmp/c.pem -outform DER -out leaf_with_aia.der

# leaf_no_aia.der — без AIA-расширения вовсе
openssl req -x509 -newkey rsa:2048 -nodes -keyout /tmp/k2.pem -out /tmp/c2.pem -days 3650 \
  -subj "/CN=leaf-no-aia.example.test"
openssl x509 -in /tmp/c2.pem -outform DER -out leaf_no_aia.der

# leaf_ocsp_only.der — AIA есть, но только OCSP, без caIssuers
openssl req -x509 -newkey rsa:2048 -nodes -keyout /tmp/k3.pem -out /tmp/c3.pem -days 3650 \
  -subj "/CN=leaf-ocsp-only.example.test" \
  -addext "authorityInfoAccess=OCSP;URI:http://ocsp.example.test/"
openssl x509 -in /tmp/c3.pem -outform DER -out leaf_ocsp_only.der
```

## Тест клампинга TTL по notAfter (ROADMAP.md, п.1) — БЕЗ статических фикстур

`test_intermediate_cert_ttl_clamped_to_cert_not_after` и
`test_intermediate_cert_already_expired_not_cached` в
`tests/test_client_server_roundtrip.cpp` проверяют, что TTL кэша
AIA-докачки клампится сверху сроком действия самого сертификата (P0,
не должен пережить `notAfter`), и что уже просроченный сертификат
вообще не кэшируется.

**Раньше** для этого использовались статические файлы-фикстуры
(`leaf_expires_soon.der`/`leaf_already_expired.der`) с датами вида
"+2 суток от момента генерации фикстуры". Это оказалось хрупким: между
рабочими сессиями, разделёнными реальными днями, такая фикстура
естественным образом СТАРЕЕТ — сертификат, который на момент генерации
был "ещё валиден 2 суток", через несколько дней реального времени
внезапно становится "уже просроченным", и тест начинает падать не
из-за бага в коде, а из-за устаревшей даты в закоммиченном файле. Это
уже дважды приводило к ложным падениям тестов между сессиями.

**Теперь** оба сертификата генерируются **во время выполнения теста**,
относительно текущего момента — см.
`tests/test_util.hpp::generate_self_signed_cert_der()` (генерация через
OpenSSL C API напрямую, без внешних зависимостей вроде Python). Файлы
`leaf_expires_soon.der`/`leaf_already_expired.der` в этом каталоге
больше не существуют и не нужны — эта проблема класса "фикстура,
осмысленная только относительно текущего времени" в принципе не может
быть корректно решена статическим файлом, только генерацией на лету.

## Фикстуры для теста верхней границы TTL OCSP/CRL (ROADMAP.md, п.2)

`ocsp_response_far_future.der` и `crl_far_future.der` используются
`tests/test_client_server_roundtrip.cpp` для проверки, что TTL,
вычисленный из `nextUpdate` OCSP-ответа/CRL, клампится сверху константами
`max_ocsp_ttl_seconds`/`max_crl_ttl_seconds` (P0) независимо от того, что
заявил responder/CA — модель угрозы: недобросовестный или
скомпрометированный responder указывает `nextUpdate` на ~год вперёд,
пытаясь заставить демон отдавать устаревший статус отзыва целый год.
`openssl ocsp`/`openssl ca -gencrl` не позволяют удобно задать
подписанный OCSP-ответ/CRL с произвольным `nextUpdate` без полноценного
CA-окружения, поэтому обе фикстуры сгенерированы через Python
`cryptography`:

```python
import datetime
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from cryptography.x509 import ocsp

now = datetime.datetime.now(datetime.timezone.utc)

issuer_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
issuer_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-issuer.example.test")])
issuer_cert = (
    x509.CertificateBuilder()
    .subject_name(issuer_name).issuer_name(issuer_name)
    .public_key(issuer_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(now - datetime.timedelta(days=1))
    .not_valid_after(now + datetime.timedelta(days=3650))
    .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    .sign(issuer_key, hashes.SHA256())
)

leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "leaf-for-ocsp.example.test")])
leaf_cert = (
    x509.CertificateBuilder()
    .subject_name(leaf_name).issuer_name(issuer_name)
    .public_key(leaf_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(now - datetime.timedelta(days=1))
    .not_valid_after(now + datetime.timedelta(days=3650))
    .sign(issuer_key, hashes.SHA256())
)

builder = ocsp.OCSPResponseBuilder().add_response(
    cert=leaf_cert, issuer=issuer_cert, algorithm=hashes.SHA1(),
    cert_status=ocsp.OCSPCertStatus.GOOD,
    this_update=now, next_update=now + datetime.timedelta(days=400),
    revocation_time=None, revocation_reason=None,
).responder_id(ocsp.OCSPResponderEncoding.HASH, issuer_cert)
ocsp_response = builder.sign(issuer_key, hashes.SHA256())
with open("ocsp_response_far_future.der", "wb") as f:
    f.write(ocsp_response.public_bytes(serialization.Encoding.DER))

crl = (
    x509.CertificateRevocationListBuilder()
    .issuer_name(issuer_name)
    .last_update(now).next_update(now + datetime.timedelta(days=400))
    .sign(issuer_key, hashes.SHA256())
)
with open("crl_far_future.der", "wb") as f:
    f.write(crl.public_bytes(serialization.Encoding.DER))
```

Оба файла — валидный подписанный DER (OpenSSL, который использует
демон через `d2i_OCSP_RESPONSE`/`d2i_X509_CRL`, успешно их разбирает);
подпись не от доверенного корня, но демон её и не проверяет (см.
комментарий в `request_router.hpp` про то, что валидацию подписи делает
tls-mitm, а не демон) — для теста клампинга TTL это неважно, важен только
разбор `nextUpdate`.

## Фикстуры для теста ключа OCSP-кэша по CertID (ROADMAP.md, п.3)

`ocsp_request_certid_a_nonce1.der`/`ocsp_request_certid_a_nonce2.der`/
`ocsp_request_certid_b_nonce1.der` используются
`tests/test_client_server_roundtrip.cpp` для проверки, что кэш OCSP
ключуется по `CertID` (issuer name hash + issuer key hash +
serialNumber), а не по фингерпринту всего DER-запроса — иначе
nonce-расширение (RFC 8954, защита от replay) ломает кэш: `nonce_a1` и
`nonce_a2` — два разных, реальных, ASN.1-корректных OCSP-запроса **для
одного и того же сертификата** (одинаковый `CertID`), различающихся
только случайным nonce; `nonce_b1` — запрос для *другого* сертификата
(другой `serialNumber`, тот же issuer), нужен для проверки, что разные
сертификаты не схлопываются в один и тот же ключ кэша. Сгенерированы
через Python `cryptography` (поддерживает построение настоящего
`OCSPRequest` с nonce-расширением из коробки):

```python
import os, datetime
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from cryptography.x509 import ocsp

now = datetime.datetime.now(datetime.timezone.utc)
issuer_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
issuer_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-issuer2.example.test")])
issuer_cert = (
    x509.CertificateBuilder()
    .subject_name(issuer_name).issuer_name(issuer_name)
    .public_key(issuer_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(now - datetime.timedelta(days=1))
    .not_valid_after(now + datetime.timedelta(days=3650))
    .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    .sign(issuer_key, hashes.SHA256())
)

def make_leaf(cn):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    return (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(issuer_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .sign(issuer_key, hashes.SHA256())
    )

def make_request(cert, nonce_bytes, path):
    req = (
        ocsp.OCSPRequestBuilder()
        .add_certificate(cert, issuer_cert, hashes.SHA1())
        .add_extension(x509.OCSPNonce(nonce_bytes), critical=False)
        .build()
    )
    with open(path, "wb") as f:
        f.write(req.public_bytes(serialization.Encoding.DER))

leaf_a = make_leaf("leaf-for-ocsp-nonce.example.test")
leaf_b = make_leaf("leaf-for-ocsp-nonce-b.example.test")
make_request(leaf_a, os.urandom(16), "ocsp_request_certid_a_nonce1.der")
make_request(leaf_a, os.urandom(16), "ocsp_request_certid_a_nonce2.der")
make_request(leaf_b, os.urandom(16), "ocsp_request_certid_b_nonce1.der")
```

## Фикстуры для теста PKCS#7 "degenerate"-контейнера в AIA (ROADMAP.md, п.6)

`aia_pkcs7_single_cert.der`/`aia_pkcs7_multi_cert.der` используются
`tests/test_client_server_roundtrip.cpp` для проверки, что
`RequestRouter` понимает caIssuers-ответ, пришедший как PKCS#7
"degenerate" контейнер (`application/pkcs7-mime` — SignedData-обёртка
без реальной подписи, только с сертификатами внутри), а не только голый
DER X.509. `aia_pkcs7_single_cert_expected.der`/
`aia_pkcs7_multi_cert_expected_first.der` — "эталонные" DER-байты того
сертификата, который демон должен извлечь из соответствующего
контейнера. Сгенерированы через Python `cryptography`
(`serialization.pkcs7.serialize_certificates`):

```python
import datetime
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import NameOID

now = datetime.datetime.now(datetime.timezone.utc)

def make_ca(cn, key):
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    return (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )

issuer_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
issuer_cert = make_ca("test-issuer-pkcs7.example.test", issuer_key)

# Один сертификат в контейнере — самый частый на практике случай.
single_der = pkcs7.serialize_certificates([issuer_cert], serialization.Encoding.DER)
with open("aia_pkcs7_single_cert.der", "wb") as f:
    f.write(single_der)
with open("aia_pkcs7_single_cert_expected.der", "wb") as f:
    f.write(issuer_cert.public_bytes(serialization.Encoding.DER))

# Несколько сертификатов — некоторые CA кладут в caIssuers весь хвост цепочки.
second_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
second_cert = make_ca("test-root-pkcs7.example.test", second_key)
multi_der = pkcs7.serialize_certificates([issuer_cert, second_cert], serialization.Encoding.DER)
with open("aia_pkcs7_multi_cert.der", "wb") as f:
    f.write(multi_der)
```

**Важная деталь, из-за которой `aia_pkcs7_multi_cert_expected_first.der`
не собран напрямую из Python:** порядок сертификатов внутри
`STACK_OF(X509)`, который в итоге видит `d2i_PKCS7` на C++-стороне, НЕ
обязательно совпадает с порядком, переданным в
`serialize_certificates([issuer_cert, second_cert])` — в этом конкретном
случае `cryptography` кладёт их в обратном порядке. Полагаться на
порядок аргументов Python-вызова для эталонного файла было бы хрупко и
могло молча разойтись с реальным поведением OpenSSL при следующей
перегенерации фикстуры. Поэтому `aia_pkcs7_multi_cert_expected_first.der`
извлечён из уже сгенерированного `aia_pkcs7_multi_cert.der` напрямую
через `d2i_PKCS7`/`sk_X509_value(certs, 0)`/`i2d_X509` — то есть тем же
кодом, что использует и сам демон (`extract_single_der_certificate()` в
`request_router.hpp`), а не пересобран "по названию" в Python:

```cpp
// см. request_router.hpp::extract_single_der_certificate() — тот же путь
PKCS7* p7 = d2i_PKCS7(nullptr, &p, (long)data.size());
STACK_OF(X509)* certs = p7->d.sign->cert;
X509* c = sk_X509_value(certs, 0);
unsigned char* out = nullptr;
int len = i2d_X509(c, &out);
// сохранить out[0..len) в aia_pkcs7_multi_cert_expected_first.der
```

## Фикстуры для теста поддержки https:// (ROADMAP.md, п.7)

`https_test_ca_cert.pem`/`https_test_server_cert.pem`/
`https_test_server_key.pem` используются `tests/test_https_support.cpp`,
который поднимает настоящий TLS-сервер на 127.0.0.1 для проверки
`SimpleHttpFetcher`'а с реальным TLS-хендшейком (не заглушкой). В отличие
от остальных фикстур в этом каталоге, здесь **пришлось сохранить и
приватный ключ сервера** (`https_test_server_key.pem`) — тесту нужно
реально "быть" этим TLS-сервером, а не только предъявлять сертификат.
Ключ и сертификаты не имеют никакой ценности за пределами этого набора
тестов: сертификат сервера подписан только собственным тестовым CA из
этого же каталога, который не является ничьим доверенным корнем за
пределами явного указания через `--https-ca-bundle`/тестовый
`ca_bundle_path`. SAN сертификата сервера включает `IP:127.0.0.1` и
`DNS:localhost` — тест обращается по IP, поэтому важно, что
`SimpleHttpFetcher` при верификации IP-литерала использует
`X509_VERIFY_PARAM_set1_ip_asc`, а не `set1_host` (который проверяет
только `dNSName`/CN и не видит `iPAddress`-записи SAN вообще). Сгенерированы через Python `cryptography`:

```python
import datetime, ipaddress
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

now = datetime.datetime.now(datetime.timezone.utc)

ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "cert-helper test CA")])
ca_cert = (
    x509.CertificateBuilder()
    .subject_name(ca_name).issuer_name(ca_name)
    .public_key(ca_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(now - datetime.timedelta(days=1))
    .not_valid_after(now + datetime.timedelta(days=3650))
    .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    .sign(ca_key, hashes.SHA256())
)

server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
server_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
server_cert = (
    x509.CertificateBuilder()
    .subject_name(server_name).issuer_name(ca_name)
    .public_key(server_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(now - datetime.timedelta(days=1))
    .not_valid_after(now + datetime.timedelta(days=3650))
    .add_extension(
        x509.SubjectAlternativeName([
            x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
            x509.DNSName("localhost"),
        ]),
        critical=False,
    )
    .sign(ca_key, hashes.SHA256())
)

with open("https_test_ca_cert.pem", "wb") as f:
    f.write(ca_cert.public_bytes(serialization.Encoding.PEM))
with open("https_test_server_cert.pem", "wb") as f:
    f.write(server_cert.public_bytes(serialization.Encoding.PEM))
with open("https_test_server_key.pem", "wb") as f:
    f.write(server_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ))
```

## Фикстуры для теста Delta CRL (ROADMAP.md, п.8)

`crl_with_freshest_crl_ext.der`, `delta_crl.der` и
`leaf_with_freshest_crl.der` используются
`tests/test_crl_delta_extraction.cpp` для проверки разбора расширений
`freshestCRL` (на CRL и на сертификате) и `deltaCRLIndicator` (на самой
delta CRL) — см. `src/crl_delta.hpp`. Как baseline "расширения нет"
переиспользуются уже существующие `crl_far_future.der` (обычный полный
CRL без каких-либо delta-related расширений) и `leaf_no_aia.der`.
Сгенерированы через Python `cryptography`, у которой уже есть готовые
классы `x509.FreshestCRL` и `x509.DeltaCRLIndicator`:

```python
import datetime
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

now = datetime.datetime.now(datetime.timezone.utc)

ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-issuer-delta-crl.example.test")])
ca_cert = (
    x509.CertificateBuilder()
    .subject_name(ca_name).issuer_name(ca_name)
    .public_key(ca_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(now - datetime.timedelta(days=1))
    .not_valid_after(now + datetime.timedelta(days=3650))
    .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    .sign(ca_key, hashes.SHA256())
)

freshest_url = "http://crl.example.test/delta.crl"
dist_point = x509.DistributionPoint(
    full_name=[x509.UniformResourceIdentifier(freshest_url)],
    relative_name=None, reasons=None, crl_issuer=None,
)

# Полный (базовый) CRL С расширением freshestCRL.
crl_with_freshest = (
    x509.CertificateRevocationListBuilder()
    .issuer_name(ca_name)
    .last_update(now).next_update(now + datetime.timedelta(days=7))
    .add_extension(x509.FreshestCRL([dist_point]), critical=False)
    .sign(ca_key, hashes.SHA256())
)
with open("crl_with_freshest_crl_ext.der", "wb") as f:
    f.write(crl_with_freshest.public_bytes(serialization.Encoding.DER))

# Delta CRL — помечена deltaCRLIndicator (BaseCRLNumber=42).
delta_crl = (
    x509.CertificateRevocationListBuilder()
    .issuer_name(ca_name)
    .last_update(now).next_update(now + datetime.timedelta(hours=1))
    .add_extension(x509.DeltaCRLIndicator(42), critical=True)
    .sign(ca_key, hashes.SHA256())
)
with open("delta_crl.der", "wb") as f:
    f.write(delta_crl.public_bytes(serialization.Encoding.DER))

# Сертификат С расширением freshestCRL (альтернативное место по RFC 5280).
leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "leaf-with-freshest-crl.example.test")])
leaf_with_freshest = (
    x509.CertificateBuilder()
    .subject_name(leaf_name).issuer_name(ca_name)
    .public_key(leaf_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(now - datetime.timedelta(days=1))
    .not_valid_after(now + datetime.timedelta(days=365))
    .add_extension(x509.FreshestCRL([dist_point]), critical=False)
    .sign(ca_key, hashes.SHA256())
)
with open("leaf_with_freshest_crl.der", "wb") as f:
    f.write(leaf_with_freshest.public_bytes(serialization.Encoding.DER))
```

## Про отсутствие файловых фикстур для теста ldap:// (ROADMAP.md, п.9)

`tests/test_ldap_support.cpp` не использует файловые DER-фикстуры из
этого каталога — переиспользует произвольные байтовые массивы прямо в
коде теста в качестве "значения атрибута" (реальный формат — DER самого
CRL — для проверки LDAP-протокола не имеет значения: `SimpleLdapFetcher`
не разбирает содержимое атрибута, просто возвращает его байты
вызывающему коду). Корректность самого протокольного клиента
(BER-кодирование, bind/search, разбор ответа) проверена отдельно —
подробности в комментарии в начале `tests/test_ldap_support.cpp`,
включая ручную сверку с настоящим OpenLDAP-сервером (`slapd`) в процессе
разработки, не зафиксированную в виде автоматического теста (не входит
в зависимости сборки cert-helper).

## Фикстуры для теста батчинга OCSP-запросов (ROADMAP.md, п.14) — тоже БЕЗ статических файлов

Как и фикстуры для клампинга TTL по notAfter (см. раздел выше), фикстуры
для теста батчинга OCSP (два одиночных OCSP-запроса с разными `CertID`
+ один комбинированный ответ с двумя `SingleResponse`) генерируются **во
время выполнения теста**, а не как статические файлы в этом каталоге —
`tests/test_util.hpp::generate_ocsp_batch_fixtures()`. Эта фикстура
изначально была статическим файлом (как и почти все остальные в этом
каталоге), но её `nextUpdate` был осмыслен только относительно момента
генерации ("+2 часа", "+20 часов") — и, ожидаемо, тест на её основе
тоже сломался спустя часы реального времени между рабочими сессиями (та
же проблема, что и с `leaf_expires_soon.der` выше). Дублировать
объяснение здесь не будем — оно то же самое.

Почему генерация идёт через OpenSSL C API, а не Python `cryptography`
(как большинство остальных фикстур в этом каталоге): `cryptography.
x509.ocsp.OCSPResponseBuilder` на уровне библиотеки запрещает несколько
`add_response()` на один билдер (`ValueError: Only one response per
OCSPResponse`), хотя RFC 6960 допускает несколько `SingleResponse` в
одном ответе. `generate_ocsp_batch_fixtures()` строит комбинированный
ответ вручную через `OCSP_basic_add1_status()` (дважды, на один
`OCSP_BASICRESP`) и один `OCSP_basic_sign()` на весь объединённый блок
— см. полный листинг в `tests/test_util.hpp`.
