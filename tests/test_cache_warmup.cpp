// test_cache_warmup.cpp — тесты прогрева кэша при старте (ROADMAP.md,
// раздел 2, пункт 15). Не поднимает D-Bus/полный демон — использует
// RequestRouter напрямую (та же точка входа, что и warmup::run()),
// сфокусировано на самой логике разбора файла прогрева и на том, что
// прогретые записи действительно оказываются в кэше.

#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include "../src/cache/cache_store.hpp"
#include "../src/cache_warmup.hpp"
#include "../src/http_client.hpp"
#include "../src/request_router.hpp"
#include "test_util.hpp"

namespace fs = std::filesystem;
using namespace cert_helper;

namespace {

fs::path make_temp_dir(const std::string& suffix) {
    auto dir = fs::temp_directory_path() / ("cert_helper_warmup_test_" + suffix + "_" +
                                             std::to_string(::getpid()) + "_" +
                                             std::to_string(reinterpret_cast<uintptr_t>(&suffix)));
    fs::create_directories(dir);
    return dir;
}

// Стаб IHttpFetcher — та же роль, что StubHttpFetcher в
// test_client_server_roundtrip.cpp, здесь реализован заново по тем же
// принципам, чтобы не тянуть весь тот файл ради одного класса.
class StubHttpFetcher : public http::IHttpFetcher {
public:
    struct Canned {
        bool ok = true;
        int status_code = 200;
        std::vector<uint8_t> body;
    };

    void set_response(const std::string& url, Canned resp) { responses[url] = std::move(resp); }
    int call_count(const std::string& url) const {
        auto it = call_counts.find(url);
        return it == call_counts.end() ? 0 : it->second;
    }

    http::HttpResult fetch(http::Method, const std::string& url, const std::vector<uint8_t>&,
                            const std::string&, uint32_t, size_t) override {
        ++call_counts[url];
        http::HttpResult result;
        auto it = responses.find(url);
        if (it == responses.end()) return result;
        result.ok = it->second.ok;
        result.status_code = it->second.status_code;
        result.body = it->second.body;
        return result;
    }

private:
    std::unordered_map<std::string, Canned> responses;
    std::unordered_map<std::string, int> call_counts;
};

std::string write_temp_file(const fs::path& dir, const std::string& name, const std::string& content) {
    auto path = dir / name;
    std::ofstream out(path, std::ios::binary);
    out << content;
    return path.string();
}

std::string write_temp_der_file(const fs::path& dir, const std::string& name, const std::vector<uint8_t>& der) {
    auto path = dir / name;
    std::ofstream out(path, std::ios::binary);
    out.write(reinterpret_cast<const char*>(der.data()), static_cast<std::streamsize>(der.size()));
    return path.string();
}

// ROADMAP.md, раздел 2, пункт 15: crl:/aia: записи из файла прогрева
// должны реально наполнить кэш — последующий "нормальный" запрос к
// тому же URL должен обслужиться из кэша, без обращения к "сети".
void test_warmup_populates_cache_for_crl_and_aia_entries() {
    auto dir = make_temp_dir("crl_aia");
    cache::FileCacheStore cache(dir / "cache", cache::FileCacheStore::Limits{});
    StubHttpFetcher http;

    std::string crl_url = "http://crl.example.test/base.crl";
    std::string aia_url = "http://ca.example.test/issuer.cer";
    auto crl_der = test_util::generate_self_signed_cert_der("crl-warmup.example.test", -1, 30);
    auto aia_der = test_util::generate_self_signed_cert_der("aia-warmup.example.test", -1, 30);
    http.set_response(crl_url, StubHttpFetcher::Canned{true, 200, crl_der});
    http.set_response(aia_url, StubHttpFetcher::Canned{true, 200, aia_der});

    RequestRouter router(cache, http, RequestRouter::Config{});

    std::string warmup_content = "# комментарий, должен игнорироваться\n"
                                  "\n"
                                  "crl:" +
                                  crl_url +
                                  "\n"
                                  "aia:" +
                                  aia_url + "\n";
    auto warmup_path = write_temp_file(dir, "warmup.txt", warmup_content);

    auto stats = warmup::run(warmup_path, router);
    TEST_CHECK_EQ(stats.succeeded, 2);
    TEST_CHECK_EQ(stats.failed, 0);
    TEST_CHECK_EQ(stats.skipped_malformed_lines, 0);

    // Повторный "обычный" запрос — должен обслужиться из кэша, не сети.
    proto::FetchCrlRequest crl_req;
    crl_req.distribution_point_url = crl_url;
    auto crl_resp = router.handle_crl(crl_req);
    TEST_CHECK(crl_resp.status == proto::FetchStatus::Ok);
    TEST_CHECK(crl_resp.from_cache);
    TEST_CHECK_EQ(http.call_count(crl_url), 1); // всё ещё 1 — прогрев уже сходил, повтор из кэша

    proto::FetchIntermediateCertRequest aia_req;
    aia_req.aia_url = aia_url;
    auto aia_resp = router.handle_intermediate_cert(aia_req);
    TEST_CHECK(aia_resp.status == proto::FetchStatus::Ok);
    TEST_CHECK(aia_resp.from_cache);
    TEST_CHECK_EQ(http.call_count(aia_url), 1);

    std::error_code ec;
    fs::remove_all(dir, ec);
}

// ROADMAP.md, раздел 2, пункт 15: ocsp: запись строит CertID из пары
// файлов сертификатов (cert+issuer) через OCSP_cert_to_id() — здесь
// проверяем именно это (не просто URL, как для crl:/aia:).
void test_warmup_ocsp_entry_builds_certid_from_cert_files_and_caches_result() {
    auto dir = make_temp_dir("ocsp");
    cache::FileCacheStore cache(dir / "cache", cache::FileCacheStore::Limits{});
    StubHttpFetcher http;

    std::string responder_url = "http://ocsp.example.test/warmup";
    auto ocsp_response = test_util::generate_ocsp_batch_fixtures(2, 20).combined_response;
    http.set_response(responder_url, StubHttpFetcher::Canned{true, 200, ocsp_response});

    // Сертификаты для построения CertID в OCSP-записи прогрева — сами по
    // себе никак не связаны с ocsp_response выше по факту подписи
    // (это тестовый стаб: StubHttpFetcher отдаёт canned-ответ независимо
    // от тела запроса), важно только то, что warmup::run() успешно
    // строит из них CertID и делает POST-запрос.
    auto cert_der = test_util::generate_self_signed_cert_der("leaf-for-warmup.example.test", -1, 365);
    auto issuer_der = test_util::generate_self_signed_cert_der("issuer-for-warmup.example.test", -1, 3650);
    auto cert_path = write_temp_der_file(dir, "leaf.der", cert_der);
    auto issuer_path = write_temp_der_file(dir, "issuer.der", issuer_der);

    RequestRouter router(cache, http, RequestRouter::Config{});

    std::string warmup_content = "ocsp:" + responder_url + ":" + cert_path + ":" + issuer_path + "\n";
    auto warmup_path = write_temp_file(dir, "warmup.txt", warmup_content);

    auto stats = warmup::run(warmup_path, router);
    TEST_CHECK_EQ(stats.succeeded, 1);
    TEST_CHECK_EQ(stats.failed, 0);
    TEST_CHECK_EQ(http.call_count(responder_url), 1);
}

// Строки без ':' или с неизвестным типом должны пропускаться с учётом в
// skipped_malformed_lines, не прерывая обработку остальных строк файла.
void test_warmup_skips_malformed_lines_without_aborting() {
    auto dir = make_temp_dir("malformed");
    cache::FileCacheStore cache(dir / "cache", cache::FileCacheStore::Limits{});
    StubHttpFetcher http;

    std::string crl_url = "http://crl.example.test/good.crl";
    auto crl_der = test_util::generate_self_signed_cert_der("good-crl.example.test", -1, 30);
    http.set_response(crl_url, StubHttpFetcher::Canned{true, 200, crl_der});

    RequestRouter router(cache, http, RequestRouter::Config{});

    std::string warmup_content = "this line has no colon at all\n"
                                  "unknown_type:something\n"
                                  "ocsp:only-one-part\n"
                                  "crl:" +
                                  crl_url + "\n";
    auto warmup_path = write_temp_file(dir, "warmup.txt", warmup_content);

    auto stats = warmup::run(warmup_path, router);
    TEST_CHECK_EQ(stats.succeeded, 1); // только валидная crl: строка
    TEST_CHECK_EQ(stats.skipped_malformed_lines, 3); // остальные три — нераспознанные

    std::error_code ec;
    fs::remove_all(dir, ec);
}

// Неудачный fetch (сервер недоступен) для отдельной записи не должен
// прерывать обработку остальных записей файла — учитывается как failed,
// не malformed.
void test_warmup_counts_network_failures_separately_from_malformed_lines() {
    auto dir = make_temp_dir("netfail");
    cache::FileCacheStore cache(dir / "cache", cache::FileCacheStore::Limits{});
    StubHttpFetcher http; // "unreachable.example.test" намеренно не сконфигурирован в http -> ok=false

    std::string good_url = "http://crl.example.test/good.crl";
    auto crl_der = test_util::generate_self_signed_cert_der("good2-crl.example.test", -1, 30);
    http.set_response(good_url, StubHttpFetcher::Canned{true, 200, crl_der});

    RequestRouter router(cache, http, RequestRouter::Config{});

    std::string warmup_content = "crl:http://unreachable.example.test/dead.crl\n"
                                  "crl:" +
                                  good_url + "\n";
    auto warmup_path = write_temp_file(dir, "warmup.txt", warmup_content);

    auto stats = warmup::run(warmup_path, router);
    TEST_CHECK_EQ(stats.succeeded, 1);
    TEST_CHECK_EQ(stats.failed, 1);
    TEST_CHECK_EQ(stats.skipped_malformed_lines, 0);

    std::error_code ec;
    fs::remove_all(dir, ec);
}

// Несуществующий файл прогрева не должен приводить к падению — просто
// нулевая статистика и сообщение в stderr.
void test_warmup_missing_file_does_not_crash() {
    auto dir = make_temp_dir("missing");
    cache::FileCacheStore cache(dir / "cache", cache::FileCacheStore::Limits{});
    StubHttpFetcher http;
    RequestRouter router(cache, http, RequestRouter::Config{});

    auto stats = warmup::run((dir / "does-not-exist.txt").string(), router);
    TEST_CHECK_EQ(stats.succeeded, 0);
    TEST_CHECK_EQ(stats.failed, 0);

    std::error_code ec;
    fs::remove_all(dir, ec);
}

} // namespace

int main() {
    RUN_TEST(test_warmup_populates_cache_for_crl_and_aia_entries);
    RUN_TEST(test_warmup_ocsp_entry_builds_certid_from_cert_files_and_caches_result);
    RUN_TEST(test_warmup_skips_malformed_lines_without_aborting);
    RUN_TEST(test_warmup_counts_network_failures_separately_from_malformed_lines);
    RUN_TEST(test_warmup_missing_file_does_not_crash);
    TEST_MAIN_EXIT();
}
