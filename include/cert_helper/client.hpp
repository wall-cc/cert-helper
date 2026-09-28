// client.hpp
//
// Публичный клиентский API cert-helper. Единственная точка входа для
// NGFW/tls-mitm — оборачивает транспортные детали (теперь — D-Bus, см.
// src/client_impl/dbus_client.hpp) и отдаёт готовые std::function с
// сигнатурами, совместимыми 1-в-1 с tls_mitm::OcspFetcher,
// tls_mitm::CrlFetcher (include/tls_mitm/revocation.hpp проекта tls-mitm)
// и будущим tls_mitm::IntermediateCertFetcher (раздел 7 исходного ТЗ,
// часть 2 — добавляется в саму библиотеку tls-mitm отдельным этапом).
//
// ВАЖНО: смена транспорта с Unix domain socket на D-Bus НЕ меняет этот
// публичный интерфейс — сигнатуры fetch_ocsp/fetch_crl/
// fetch_intermediate_cert и *_fetcher() остались прежними. Код NGFW,
// однажды написанный против cert_helper::Client, не нужно менять при
// таких заменах транспорта — ради этого API и был вынесен в отдельный
// слой поверх client_impl::DbusClient.
//
// Пример подключения в NGFW (см. раздел 2.4 исходного ТЗ):
//
//   cert_helper::Client helper_client; // системная шина D-Bus по умолчанию
//
//   tls_mitm::RevocationFetchers fetchers;
//   fetchers.ocsp = helper_client.ocsp_fetcher();
//   fetchers.crl  = helper_client.crl_fetcher();
//   config.revocation_fetchers = fetchers;
//
//   // После доработки tls-mitm из раздела 7 ТЗ (часть 2):
//   // config.certificate_fetchers.intermediate_cert = helper_client.intermediate_cert_fetcher();
//
// Все три fetcher'а — блокирующие вызовы (синхронный sd_bus_call внутри
// DbusClient) и следуют контракту "пустой вектор = ошибка/таймаут", уже
// принятому в tls_mitm::OcspFetcher/CrlFetcher.

#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

#include "../../src/client_impl/dbus_client.hpp"
#include "protocol.hpp"

namespace cert_helper {

// Сигнатуры намеренно зеркалят tls_mitm::OcspFetcher / tls_mitm::CrlFetcher
// / (будущий) tls_mitm::IntermediateCertFetcher — так что результат
// ocsp_fetcher()/crl_fetcher()/intermediate_cert_fetcher() можно присвоить
// напрямую в соответствующее поле RevocationFetchers/CertificateFetchers
// без дополнительных адаптеров.
using OcspFetcherFn = std::function<std::vector<uint8_t>(
    const std::string& responder_url, const std::vector<uint8_t>& request_der,
    uint32_t timeout_ms)>;

using CrlFetcherFn = std::function<std::vector<uint8_t>(
    const std::string& distribution_point_url, uint32_t timeout_ms)>;

using IntermediateCertFetcherFn = std::function<std::vector<uint8_t>(
    const std::string& aia_url, uint32_t timeout_ms)>;

class Client {
public:
    // bus_address пустой (по умолчанию) => системная шина D-Bus, как и
    // положено для системного демона вроде cert-helper. Непустой адрес —
    // для тестов/нестандартных окружений (приватная шина).
    explicit Client(std::string bus_address = {}) : impl(std::move(bus_address)) {}

    std::vector<uint8_t> fetch_ocsp(const std::string& responder_url,
                                     const std::vector<uint8_t>& request_der,
                                     uint32_t timeout_ms) {
        auto resp = impl.fetch_ocsp(responder_url, request_der, timeout_ms);
        return unwrap(resp);
    }

    std::vector<uint8_t> fetch_crl(const std::string& distribution_point_url,
                                    uint32_t timeout_ms) {
        auto resp = impl.fetch_crl(distribution_point_url, timeout_ms);
        return unwrap(resp);
    }

    std::vector<uint8_t> fetch_intermediate_cert(const std::string& aia_url,
                                                  uint32_t timeout_ms) {
        auto resp = impl.fetch_intermediate_cert(aia_url, timeout_ms);
        return unwrap(resp);
    }

    // Диагностика — не входит в OcspFetcher/CrlFetcher контракт, но полезна
    // для мониторинга демона отдельно (D-Bus метод HealthCheck).
    // memory_cache_* — отражают in-memory слой поверх диска (пункт 2 из
    // анализа Squid, см. src/cache/two_tier_cache.hpp); ocsp/crl/
    // intermediate_cert — разбивка наблюдаемости по типу запроса
    // (пункт 5), см. cert_helper::protocol::RequestTypeStats.
    struct HealthStatus {
        bool reachable = false;
        bool healthy = false;
        uint64_t cache_entries = 0;
        uint64_t cache_size_bytes = 0;
        uint64_t memory_cache_entries = 0;
        uint64_t memory_cache_size_bytes = 0;
        protocol::RequestTypeStats ocsp;
        protocol::RequestTypeStats crl;
        protocol::RequestTypeStats intermediate_cert;
    };

    HealthStatus health_check(uint32_t timeout_ms = 1000) {
        HealthStatus status;
        auto result = impl.health_check(timeout_ms);
        status.reachable = result.reachable;
        status.healthy = result.health.healthy;
        status.cache_entries = result.health.cache_entries;
        status.cache_size_bytes = result.health.cache_size_bytes;
        status.memory_cache_entries = result.health.memory_cache_entries;
        status.memory_cache_size_bytes = result.health.memory_cache_size_bytes;
        status.ocsp = result.health.ocsp;
        status.crl = result.health.crl;
        status.intermediate_cert = result.health.intermediate_cert;
        return status;
    }

    // Готовые std::function для прямого присваивания в
    // tls_mitm::RevocationFetchers / будущую tls_mitm::CertificateFetchers.
    OcspFetcherFn ocsp_fetcher() {
        return [this](const std::string& url, const std::vector<uint8_t>& der, uint32_t timeout_ms) {
            return this->fetch_ocsp(url, der, timeout_ms);
        };
    }

    CrlFetcherFn crl_fetcher() {
        return [this](const std::string& url, uint32_t timeout_ms) {
            return this->fetch_crl(url, timeout_ms);
        };
    }

    IntermediateCertFetcherFn intermediate_cert_fetcher() {
        return [this](const std::string& url, uint32_t timeout_ms) {
            return this->fetch_intermediate_cert(url, timeout_ms);
        };
    }

private:
    // Контракт tls_mitm::OcspFetcher/CrlFetcher: "пустой вектор = таймаут/
    // ошибка" — соблюдается для ЛЮБОГО сбоя, будь то сбой самого IPC (шина
    // недоступна, вызов оборван по таймауту) или сбой сетевого запроса,
    // который сделал сам демон (FetchStatus != Ok). Вызывающая библиотека
    // не обязана различать эти случаи.
    static std::vector<uint8_t> unwrap(const protocol::FetchResponse& resp) {
        if (resp.status != protocol::FetchStatus::Ok) return {};
        return resp.payload_der;
    }

    client_impl::DbusClient impl;
};

} // namespace cert_helper
