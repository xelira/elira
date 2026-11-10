# Changelog

Формат основан на [Keep a Changelog](https://keepachangelog.com/ru/1.1.0/),
версии следуют [Semantic Versioning](https://semver.org/lang/ru/).

## [0.1.0] — не выпущена

### Added

- HTTP/1.1 и HTTP/2 на TCP-листенере; HTTP/3 поверх QUIC на отдельном
  UDP-листенере.
- TLS через rustls с ALPN `h2`, затем `http/1.1`; перечитывание сертификата и
  ключа по `SIGHUP`.
- Маршрутизация по Host без учёта регистра, порта и userinfo; для HTTP/2
  используется `:authority`; маршрут `host = "*"` ловит остальные запросы.
- Upstream'ы с балансировкой `round_robin` и `least_conn`, активными
  health-проверками (живым считается ответ `2xx`/`3xx`) и fail-open, когда все
  серверы помечены мёртвыми.
- Повторы для GET, HEAD и OPTIONS без тела при ошибке соединения или таймауте.
- Websockets и другие протоколы `Upgrade` через отдельное TCP-соединение к
  upstream'у.
- `CONNECT`-туннели: выключены по умолчанию, разрешены только для точных
  `host:port` из `connect.allow`, только по HTTP/1.1.
- Статика: index-файлы, MIME-типы, `ETag` и `If-None-Match`,
  `If-Modified-Since`, одиночные byte ranges, `HEAD`, SPA fallback и редирект
  каталога без завершающего `/`.
- Сжатие gzip/brotli для подходящих ответов и статики, с `Vary` и потоковой
  передачей тела; предсжатые `.br`/`.gz` рядом с файлом выигрывают.
- `sendfile(2)` для простых статических GET/HEAD по HTTP/1.1 без TLS.
- Ограничение частоты запросов на IP через token bucket и лимит тела по
  `Content-Length`.
- `trusted_proxies` для `X-Forwarded-For`; заголовки `Forwarded`,
  `X-Forwarded-*`, `X-Real-IP` и их underscore-алиасы от клиента отбрасываются.
- PROXY protocol версий 1 и 2 до TLS и HTTP.
- Access-лог в текстовом или JSON-формате с request id на каждый запрос; вывод
  в stdout или в файл с ротацией по размеру.
- Basic auth из htpasswd (bcrypt) и списки `ip_allow`/`ip_deny` на маршруте.
- Таймаут upstream'а, переопределяемый на маршруте через `timeout_secs`.
- Таймауты на тело запроса и ответа, простой websocket/CONNECT и опциональная
  буферизация небольших ответов upstream'а.
- Свой token bucket, предел тела и `error_pages` на маршруте.
- Кэш учитывает `Vary`, `Cache-Control`, `Authorization` и `Cookie`; не
  смешивает ответы разных пользователей и выставляет `Age`. Тела можно
  хранить на диске (`cache.dir`), а `stale_secs` включает
  stale-while-revalidate с фоновым обновлением.
- `dns_ttl_secs` ограничивает жизнь соединения в пуле, чтобы смена DNS
  подхватывалась за предсказуемое время.
- Микробенчмарки кэша и разбора конфига (`cargo bench`).
- mTLS на TCP- и QUIC-листенерах: `client_auth` и `client_ca`.
- SNI-сертификаты через `[[tls.certificates]]`, минимальная версия TLS.
- Свои `sni`, `health_path`, `tls_insecure`, `tls_ca` и `http2` у upstream'а;
  health-проба для TLS-бэкенда делает настоящее рукопожатие.
- Unix-сокеты как адреса upstream'ов (`unix:/run/app.sock`), включая
  upgrade и health-пробу, и дополнительный HTTP/1.1-листенер `listen_unix`.
- HTTP/2 до upstream'а по `[upstream_tls] http2 = true`.
- Prometheus-метрики на отдельном листенере: запросы по классам статусов,
  гистограмма задержки, число соединений в работе и состояние upstream'ов.
  Там же `GET /status` с JSON-снимком upstream'ов и их серверов, а также
  `POST /reload`, `POST /drain` и `POST /cache/purge`; `metrics.auth_file`
  закрывает весь листенер Basic auth.
- Шаблоны access-лога в стиле nginx и отправка в syslog.
- `SIGUSR2` ждёт готовности замены (файл готовности и systemd `READY=1`),
  поэтому неудачный рестарт оставляет старый процесс живым.
- Перезагрузка конфигурации по `SIGHUP`: маршруты, upstream'ы, сертификаты и
  формат лога применяются без разрыва HTTP/1.1 и HTTP/2 соединений.
- Ограничения на число и размер заголовков, число соединений, idle-таймаут,
  таймаут upstream'а и размер тела запроса.
- Удаление hop-by-hop заголовков, включая токены из `Connection`.
- Graceful shutdown по `SIGINT` и `SIGTERM` с ограниченным временем на
  завершение соединений.
- Команда `elira check` для разбора и валидации конфигурации без открытия
  сокетов и `elira migrate` для конвертации подмножества nginx-конфига.
- ACME проверен против Let's Encrypt staging и production на реальном домене
  и публичном порту 443; HTTP-01 проверен на staging через отдельный
  plain-листенер за nginx.
- PROXY protocol v2 на QUIC-датаграммах: заголовок снимается до quinn.
- HTTP/3-листенер переживает SIGHUP, если не менялись адрес, сертификат и
  клиентская аутентификация.
- Дисковый кэш переживает перезапуск; метаданные и тела загружаются обратно.
- sendfile обслуживает одиночные range, conditionals, auth/ACL и per-route
  заголовки; TLS, HTTP/2, сжатие и multi-range остаются в hyper.
- Маршруты по регулярному выражению пути (`path_regex`) после префиксных.
- FastCGI принимает DNS-имена в `fastcgi_pass`.
- Кэш делает условную revalidation (`ETag`/`Last-Modified` → `304`) и сжимает
  HIT-ответы.
- SNI-сертификаты и mTLS на QUIC-листенере.
- `include` с масками и рекурсивным слиянием, подстановка `${ENV}` в конфиге.
- Агрегированные `/metrics` и `/status` супервизором при `workers > 1`.
- `max_concurrent` для FastCGI/CGI/module-маршрутов и запрет загрузки
  world-writable модулей.
- Потоковые FastCGI/CGI: stdin/stdout с backpressure и лимитом ответа.
- OCSP stapling из DER-файла, перечитываемого по SIGHUP.
- Пул idle-соединений FastCGI с TTL и повторной попыткой на мёртвом сокете.
- ACME DNS-01 через внешний hook: wildcard-сертификаты, кэш аккаунта,
  обновление раз в 12 часов.
- `ocsp_hook` с периодическим обновлением OCSP-файла и reload.
- `module_sandbox`: изоляция `.so` в дочернем процессе через JSON-протокол.
- `POST /reload` и `/drain` на агрегированном админ-листенере воркеров.
- Per-route `cache_enabled` и `cache_ttl_secs`.
- Метрики TLS handshake и принятых QUIC-соединений.
- Имя upstream в текстовом/JSON access-логе и `$upstream`.
- Gauge активных запросов по пулам upstream.
- Счётчики stale-попаданий кэша и health-проверок.
- `limits.connection_drain_secs` и `limits.shutdown_timeout_secs`.
- Gauge `elira_tls_certificate_expires_seconds` для TCP/QUIC сертификатов.
- Per-route `access_log = false`.
- WASM-модули как цель маршрута (`wasm = "/path/echo.wasm"`) с fuel-бюджетом
  против бесконечных циклов.
- Собственный HTTP/2-пул upstream (`h2_pool`), h2c prior knowledge,
  connections/active/total/queued в `/status` и Prometheus-gauges.
- Собственный HTTP/3-пул upstream (`h3_pool`) на quinn/h3 с
  Prometheus-gauges.
- `scripts/cloudflare-dns.sh` для DNS-01 через Cloudflare API token.
- `fastcgi_param` и `cgi_param` на маршруте.
- `limits.max_upstream_response_bytes` и одноимённый per-route предел ответа
  проксируемого upstream.
- Глобальные `error_pages`/`error_root`: страницы для `401`, `403`, `404` без
  маршрута, `429` и ошибок upstream.
- Сэмплирование access-лога: `log.sample` и `access_log_sample` на маршруте.
- Per-route mTLS: `client_auth`, `client_cn`, `client_issuer_cn`; работает на
  HTTP/1.1, HTTP/2 и HTTP/3.
- `rate_key` на маршруте: лимит по заголовку, cookie или `Authorization`.
- OCSP stapling для SNI-сертификатов на TCP и QUIC; `ocsp_hook` обновляет все
  файлы.
- `cipher_suites`/`curves` для TCP и отдельно для HTTP/3.
- `GET /config` на админском листенере: эффективный конфиг в JSON.
- Тесты FastCGI/CGI на обрезанные заголовки, длину записи, padding и хвост
  после `END_REQUEST`.
- DNS-01 проверен на production CA Let's Encrypt через Cloudflare-зону
  (`elira-dns-prod.owaw.online`).
- `request_headers`/`request_remove_headers` на маршруте.
- Пассивная эвикция upstream: `failures_before_eject` и `eject_secs`.
- Балансировка `hash` (rendezvous) по IP/заголовку/cookie/URI.
- Multi-range для статики: `multipart/byteranges`, склейка и лимит 64.
- Дисковая буферизация ответов upstream (`response_spool_bytes`).
- TLS на `listen_unix` через общую секцию `[tls]`.
- Сквозной тест gRPC-трейлеров через собственный HTTP/2-пул.
- Per-route метрики кэша: `elira_route_cache_requests_total`.
- Веса upstream-серверов (`weights`) для round robin и least connections.
- Потоковый лимит тела запроса для chunked-загрузок.
- Настраиваемые health-пробы: метод, ожидаемые коды, Host.
- `If-Range` и сильные `ETag` для диапазонов.
- Лимиты количества и размера заголовков для HTTP/3.
- Тест клиентских gRPC-трейлеров через HTTP/2-пул.
- Глобальный бюджет spool-файлов с fallback на streaming.
- CRL для клиентских сертификатов на TCP и QUIC.
- `max_concurrent` для проксирующих маршрутов.
- Буферизация и spooling тела запроса; ретраи `PUT`/`DELETE` с телом.
- Single-flight заполнение кэша при одновременных промахах.
- Политика `retry_on`: ошибки, таймауты и 5xx.
- Права и владелец unix-сокета (`listen_unix_mode`, `listen_unix_owner`).
- Буферизация chunked-тел запроса с replay префикса при переполнении.
- Replay префикса для тел с `Content-Length` выше spool-лимита.
- Дополнительные TCP-листенеры с отдельным TLS.
- `user`, `worker_rlimit_nofile` и `pid_file`.
- L4 TCP/UDP stream-прокси с TLS-терминацией.
- Общий TLS 1.3 ticket key между воркерами.
- Переменные `$host`, `$remote_addr`, `$request_uri` и другие в заголовках и
  редиректах.
- Переменные в путях `error_pages`.
- `alias`, `expires_secs` и `etag = false` для статики.
- `return` с переменными в теле и `content_type`.
- `[[rewrites]]`: regex-замены пути с `last`/`break`/`redirect`/`permanent`.
- `[[maps]]`: именованные переменные из таблицы значений.
- `[[geos]]`, `[[splits]]` и route-level `if` с `return`.
- `match = "exact"` и `no_regex` (`location =` и `^~`).
- `[[routes.locations]]`: вложенные location с наследованием цели и пути.
- `Cache-Control: must-revalidate` запрещает stale-выдачу; `Expires`/`Date`
  задают TTL, если `max-age` нет. Запросы с `no-cache`/`no-store` обходят кэш.
- Заголовки `Forwarded` и `X-Forwarded-Port` к upstream.
- Задокументировано, что handoff установленных соединений между воркерами не
  выполняется: воркер дожидается активных запросов и завершается.
- `cache.shared`: read-through общего дискового кэша между воркерами,
  общий бюджет, advisory-lock и стабильное имя файла на key+Vary.
- `http3.idle_timeout_secs` и `http3.early_data` (0-RTT проверен QUIC-клиентом);
  настройки TLS resumption
  (`session_tickets`, `session_cache`).
- `POST /cache/purge?prefix=` и prefix-инвалидация кэша во всех воркерах.
- `dns_cleanup_hook` для удаления TXT после DNS-01 и OCSP hook в режиме
  воркеров.
- `elira migrate` переносит `try_files`, `add_header`, `allow`/`deny`,
  `auth_basic_user_file`, `client_max_body_size`, `gzip`, TLS и regex-location.
- FastCGI-бэкенды по TCP и unix-сокетам, CGI-скрипты и нативные
  динамические модули (`.so`).
- Режим `workers > 1` с супервизором, SO_REUSEPORT, перезапуском упавших
  воркеров и rolling restart по SIGUSR2.
- HTTP/2 prior knowledge (h2c) на plain TCP.
- Fuzz-цели для конфига, мигратора, заголовков и PROXY protocol; CI-джобы
  MSRV, `cargo-audit`, `cargo-deny`, musl и Docker; e2e-тесты mTLS и
  неудачного hot restart.
- Dockerfile, unit для systemd и release workflow для `x86_64` и `aarch64`.

### Changed

Нет. 0.1.0 — первый выпуск.

### Fixed

Нет. 0.1.0 — первый выпуск.

### Security

Исправленных уязвимостей нет. `CONNECT` выключен по умолчанию и ограничен явным
списком назначений; статика не выходит за пределы `root`; клиентские
forwarding-заголовки не передаются upstream'у. О проблемах безопасности
сообщайте по правилам из [SECURITY.md](SECURITY.md).
