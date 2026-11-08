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
- `cache.shared`: read-through общего дискового кэша между воркерами,
  общий бюджет и advisory-lock на мутации каталога.
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
