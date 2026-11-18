> English version: [README.md](README.md)
> Changelog: [CHANGELOG.md](CHANGELOG.md)

# Elira

Elira — HTTP/1.1, HTTP/2 и HTTP/3 сервер и обратный прокси на Rust. Умеет
отдавать статику, проксировать запросы, терминировать TLS, кэшировать ответы,
зеркалировать трафик и работать в нескольких процессах.

Версия 0.1.0. Конфиг и API ещё могут меняться, но основные подсистемы уже
работают полностью, без заглушек.

Произносится «э-ли-ра».

## Сборка и запуск

```sh
cargo build --release
./target/release/elira check --config elira.toml
./target/release/elira run --config elira.toml
```

То же самое через cargo:

```sh
cargo run -p elira -- check --config elira.toml
cargo run -p elira -- run --config elira.toml
```

`check` читает и валидирует конфиг, но не открывает сокеты. Подходит для CI и
systemd-юнитов. `migrate` переносит часть nginx-конфига в TOML:

```sh
./target/release/elira migrate /etc/nginx/nginx.conf > elira.toml
```

Переносятся `proxy_pass`, `root`, `try_files`, `add_header`, `allow`/`deny`,
htpasswd, gzip, TLS и regex-локации. Результат всё равно нужно проверить
руками.

## Минимальный конфиг

```toml
listen = "0.0.0.0:8080"

[limits]
max_connections = 4096
idle_timeout_secs = 60
upstream_timeout_secs = 30

[log]
format = "text"

[[upstreams]]
name = "app"
servers = ["127.0.0.1:3000", "127.0.0.1:3001"]
balance = "least_conn"
health_path = "/ready"

[[routes]]
host = "*"
upstream = "app"
```

Статика:

```toml
[[routes]]
host = "example.com"
root = "/srv/www"
index = ["index.html"]
try_files = ["$uri", "$uri.html"]
```

TLS и HTTP/3:

```toml
[tls]
cert = "/etc/elira/cert.pem"
key = "/etc/elira/key.pem"

[http3]
listen = "0.0.0.0:443"
cert = "/etc/elira/cert.pem"
key = "/etc/elira/key.pem"
```

Конфиг можно разложить по файлам:

```toml
include = ["/etc/elira/conf.d/*.toml"]
```

В значениях подставляются переменные окружения вида `${HOME}`. Полный
справочник — в [docs/configuration.md](docs/configuration.md).

## Быстрый прокси

`fast_proxy = true` включает сырой HTTP/1.1 relay: запрос и ответ идут между
клиентом и upstream без hyper, через собственный пул соединений.

```toml
[[routes]]
host = "api.example.com"
upstream = "app"
fast_proxy = true
```

Что поддерживается:

- клиенты по plain HTTP/1.1 и после TLS-терминации;
- upstream по HTTP и HTTPS, включая SNI и клиентские сертификаты;
- `GET`/`HEAD` без тела и upgrade;
- gzip/brotli с буферизацией тел до 256 КиБ и потоковым сжатием крупных;
- `add_headers`/`remove_headers`, `proxy_hide_header`/`proxy_pass_header`;
- `request_headers`/`request_remove_headers`;
- `proxy_redirect`, `proxy_cookie_domain`, `proxy_cookie_path`;
- статические и named `error_pages` без переменных;
- `early_hints`;
- один повтор `GET`/`HEAD`, если уже открытое upstream-соединение оборвалось
  до получения ответа;
- пул с idle-TTL 60 секунд, проверкой закрытых соединений и метриками.

Если маршрут или запрос не подходят под эти условия, Elira автоматически
уходит в обычный путь. Сырой путь не применяет auth, ACL, `secure_link`, `if`,
кэш, rate/conn-лимиты, rewrite, `X-Sendfile`, `max_upstream_response_bytes`,
TLS/Unix/HTTP2/HTTP3-upstream, hash-балансировку и переменные в заголовках.
Флаг оставлен opt-in: он меняет retry-поведение и не пишет per-route
`Labels`-метрики так же, как обычный путь.

## Кэш с тегами

Кэш хранит теги из `Surrogate-Key` и `Cache-Tag`:

```text
Surrogate-Key: catalog product-42
Cache-Tag: catalog
```

Очистка по тегу:

```text
POST /cache/purge?tag=catalog
```

Поддерживаются memory- и disk-записи, shared-кэш и broadcast во все воркеры.
Формат disk-кэша — `ELIRA3`; файлы `ELIRA2` читаются со старыми записями без
тегов.

Также доступны:

- `X-Cache: HIT|MISS|STALE`;
- `Vary`, `Cache-Control`, `s-maxage`, `max-age`, `Age`, `must-revalidate`;
- `require_explicit = true` по умолчанию: без `Cache-Control`/`Expires`
  ответ не кэшируется;
- single-flight заполнение;
- stale-while-revalidate;
- именованные зоны со своими бюджетами, каталогами и окнами stale.

## Зеркалирование трафика

```toml
[[routes]]
host = "*"
upstream = "app"
mirror = "shadow"
mirror_percent = 100
```

`mirror` отправляет копию запроса в другой upstream, ответ игнорируется.
Зеркалируются `GET`/`HEAD` с пустым или уже буферизованным телом; решение о
доле запросов детерминировано по `request_id`. Подходит для теневого прогрева,
canary-проверок и сбора метрик с новой версии.

## Adaptive concurrency

```toml
[limits]
adaptive_concurrency = true
adaptive_target_ms = 50
adaptive_min = 8
adaptive_max = 256
```

AIMD-лимит на одновременные прокси-запросы. При задержке выше целевой предел
уменьшается, при стабильно низкой — растёт. При достижении предела новые
прокси-запросы получают `503`. Статика, кэш-хиты и локальные ответы не
ограничиваются. Лимит считается в каждом worker-процессе отдельно.

## TLS и kTLS

По умолчанию используется rustls. `backend = "openssl"` включает OpenSSL, в
том числе для TLS 1.0/1.1 и kernel TLS:

```toml
[tls]
backend = "openssl"
ktls = true
ktls_zerocopy = false
```

- `ktls = true` включает `SSL_OP_ENABLE_KTLS`.
- `ktls_zerocopy = true` дополнительно включает
  `SSL_OP_ENABLE_KTLS_TX_ZEROCOPY_SENDFILE`. Это быстрее, но при изменении
  файла во время отправки возможны повреждённые TLS-записи.
- Крупная статика по TLS отдаётся через `SSL_sendfile`, если kTLS активен.
- Если ядро не поддерживает `tls` ULP, Elira автоматически переходит на
  обычное асинхронное копирование без hyper.

Также поддерживаются SNI-сертификаты, RSA и ECDSA имена, mTLS, CRL, OCSP,
общие TLS 1.3 ticket keys и собственные cipher/curve-политики.

## HTTP/3 и 0-RTT

HTTP/3 работает на отдельном UDP-листенере. При `early_data = true`
разрешены только идемпотентные методы: `GET`, `HEAD`, `OPTIONS`, `TRACE`.
Неидемпотентные запросы до завершения QUIC-handshake получают
`425 Too Early`, чтобы исключить replay POST/PUT/DELETE.

## Динамические веса upstream

```text
POST /upstream/weight?upstream=app&index=0&weight=3
```

Меняет вес сервера без reload и перезапуска. В worker-режиме команда
транслируется всем воркерам. Неверный upstream или индекс возвращает
`{"updated":false}`.

## Перезагрузка и сигналы

| Сигнал | Что происходит |
| --- | --- |
| `SIGHUP` | Перечитывает маршруты, upstream'ы, сертификаты, TLS, кэш, health-проверки и формат лога. HTTP/1.1 и HTTP/2 соединения не рвутся. |
| `SIGUSR1` | Переоткрывает файл access-лога. |
| `SIGUSR2` | Запускает новый процесс, ждёт готовности и только потом гасит старый. Нужен `reuse_port = true`. |
| `SIGINT`, `SIGTERM` | Graceful shutdown с ограниченным временем на активные соединения. |

При `workers > 1` супервизор делит порт через `SO_REUSEPORT`, перезапускает
воркеры по одному и передаёт systemd `READY=1`/`MAINPID`. Если задан `user`,
супервизор сбрасывает root и сохраняет только `CAP_NET_BIND_SERVICE`.
Изменение числа воркеров и адресов листенеров требует рестарта.

## Возможности

### Протоколы

- HTTP/1.1, HTTP/2 по TLS и h2c prior knowledge, HTTP/3 поверх QUIC.
- WebSocket по HTTP/1.1, HTTP/2 (RFC 8441) и HTTP/3.
- `CONNECT` по HTTP/1.1, HTTP/2 и HTTP/3 с allowlist `host:port`.
- `103 Early Hints` на HTTP/1.1 и в `fast_proxy`.

### Маршрутизация и статика

- Точные хосты, `*.example.com`, `host = "*"`, самый длинный префикс,
  `match = "exact"`, `no_regex`, `path_regex`.
- Вложенные локации, именованные `@locations`, `internal`, `try_files`,
  SPA fallback, автоиндекс.
- `strip_prefix`, редиректы, `return`, regex-rewrites, `map`/`geo`/`split`,
  условные `if`-ответы.
- Заголовки запроса и ответа, Basic auth (bcrypt), IPv4/IPv6 ACL,
  `auth_request`, `secure_link`, `satisfy any/all`.
- `X-Accel-Redirect` и `X-Sendfile` в разрешённых каталогах.
- Именованные страницы ошибок, включая `"404 =200 /soft-404.html"`.
- Статика: index-файлы, MIME, ETag, `If-None-Match`, `If-Modified-Since`,
  byte ranges (включая multipart), HEAD, предсжатые `.br`/`.gz`, gzip/brotli,
  `sendfile(2)` на plain HTTP/1.1, `force_download`.
- Защита от path traversal, symlink-выходов и открытия спецфайлов.

### Upstream'ы

- `round_robin`, `least_conn`, rendezvous hashing, random.
- Веса, `backup`, `down`, `max_conns`, slow start.
- Активные health-проверки и пассивное выкидывание.
- Повторы идемпотентных запросов и настраиваемый `retry_on`.
- Отдельные таймауты connect/send/read.
- TCP и Unix-сокеты, DNS-кэш с положительным и отрицательным TTL, `resolver.pin`.
- TLS до upstream: CA, `insecure`, SNI, клиентские сертификаты, CRL.
- PROXY protocol v1 в сторону upstream.
- Собственные HTTP/2- и HTTP/3-пулы, метрики соединений и стримов.
- FastCGI (с multiplexing), SCGI, uWSGI, AJP13, CGI.
- Нативные `.so`-модули и песочница WebAssembly.

### Ограничения и безопасность

- Token bucket на IP, заголовок, cookie или `Authorization`.
- Лимиты соединений, заголовков, тела и скорости отдачи.
- Adaptive concurrency.
- Таймауты тела запроса/ответа, простоя WebSocket/CONNECT, размера ответа.
- Hop-by-hop заголовки удаляются с учётом `Connection`.
- `Forwarded` и `X-Forwarded-*` очищаются и дополняются только для
  `trusted_proxies`.
- PROXY protocol v1/v2 до TLS и HTTP, v2 на QUIC.
- `user`/`group`, chroot, CPU affinity, `worker_rlimit_nofile`, PID-файл.
- Include-циклы, права секретных файлов, `openat2` для статики.

### Наблюдаемость

- Access-лог в text/JSON, request id, ротация, шаблоны nginx, syslog.
- `$upstream_addr`, `$upstream_status`, `$upstream_response_time`.
- Prometheus-метрики, `/status`, `/config`, `/metrics`.
- Метрики маршрутов, upstream'ов, кэша, TLS, QUIC и пулов.
- Метрики `fast_proxy`: hit/fallback с причинами, idle/active/created/reused/errors.
- L4 TCP/UDP-прокси с балансировкой, idle timeout и TLS.
- Несколько TCP-листенеров с отдельными TLS и маршрутами.

## Админ-листенер

Включается секцией `[metrics]`:

| Запрос | Ответ |
| --- | --- |
| `GET /metrics` | Prometheus text |
| `GET /status` | JSON: upstream'ы, серверы, health, запросы, кэш |
| `GET /config` | действующий конфиг в JSON |
| `POST /reload` | то же, что `SIGHUP` |
| `POST /drain` | graceful shutdown |
| `POST /cache/purge` | сброс кэша: `?prefix=` или `?tag=` |
| `POST /upstream/weight` | вес сервера: `?upstream=NAME&index=N&weight=W` |

TLS на этом листенере нет. Его место — loopback либо `auth_file`. Листенер не
на loopback без `auth_file` не запустится. `POST` требует заголовок
`x-elira-admin: 1`, иначе 403.

## Производительность

Локальный стенд: 16 vCPU, Linux 6.12, nginx 1.30.4 как upstream и эталон,
`oha -z 5s -c 50`, `GET /index.html`.

| Сценарий | nginx | Elira обычная | Elira `fast_proxy` |
| --- | ---: | ---: | ---: |
| Статика 11 Б | 125k | **225k** | **225k** |
| Статика 1 МиБ | 16.0k | **30.2k** | **30.2k** |
| Прокси 11 Б | 57.8k | 54.0k | **80.8k** |
| Прокси 4 КиБ, gzip | 47.3k | 40.7k | **45.6k** |

- Малая статика требует `[limits] open_file_cache`.
- `fast_proxy` даёт около +40% к nginx на мелком прокси и +50% к обычному
  пути Elira.
- Сжатый прокси почти догоняет nginx, но остаётся в пределах нескольких
  процентов.
- TLS-статика упирается в шифрование; kTLS может изменить картину на хостах
  с ядерным `tls`.

Подробности, старые замеры и методика — в
[docs/benchmarks.md](docs/benchmarks.md).

## Тесты

```sh
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
cargo deny check
cargo audit
```

End-to-end тесты поднимают настоящие сокеты и проверяют маршрутизацию,
заголовки, ranges, сжатие, кэш и `Vary`, stale-обновление, auth/ACL, TLS и
mTLS, PROXY protocol, Unix-листенеры, upstream'ы, hot restart, access-логи,
`fast_proxy`, зеркалирование, error pages, 0-RTT и cache tags. Отдельно
проверяются контрабанда `Content-Length`/`Transfer-Encoding`, нормализация
неоднозначного framing и атомарность подмены `Runtime` под нагрузкой.

Бенчмарки кэша и конфига:

```sh
cargo bench -p elira-cache
cargo bench -p elira-config
```

Проверка регрессии производительности:

```sh
./scripts/bench-check.sh http://127.0.0.1:8080/ baseline.txt
```

## Ограничения

- `fast_proxy` не покрывает auth/ACL, кэш, `secure_link`, `if`, rewrite,
  rate/conn-лимиты, `X-Sendfile`, `max_upstream_response_bytes`, Unix/H2/H3
  upstream, hash-балансировку и переменные в заголовках — такие запросы идут
  обычным путём.
- `sendfile(2)` работает только на plain HTTP/1.1. TLS-клиенты используют
  отдельный быстрый путь, а kTLS — только при `backend = "openssl"` и
  поддержке `tls` в ядре.
- `ktls_zerocopy` может отправить повреждённые TLS-записи, если файл изменят
  во время отправки.
- `SIGHUP` сохраняет пулы upstream, кэш, token bucket и adaptive-лимитер,
  если proxy-конфигурация не менялась. Изменение маршрутов, upstream'ов,
  кэша или лимитов пересобирает `Proxy` и сбрасывает это состояние.
- HTTP/3 поддерживает SNI-сертификаты через `[[http3.certificates]]`.
  WebTransport и произвольный extended CONNECT отвечают `501`.
- HTTP/3-листенер переживает `SIGHUP`, только если не менялись адрес,
  сертификат и настройки клиентской аутентификации.
- ACME TLS-ALPN-01 требует порт 443, HTTP-01 — листенер на 80 или
  `acme.http01_listen`.
- Нативные модули имеют полные права процесса; для недоверенного кода
  используйте WebAssembly.
- FastCGI и CGI буферизуют тело запроса; большие загрузки режутся лимитами.
- DNS резолвится системным resolver'ом, без SRV. `resolver.pin` защищает от
  rebinding, но требует статических IP или доверенного DNS.
- `chrono` приходит транзитивно через `rustls-acme` и помечен unmaintained;
  это отслеживается `cargo audit` и политикой `cargo deny`.

## Структура репозитория

- `crates/elira` — бинарник, листенеры, runtime, sendfile, access-log, admin API.
- `crates/elira-config` — TOML-типы, значения по умолчанию, валидация.
- `crates/elira-proxy` — маршрутизация, проксирование, статика, health,
  `fast_proxy`, adaptive concurrency.
- `crates/elira-tls` — PEM, SNI, mTLS, ALPN, CRL/OCSP, kTLS.
- `crates/elira-pem` — собственный PEM-парсер.
- `crates/elira-upstream` — HTTPS-коннектор, resolver, доверие.
- `crates/elira-cache` — память, диск, теги, stale.
- `crates/elira-auth` — htpasswd и IP ACL.
- `crates/elira-limit` — token bucket.
- `crates/elira-accesslog` — форматирование, шаблоны, syslog, request id.
- `crates/elira-metrics` — счётчики, гистограммы, Prometheus.
- `crates/elira-h3` — QUIC-endpoint и HTTP/3.
- `crates/elira-h2`, `crates/elira-h1upstream`, `crates/elira-h3upstream` —
  пулы upstream-соединений.
- `crates/elira-acme` — ACME-состояния и проверки доменов.
- `crates/elira-fastcgi`, `crates/elira-cgi`, `crates/elira-module`,
  `crates/elira-wasm` — прикладные бэкенды.
- `crates/elira-migrate` — конвертер nginx-конфига.

Устройство запроса и слоёв — в [docs/architecture.md](docs/architecture.md).

## Лицензия

MIT.
