# Elira

Elira — HTTP/1.1, HTTP/2 и HTTP/3 сервер и обратный прокси на Rust. Умеет
отдавать статику, проксировать запросы, терминировать TLS, кэшировать ответы
и работать в нескольких процессах.

Проект ранний: версия 0.1.0, API и конфиг ещё могут меняться. Но основные
вещи уже сделаны по-взрослому — не заглушками.

Произносится «э-ли-ра».

## Сборка и запуск

```sh
cargo build --release
./target/release/elira check --config elira.toml
./target/release/elira run --config elira.toml
```

Если бинарник ещё не собран, то же самое через cargo:

```sh
cargo run -p elira -- check --config elira.toml
cargo run -p elira -- run --config elira.toml
```

`check` читает и проверяет конфиг, но не открывает сокеты. Удобно для CI и
systemd-юнитов.

`migrate` конвертирует часть nginx-конфига в TOML и печатает то, что не
удалось перенести:

```sh
./target/release/elira migrate /etc/nginx/nginx.conf > elira.toml
```

Переносятся `proxy_pass`, `root`, `try_files`, `add_header`, `allow`/`deny`,
файлы basic auth, gzip, TLS и regex-локации. Это помощник, а не волшебная
кнопка: результат всё равно нужно прочитать глазами.

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

Статика описывается через `root`:

```toml
[[routes]]
host = "example.com"
root = "/srv/www"
index = ["index.html"]
try_files = ["$uri", "$uri.html"]
```

TLS включается отдельной секцией. HTTP/3 — своим UDP-листенером; сертификат
у него свой, даже если файлы те же самые:

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

В значениях подставляются переменные окружения вида `${HOME}`. Секции,
которых нет в файле, получают значения по умолчанию. Полный справочник —
в [docs/configuration.md](docs/configuration.md).

## Перезагрузка и сигналы

| Сигнал | Что происходит |
| --- | --- |
| `SIGHUP` | Перечитывает маршруты, upstream'ы, сертификаты, TLS, кэш, health-проверки и формат лога. HTTP/1.1 и HTTP/2 соединения не рвутся. |
| `SIGUSR1` | Переоткрывает файл access-лога. Для logrotate. |
| `SIGUSR2` | Запускает новый процесс, ждёт, пока тот займёт все порты, и только потом гасит старый. Нужен `reuse_port = true`. |
| `SIGINT`, `SIGTERM` | Graceful shutdown с ограниченным временем на активные соединения. |

Адреса листенеров и лимиты соединений по `SIGHUP` не меняются — для них нужен
рестарт. Сервер честно пишет об этом в лог, а не делает вид, что всё
применилось.

При `workers > 1` работает супервизор: воркеры делят порт через
`SO_REUSEPORT`, а `SIGUSR2` перезапускает их по одному. Systemd получает
`READY=1` и `MAINPID`, поэтому юнит можно держать в `Type=notify`.

## Что уже есть

### Протоколы и TLS

- HTTP/1.1, HTTP/2 по TLS и h2c с prior knowledge, HTTP/3 поверх QUIC.
- WebSocket и другие `Upgrade`-протоколы по HTTP/1.1, WebSocket over HTTP/2
  через RFC 8441 и WebSocket over HTTP/3.
- `CONNECT`-туннели по HTTP/1.1, HTTP/2 и HTTP/3. По умолчанию выключены,
  разрешены только точные `host:port` из allowlist.
- rustls по умолчанию, OpenSSL как опциональный бэкенд для старых TLS 1.0/1.1.
- SNI-сертификаты, отдельные RSA и ECDSA имена, минимальная версия TLS,
  политика cipher suites и кривых, отклонение неизвестного SNI.
- mTLS на TCP и QUIC: `optional` или `required`, проверка CN субъекта и
  издателя на маршруте, CRL.
- Общие TLS 1.3 ticket keys между воркерами, чтобы сессии переживали
  перезапуск процесса.
- ACME: TLS-ALPN-01, HTTP-01 и DNS-01 с внешним хуком или готовым помощником
  для Cloudflare. Wildcard-домены выдаются через DNS-01.

### Маршрутизация и статика

- Точные хосты, `*.example.com`, `host = "*"`, самый длинный префикс пути,
  `match = "exact"`, `no_regex` и `path_regex` с nginx-порядком.
- Вложенные `[[routes.locations]]`, именованные `@locations`, `internal`
  маршруты, `try_files`, SPA fallback и автоиндекс каталогов.
- `strip_prefix`, редиректы, фиксированные `return`, regex-`rewrites`,
  переменные `map`/`geo`/`split`, условные `if`-ответы.
- `add_headers`/`remove_headers` для ответов и
  `request_headers`/`request_remove_headers` для запросов к upstream'у.
- Basic auth по htpasswd с bcrypt, IPv4/IPv6 ACL, `auth_request`,
  `secure_link` с MD5 и `satisfy any`/`satisfy all`.
- `X-Accel-Redirect` и `X-Sendfile` в пределах разрешённых каталогов.
- `103 Early Hints` на обычном HTTP/1.1.
- Именованные страницы ошибок, включая подмену статуса вроде
  `"404 =200 /soft-404.html"`.
- Статика: index-файлы, MIME, `ETag`, `If-None-Match`,
  `If-Modified-Since`, одиночные и multipart byte ranges, `HEAD`,
  предсжатые `.br`/`.gz`, gzip/brotli на лету, `sendfile(2)` для простых
  HTTP/1.1 GET/HEAD.
- Защита от path traversal и выхода через symlink.

### Upstream'ы

- `round_robin`, `least_conn`, rendezvous hashing по IP, заголовку, cookie,
  `Authorization` или URI, случайный выбор.
- Веса серверов, флаги `backup` и `down`, `max_conns`, slow start после
  восстановления.
- Активные health-проверки с методом, ожидаемым статусом и `Host`;
  пассивное выкидывание после серии транспортных ошибок.
- Повторы идемпотентных запросов, в том числе с буферизованным телом
  `PUT`/`DELETE`, и настраиваемая политика `retry_on`.
- Отдельные таймауты на connect, отправку тела и получение заголовков ответа,
  с переопределением на маршруте.
- TCP и unix-сокеты в одном пуле, DNS-кэш с положительным и отрицательным TTL.
- TLS до upstream'а: свой CA, `insecure`, SNI, клиентские сертификаты, CRL.
- Привязка исходящего соединения к локальному адресу и PROXY protocol v1
  в сторону upstream'а.
- HTTP/2- и HTTP/3-пулы Elira, выбираемые на уровне upstream'а, со счётчиками
  соединений и стримов.
- Опциональный собственный HTTP/1.1 keep-alive пул (`h1_pool`).
- FastCGI (включая multiplexing), SCGI, uWSGI, AJP13 и CGI.
- Нативные `.so`-модули в процессе или в дочернем runner'е и песочница для
  WebAssembly-модулей.

### Кэш

- Ответы на `GET` с `X-Cache: HIT`, `MISS` или `STALE`.
- Учёт `Vary`, `Cache-Control`, `s-maxage`, `max-age` и `Age`.
- Запросы с `Authorization` или `Cookie` не читают и не пишут кэш.
- Single-flight: одновременные промахи ждут один поход в upstream.
- Тела на диске, переживающие рестарт, и stale-while-revalidate с одним
  фоновым обновлением через `If-None-Match`/`If-Modified-Since`.
- Именованные зоны кэша со своими бюджетами, каталогами и окнами stale.
- `purge` через админский API.

### Ограничения и безопасность

- Token bucket на IP, заголовок, cookie или `Authorization`.
- Лимиты на число соединений, заголовков, размер тела и скорость отдачи.
- Таймауты на тело запроса и ответа, простой WebSocket/CONNECT, ограничение
  размера ответа upstream'а.
- Вырезание hop-by-hop заголовков с учётом токенов из `Connection`.
- `Forwarded` и `X-Forwarded-*` очищаются от клиентских значений и
  дополняются только для адресов из `trusted_proxies`.
- PROXY protocol v1/v2 до TLS и HTTP, v2 на QUIC-датаграммах.
- Разделение привилегий: `user`/`group`, chroot, CPU affinity,
  `worker_rlimit_nofile`, PID-файл.

### Наблюдаемость и эксплуатация

- Access-лог в text или JSON, с request id, ротацией по размеру, шаблонами в
  стиле nginx и отправкой в syslog.
- `$upstream_addr`, `$upstream_status` и `$upstream_response_time` в логе.
- Prometheus-метрики, JSON `/status` и `/config` на отдельном админ-листенере.
- Метрики по маршрутам и upstream'ам: запросы, байты, задержки.
- `POST /reload`, `POST /drain`, `POST /cache/purge`, опциональный Basic auth.
- L4-проксирование TCP и UDP: round robin, least connections или хеш по IP
  клиента, idle timeout, опциональный TLS.
- Несколько TCP-листенеров с отдельными TLS-настройками и маршрутами.

## Админ-листенер

Включается секцией `[metrics]`:

| Запрос | Ответ |
| --- | --- |
| `GET /metrics` | Prometheus text |
| `GET /status` | состояние upstream'ов, серверов, health, запросов и кэша |
| `GET /config` | действующий конфиг в JSON |
| `POST /reload` | то же, что `SIGHUP` |
| `POST /drain` | graceful shutdown |
| `POST /cache/purge` | сброс кэша, можно с `?prefix=` |

TLS на этом листенере нет. Его место — loopback, либо закройте его
`auth_file`. Листенер не на loopback без `auth_file` не запустится.
`POST`-запросы требуют заголовок `x-elira-admin: 1`, иначе возвращается 403.

## Производительность

Замеры на стенде: Debian 13, Linux 6.12, 4 vCPU, 5 GiB RAM. nginx — в Docker,
`worker_processes auto`, `sendfile on`; нагрузка — `wrk` в Docker с host
networking. Elira собрана в release, `workers = 4`, `reuse_port = true`,
access-log sampling выключен.

| Сценарий | nginx | Elira |
| --- | ---: | ---: |
| Статика 549 Б, `wrk -t2 -c50` | 46.5k req/s | **51.7k req/s** |
| Статика 1 МиБ, `wrk -t2 -c20` | 3.0 ГБ/с | 2.84 ГБ/с |
| Прокси 549 Б, `wrk -t2 -c50` | 21.5k req/s | 15.0k req/s |

На маленькой статике Elira обгоняет nginx. На прокси пока отстаёт примерно в
1.4 раза: разница в основном в generic-пути hyper и сопутствующем учёте, а не
в переиспользовании соединений. Подробности и p50/p99 — в
[docs/benchmarks.md](docs/benchmarks.md).

## Тесты

```sh
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

End-to-end тесты поднимают настоящие сокеты и проверяют маршрутизацию,
подмену заголовков, диапазоны в статике, сжатие, приватность кэша и `Vary`,
stale-обновление, авторизацию и ACL, fallback'и sendfile, TLS и mTLS,
PROXY protocol, unix-листенеры и upstream'ы, неудачный hot restart и
access-логи.

Есть отдельные бенчмарки кэша и разбора конфига:

```sh
cargo bench -p elira-cache
cargo bench -p elira-config
```

## Чего пока нет

- `sendfile` работает только на plain HTTP/1.1. TLS, HTTP/2, сжатие и
  multipart ranges идут через hyper или отдельное тело.
- HTTP/3-листенер переживает `SIGHUP`, только если не менялись адрес,
  сертификат и настройки клиентской аутентификации. Новый файл сертификата
  перезапускает endpoint и сбрасывает живые QUIC-соединения.
- ACME TLS-ALPN-01 требует порт 443, HTTP-01 — листенер на 80 или отдельный
  `acme.http01_listen`.
- Нативные модули — это `.so` с полными правами процесса. Для недоверенного
  кода есть WebAssembly-модули.
- FastCGI и CGI буферизуют тело запроса; очень большие загрузки режутся
  лимитами.
- Изменение `workers` и адресов листенеров требует рестарта. `SIGHUP`
  перечитывает маршруты во всех воркерах, `SIGUSR2` перезапускает их по
  одному.
- DNS резолвится системным resolver'ом. `dns_ttl_secs` ограничивает, сколько
  живёт соединение в пуле после смены DNS.

## Структура репозитория

- `crates/elira` — бинарник, листенеры, runtime, sendfile, access-log, admin API.
- `crates/elira-config` — типы TOML, значения по умолчанию, валидация.
- `crates/elira-proxy` — маршрутизация, проксирование, статика, health.
- `crates/elira-tls` — PEM, SNI resolver, mTLS, ALPN, CRL/OCSP.
- `crates/elira-upstream` — HTTPS-коннектор и настройки доверия.
- `crates/elira-cache` — кэш ответов, тела на диске, stale-окно.
- `crates/elira-auth` — htpasswd и IP ACL.
- `crates/elira-limit` — token bucket.
- `crates/elira-accesslog` — форматирование, шаблоны, syslog, request id.
- `crates/elira-metrics` — счётчики, гистограммы, Prometheus.
- `crates/elira-h3` — QUIC-endpoint и мост в HTTP/3.
- `crates/elira-h2`, `crates/elira-h1upstream`, `crates/elira-h3upstream` —
  отдельные пулы для upstream'ов.
- `crates/elira-acme` — ACME-состояния и проверки доменов.
- `crates/elira-fastcgi`, `crates/elira-cgi`, `crates/elira-module`,
  `crates/elira-wasm` — прикладные бэкенды.
- `crates/elira-migrate` — конвертер nginx-конфига.

Устройство запроса и внутренних слоёв описано в
[docs/architecture.md](docs/architecture.md).

## Лицензия

MIT.
