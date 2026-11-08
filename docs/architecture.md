# Архитектура Elira

Документ описывает текущий код: где живёт каждый шаг обработки запроса, какие
данные переживают `SIGHUP`, а какие захвачены при старте. Конфигурация
разбирается в `elira-config`, сетевой цикл и сборка `Runtime` — в
`crates/elira/src/server.rs`, решения о маршруте, содержимом ответа и
upstream'ах — в `elira-proxy`.

## Поток запроса

```
TCP accept
  -> семафор max_connections
  -> PROXY protocol v1/v2 (если proxy_protocol = true)
  -> ACME handshake (если задан [acme])        -> hyper
  -> TLS handshake + ALPN (если задан [tls])   -> h2 или http/1.1 -> hyper
  -> открытый HTTP: sendfile fast path (Linux) -> ответ и close,
     иначе hyper
  -> hyper service
       -> ArcSwap<Runtime> загружается на запрос
       -> Proxy::handle
            -> глобальный rate limit по IP peer'а
            -> Proxy::forward
                 -> CONNECT (до маршрутизации)
                 -> проверка Transfer-Encoding и глобального Content-Length
                 -> Host -> canonical_host
                 -> Router по host и path
                 -> per-route body limit, per-route rate limit, ACL, auth
                 -> cache lookup (GET)
                 -> Files / Redirect / Pool
                 -> error page, заголовки ответа, сжатие, тело
       -> метрики и access-лог
  -> graceful shutdown / idle watchdog

UDP (QUIC)
  -> HTTP/3 listener на [http3].listen
  -> тот же Proxy::handle
  -> access-лог через Runtime::write_log
  -> метрики запросов обновляются, соединений — нет
```

## Приём TCP-соединения

`server::bind_tcp` создаёт сокет через `socket2`: `SO_REUSEADDR` включён
всегда, `SO_REUSEPORT` — только при `reuse_port = true`, backlog 1024.
`socket2` нужен потому, что `TcpListener::bind` не даёт выставить
`SO_REUSEPORT` до `bind`.

`server::serve` держит `Semaphore` на `limits.max_connections`. Permit
захватывается через `try_acquire_owned`; при исчерпании лимита принятый сокет
закрывается без ответа, событие пишется в лог на уровне `debug`. Блокирующее
ожидание permit'а остановило бы цикл accept и реакцию на остановку, поэтому
его нет.

Ошибка `accept` (в том числе `EMFILE`/`ENFILE`) логируется как `warn`, цикл
ждёт 100 мс и продолжает работу — иначе ошибка возвращалась бы немедленно и
превращала цикл в log-flooding spin.

На каждое соединение создаётся задача в `JoinSet`. На остановке listener
закрывается, `serve` ждёт завершения задач до 10 секунд; соединение получает
`graceful_shutdown` и до 5 секунд на дозавершение. `main` ждёт задачу
`server::serve` до 15 секунд и пишет `warn`, если она не завершилась.

После запуска accept-циклов `main::notify_ready` пишет pid в файл из
`ELIRA_READY_FILE` и отправляет `READY=1`/`MAINPID` в `NOTIFY_SOCKET`
(systemd, включая abstract namespace с `@`). Файл готовности использует
`SIGUSR2`-рестарт. HTTP/3 bind выполняется в отдельной задаче и может
завершиться уже после записи файла; при занятом порту он повторяется.

## Unix-листенер

`listen_unix` поднимает отдельный `server::serve_unix`: `UnixListener`
принимает только открытый HTTP/1.1, TLS и PROXY protocol не применяются,
peer для логов и ACL — `127.0.0.1`. Каждое соединение проходит тот же
`serve_conn`, поэтому маршруты, кэш, auth и лимиты работают одинаково.
Семафор `max_connections` у листенера свой. Файл сокета при старте не
удаляется.

## PROXY protocol

`server::serve_stream` вызывает `proxy_protocol::read_peer` до TLS, до ACME и
до HTTP, если `proxy_protocol = true`. Заголовок читается через `peek` на
512 байт, поэтому при ошибке первые байты HTTP не теряются; после разбора
ровно `end` байт вычитываются через `read_exact`.

Поддержаны версии 1 (`PROXY TCP4/TCP6`) и 2 (бинарная сигнатура, команда
`PROXY`, family `TCP4`/`TCP6`). Заголовок обязателен: при отсутствии,
неполном заголовке или ошибке разбора `read_peer` возвращает `None`, и
соединение закрывается без ответа. Версия 2 с командой `LOCAL` и версия 1 с
`UNKNOWN` тоже дают `None`, несмотря на комментарий в `parse_v2`; исключения
для них нет.

Адрес из заголовка заменяет адрес сокета и дальше используется в access-логе,
rate limiter, ACL и `X-Forwarded-For`. Включать `proxy_protocol` можно только
на порту, доступном исключительно через балансировщик: иначе клиент подделает
адрес.

## TLS, ALPN, SNI и клиентские сертификаты

TLS-конфигурация лежит в `Runtime.tls` и загружается из `ArcSwap` при
установке каждого нового соединения (`serve_stream`). Поэтому `SIGHUP`
применяется к новым соединениям, уже установленные остаются на старом
сертификате.

`Runtime::build` вызывает `elira_tls::server_config_with_options`:

- ALPN предлагается в порядке `h2`, затем `http/1.1`. Клиент, приславший
  только неизвестный ALPN, получает ошибку handshake; клиент без ALPN
  обслуживается по HTTP/1.1.
- HTTP/2 включается только при согласованном `h2`
  (`stream.get_ref().1.alpn_protocol() == Some(b"h2")`). Cleartext h2c нет.
- `client_auth = "off"` не читает `client_ca` вовсе. `optional` и `required`
  строят `WebPkiClientVerifier`; `optional` добавляет
  `allow_unauthenticated`, то есть сертификат проверяется, если прислан, но
  его отсутствие не блокирует соединение.
- `min_version = "tls13"` собирает rustls с одним TLS 1.3; по умолчанию
  доступны TLS 1.2 и 1.3.
- `[tls.certificates]` добавляет сертификаты, выбираемые по SNI. Записи
  перебираются в порядке конфигурации; внутри записи точное имя проверяется
  раньше `*.example.com`. Wildcard совпадает ровно с одним уровнем и не
  совпадает с `example.com` или `a.b.example.com`, поэтому wildcard из более
  ранней записи может перекрыть точное имя из более поздней. Если
  `cert`/`key` заданы, клиент без SNI получает их; без пары handshake без
  SNI завершится ошибкой. Провайдер rustls выбирается явно (`aws_lc_rs`),
  потому что в процессе слинкованы два бэкенда (quinn тянет свой набор).

Handshake ограничен 10 секундами. Клиент, который не прислал ClientHello, не
держит permit и не блокирует accept. Ошибка или таймаут handshake пишутся в
лог на уровне `debug`, метрика не меняется.

При `[acme]` ветка TLS другая: `Acme::accept` из `elira-acme` завершает
handshake через `rustls-acme`, ALPN там `h2`, `http/1.1`, `acme-tls/1`.
TLS-ALPN-01 validation connection возвращается как
`io::ErrorKind::ConnectionAborted` и просто закрывается. На этом пути нет
10-секундного таймаута, нет mTLS (`with_no_client_auth`) и не применяется
`tls.min_version`; `rustls-acme` сам выбирает сертификат по SNI из
настроенных доменов. ACME и `[tls]` взаимоисключающие, это проверяет
`elira-config`.

HTTP/3 собирает конфигурацию через
`quic_server_config_with_client_auth`: ALPN только `h3`, всегда TLS 1.3,
один сертификат `[http3].cert`/`key` без списка SNI. Клиентские сертификаты
включаются полями `[http3].client_ca`/`client_auth`; `optional`/`required`
означают то же, что на TCP.

## HTTP/1.1 и HTTP/2

Оба протокола обслуживает hyper в `server::serve_conn`.

HTTP/1.1 (`http1::Builder`):

- `max_headers` из `limits.max_headers`;
- `max_buf_size` из `limits.max_header_bytes`;
- `header_read_timeout` 30 секунд;
- `with_upgrades()` — без него hyper не отдаёт сокет для `Upgrade`, и
  `OnUpgrade` завершается ошибкой `upgrade expected but low level API in
  use`.

HTTP/2 (`http2::Builder`):

- `max_header_list_size` из `limits.max_header_bytes`;
- keep-alive interval 30 секунд, timeout 20 секунд;
- `max_headers` не применяется: в h2 считаются не заголовки, а размер списка.

Idle watchdog одинаков для h1 и h2: `idle_watch` ждёт запроса
`limits.idle_timeout_secs`; ноль отключает таймер через
`std::future::pending`. Таймер сбрасывается в момент прихода запроса
(`idle.notify_one()` в service), а не после завершения ответа, поэтому
долгий ответ не считается простоем.

Тело запроса оборачивается `elira_proxy::timeout_body` с
`limits.request_body_timeout_secs`, если значение не ноль. Обёртка
`IdleBody` сбрасывает таймер на каждом кадре и возвращает ошибку
`TimedOut`, если данных нет дольше лимита. Тот же приём применяется к телу
ответа upstream'а с `limits.upstream_body_timeout_secs`.

При остановке вызывается `graceful_shutdown`, затем `drain` с лимитом
5 секунд. Счётчик `elira_connections_in_flight` увеличивается в
`serve_conn` и уменьшается после завершения соединения.

## HTTP/3

HTTP/3 живёт на отдельном UDP-листенере (`[http3]`) и использует quinn и h3.
`elira_h3::serve` собирает QUIC-конфигурацию через
`elira_tls::quic_server_config_with_client_auth`: ALPN `h3`, TLS 1.3 и
опциональные клиентские сертификаты. Сокет создаётся через `socket2` с
`SO_REUSEPORT` при `reuse_port = true`; при `AddrInUse` bind повторяется до
20 раз с интервалом 100 мс, потому что сокет освобождает driver-задача
quinn, а не `Drop` эндпоинта.

Peer берётся из `conn.remote_address()`. PROXY protocol на этом пути не
разбирается.

Тело запроса перекладывается из QUIC-потока в `StreamBody` через
`mpsc::channel` ёмкостью 4: канал делает body `Send + Sync`, чего требует
hyper-клиент на upstream-плече. Это потоковая передача, а не полная
буферизация. При `request_body_timeout_secs > 0` каждый `recv_data()`
ограничен таймаутом; истёкший таймаут отправляется в тело как ошибка
`TimedOut`.

После этого вызывается тот же `Proxy::handle` со схемой `"https"`. Из ответа
удаляются `Content-Length` и `Transfer-Encoding`: во фрейминге HTTP/3 длину
задаёт поток. Trailers пересылаются.

HTTP/3-путь получает `Arc<Metrics>` и обновляет:

- `elira_requests_total` и глобальную гистограмму;
- `elira_route_*` и `elira_upstream_*`, если ответ нёс `Labels`;
- `elira_cache_requests_total` по `X-Cache`;
- `elira_response_bytes_total`.

Не обновляются `elira_connections_in_flight` и
`elira_request_bytes_total`: h3 не вызывает соответствующие методы.
Access-лог идёт через замыкание, которое на каждую строку загружает текущий
`Runtime` и вызывает `Runtime::write_log`, поэтому `log.file`, шаблон и
syslog работают и здесь.

Отличия от TCP-пути:

- нет PROXY protocol;
- `CONNECT` и `Upgrade` не работают: `Proxy` реализует их через
  `hyper::upgrade::on`, а h3-соединение не даёт hyper upgrade-путь. Запрос
  дойдёт до `connect`/`forward_upgrade`, туннель не установится;
- `max_headers`/`max_header_bytes` из `[limits]` не применяются;
- один сертификат на слушатель, списка SNI-сертификатов нет;
- `Alt-Svc` на h3-ответах всё равно выставляется, потому что это делает тот
  же `Proxy::apply_route`.

## Runtime, SIGHUP и SIGUSR2

`Runtime` (`crates/elira/src/server.rs`) содержит:

- `Proxy` — маршруты, пулы, клиенты к upstream'ам, лимитеры, кэш, сжатие;
- `Option<Arc<rustls::ServerConfig>>` — TLS статического `[tls]`;
- `LogFormat`, необязательный `Format` (шаблон) и `Arc<Syslog>`;
- `Health`;
- `Option<Http3>`;
- `Option<Arc<AccessLog>>` — открытый файл access-лога.

`Runtime::build` читает сертификаты, собирает `Proxy`, открывает файл лога,
разбирает `log.template` и подключает syslog. Ошибка любого шага отменяет
reload: неизвестная переменная шаблона или недоступный syslog-сокет не
применяются.

Runtime лежит в `ArcSwap` и загружается на каждый запрос, поэтому `SIGHUP`
применяется к следующему запросу на уже открытом keep-alive соединении.
`sendfile` загружает runtime один раз перед hyper.

По `SIGHUP` (`main::reload`):

1. `Config::load` читает и валидирует файл. При ошибке в лог пишется
   `reload failed, keeping the old config`, старый runtime остаётся.
2. Сравниваются захваченные поля: `listen`, `metrics.listen`,
   `limits.max_connections`, `max_headers`, `max_header_bytes`. Расхождения
   дают `warn`; применяются они только после рестарта.
3. `Runtime::build` собирает TLS, `Proxy`, формат/шаблон/syslog лога и файл
   access-лога. Ошибка сборки отменяет весь reload.
4. Если `health.enabled`, все upstream'ы проверяются один раз до публикации,
   чтобы после reload не было интервала, в котором всё снова «здорово».
5. Новый runtime публикуется через `ArcSwap::store`.
6. HTTP/3-задача прерывается (`abort`), дожидается завершения и запускается
   заново уже с `http3` из нового runtime. Живые QUIC-соединения рвутся.

Что не переживает reload и меняется только рестартом, часто без
предупреждения: `listen`, `proxy_protocol`, `sendfile`, `reuse_port`,
`limits.idle_timeout_secs`, `limits.request_body_timeout_secs` (захвачен в
`Options`), наличие и адрес `[metrics]`, `metrics.auth_file`, `[acme]`.
`[acme]` создаётся один раз в `main::run` из стартового конфига и в
`Runtime` не входит; reload его не перечитывает и не перезапускает.

Пересборка `Proxy` означает новое состояние: пулы соединений к upstream'ам,
кэш, глобальный и per-route token bucket создаются заново. Старые keep-alive
соединения к бэкендам и накопленный кэш после reload не сохраняются.

`SIGUSR2` делает hot restart: `spawn_replacement` запускает тот же бинарник с
теми же аргументами и с `ELIRA_READY_FILE`, затем до 15 секунд ждёт файл
готовности. Если новый процесс завершился или не успел, старый остаётся
работать, а дочерний убивается. Если файл появился, старый отправляет stop и
уходит в обычный drain. Требуется `reuse_port = true`; без него сигнал
игнорируется с `warn`. Новый процесс биндит TCP, metrics и HTTP/3 через
`SO_REUSEPORT`. `SIGINT` и `SIGTERM` просто останавливают процесс.

## Маршрутизация

`Proxy::forward` берёт Host из заголовка `Host`, а при его отсутствии — из
`:authority` (HTTP/2). Пустой Host даёт `400`.

`canonical_host` (`crates/elira-proxy/src/lib.rs`):

- отклоняет `@` (userinfo) и некорректный порт (`example.com:abc`,
  незакрытый IPv6) — `400 malformed Host header`;
- убирает завершающую точку и приводит host к нижнему регистру;
- отдельно возвращает ключ маршрутизации без порта и значение для
  пересылки: с портом, если он был, и в скобках для IPv6.

Маршрут ищется по ключу без порта, в upstream уходит нормализованный Host с
портом. Это исключает расхождение, когда `admin:80@example.com`
маршрутизируется как `example.com`, а бэкенд видит исходную строку.

`Router` хранит три набора:

- `exact: HashMap<String, Vec<RouteEntry>>` — точный host;
- `wildcard: Vec<(suffix, Vec<RouteEntry>)>` — host вида `*.example.com`,
  хранится суффикс `.example.com`; совпадение по `ends_with`, поэтому
  `example.com` сам не совпадает, а `a.b.example.com` совпадает. Суффиксы
  отсортированы по длине, побеждает самый длинный;
- `default` — `host = "*"`.

Порядок поиска: точный host, затем первый подходящий wildcard, затем
default. Внутри каждого списка маршруты отсортированы по убыванию длины
`path`, выбирается первый подходящий. Если в точном host нет подходящего
`path`, поиск переходит к wildcard и default, а не завершается `404`.

`path_matches`: пустой `path` или `/` совпадает со всем; иначе путь должен
начинаться с префикса, а следующий байт быть `/` или концом строки.
`/api` совпадает с `/api` и `/api/users`, но не с `/apix`.

`strip_prefix` (только с upstream) срезает префикс; пустой остаток
превращается в `/`, остаток без ведущего `/` получает его. `redirect`
отвечает заданным статусом (`301`, `302`, `303`, `307`, `308`) с `Location`
и не трогает upstream. И `root`, и `redirect` проходят через
`apply_route`; upstream — через общий путь с кэшем, error pages и сжатием.

## Upstream

Каждый `[[upstreams]]` превращается в `Pool`:

- `servers: Vec<Authority>`;
- `health: Vec<AtomicBool>` — по флагу на сервер;
- `active: Vec<AtomicUsize>` — счётчик активных запросов;
- `next: AtomicUsize` — атомарный курсор;
- `balance`, `retries`, `scheme` (`http` или `https` по флагу `tls`);
- собственный `Client<HttpsConnector<HttpConnector>, Body>` и `TlsOptions`.

Отдельный клиент на пул нужен потому, что доверие и ALPN могут отличаться:
`insecure`, `ca`, `sni` и `http2` берутся из upstream'а, а при отсутствии
переопределения — из `[upstream_tls]`. `min_version` задаётся только
глобально и превращается в `tls13_only`.

Выбор сервера:

- `round_robin` идёт от `next` по кругу и возвращает первый сервер с
  `health = true`. Если живым не помечен ни один, возвращается
  `start % count` — fail-open, чтобы сломанный пробник не устроил аварию.
- `least_conn` перебирает живых и выбирает сервер с минимальным `active`;
  при равенстве побеждает тот, что встретился раньше от курсора. Если живых
  нет, также `start % count`.
- `ActiveGuard` увеличивает `active` при выборе и уменьшает в `Drop`.
  Для обычного запроса guard живёт до возврата заголовков ответа: потоковое
  тело в счётчике уже не учитывается. Для upgrade — до завершения
  handshake.

Соединение к upstream открывает `hyper-util` legacy `Client` с
`HttpsConnector<HttpConnector>`; `pool_idle_timeout` 30 секунд. HTTPS-
соединитель строится в `elira-upstream::https_connector`: системные корни,
дополнительный PEM из `[upstream_tls].ca` или `[[upstreams]].tls_ca`,
`insecure` с `NoCertificateVerification` (подпись handshake всё равно
проверяется), `http2` добавляет `h2` в ALPN, `min_version = "tls13"`
включает только TLS 1.3. SNI берётся из `sni`, если задан, иначе из
authority URI.

Отдельного connect-таймаута у клиента нет: блок `HttpConnector` с
`set_connect_timeout` в `Proxy::new` создаётся, но не используется — клиент
собирается из `https_connector`. Время установки соединения ограничено
общим таймаутом запроса (`route.timeout_secs` или
`limits.upstream_timeout_secs`), который оборачивает весь `client.request`.

Запрос к upstream идёт по схеме пула. Для каждого запроса собирается
`HeaderMap`:

- удаляются hop-by-hop заголовки: `connection`, `keep-alive`,
  `proxy-authenticate`, `proxy-authorization`, `proxy-connection`, `te`,
  `trailer`, `transfer-encoding`, `upgrade`. Исключение — `TE: trailers`:
  он сохраняется, потому что нужен gRPC;
- удаляются токены, перечисленные в `Connection`;
- удаляются клиентские forwarding-заголовки: `Forwarded`, `X-Real-IP`, все
  `X-Forwarded-*`, `X-Original-URL`, `X-Rewrite-URL`, `Front-End-Https`,
  `X-Url-Scheme`; underscore-алиасы нормализуются заменой `_` на `-`;
- выставляются `Host` (нормализованный), `X-Forwarded-For`,
  `X-Forwarded-Proto` (`http`/`https` соединения), `X-Forwarded-Host`,
  `Via: 1.1 elira`;
- `X-Request-Id` из запроса принимается, если он непустой и не длиннее 64
  байт; иначе генерируется новый;
- для `Upgrade` возвращаются `Connection: upgrade` и исходный `Upgrade`.

`X-Forwarded-For`: если peer входит в `limits.trusted_proxies`, к
существующему значению добавляется адрес peer'а; иначе заголовок начинается
заново с адреса peer'а. Клиентские `X-Forwarded-*` к этому моменту уже
удалены.

Повторы:

- `can_retry` требует `retries > 0`, отсутствия `Content-Length` и
  `Transfer-Encoding`, метода `GET`, `HEAD` или `OPTIONS`;
- число попыток — `retries + 1`, каждая заново выбирает сервер;
- тело отправляется только в первой попытке, повтор идёт с пустым телом;
- повтор бывает при ошибке соединения и таймауте, но не при ответе `5xx`;
- ошибка последней попытки — `502`, таймаут — `504`.

Таймаут запроса — `route.timeout_secs` или `limits.upstream_timeout_secs`;
он оборачивает `pool.client.request`, то есть ожидание заголовков ответа.
Тело ответа отдельно ограничено `limits.upstream_body_timeout_secs` через
`timeout_body`. `CONNECT` использует только глобальный таймаут, потому что
обрабатывается до маршрутизации.

Health-проверки (`Proxy::check_health`) выполняются циклом
`server::spawn_health_loop`:

- при `health.enabled` интервал `health.interval_secs`, иначе 30 секунд;
- путь берётся из `[[upstreams]].health_path`, иначе из `health.path`;
- каждый сервер получает HTTP/1.1 `GET path` с `Connection: close`;
- для `tls = true` проба делает настоящий TLS-handshake с теми же
  `TlsOptions`: доверие, `sni`, `tls13_only`; порт по умолчанию 443;
- ответ `2xx`/`3xx` — жив, всё остальное, ошибка и таймаут — мёртв;
- таймаут применяется отдельно к connect, TLS-handshake, записи и чтению;
- метрики `up`/`down` обновляются после каждого тика, включая тики с
  выключенными проверками.

Reload при включённых проверках делает один внеочередной проход до
публикации. Метрики после этого обновятся только на следующем тике.

`health_path` у `[[upstreams]]` не проходит такую же проверку формата, как
`health.path`: значение подставляется в строку `GET <path> HTTP/1.1` как
есть. Опечатка или управляющий символ здесь не отсекаются при загрузке
конфигурации.

## Статика

Маршрут с `root` обслуживает `elira_proxy::files::Files`. Поля `Files`
фиксируются при сборке `Proxy`: `root`, `index`, `spa`, `try_files`,
`autoindex`, `compression.enabled`, `compression.min_bytes`. Для error pages
создаётся отдельный `Files` с выключенными `spa`, `try_files`, `autoindex` и
сжатием.

Порядок обработки `Files::serve`:

1. Только `GET` и `HEAD`; остальные методы — `405` с `Allow: GET, HEAD`.
2. Путь percent-декодируется в UTF-8; ошибка декодирования — `400`.
3. Сегменты разбираются вручную: пустые и `.` пропускаются, `..` даёт
   `403`, NUL и обратный слэш — `400`. Это происходит до обращения к
   файловой системе.
4. `root` канонизируется; ошибка — `404`.
5. Если найден каталог и URL не заканчивается `/`, ответ `301` с
   `Location: <path>/`.
6. В каталоге перебираются `index`-файлы по порядку; первый существующий
   обычный файл становится кандидатом. Если индекс не найден и включён
   `autoindex`, генерируется листинг. Иначе путь считается несуществующим.
7. Если файла нет, перебираются `try_files`: в каждом шаблоне `$uri`
   заменяется относительным путём, ведущий `/` срезается, результат
   присоединяется к `root`; подходит только обычный файл.
8. Если ничего не найдено и `spa = true`, отдаётся первый `index`-файл из
   корня. Иначе `404`.
9. Найденный путь канонизируется и проверяется через
   `resolved.starts_with(&root)`. Симлинк, ведущий за пределы `root`, даёт
   `403`.

Листинг каталога сортируется по имени, экранирует HTML, добавляет `/` к
каталогам и ссылку `../`, кроме корня. У листинга `Cache-Control: no-store`.

`send`:

- MIME определяется по расширению (`content_type`), неизвестное —
  `application/octet-stream`;
- если клиент принимает `br` или `gzip` и рядом есть `<file>.<encoding>`,
  отдаётся предсжатый sibling. `Content-Type` при этом берётся по
  расширению исходного файла, а `Content-Length`, `ETag` и `Last-Modified` —
  по sibling'у;
- `ETag` — слабый, `W/"<len в hex>-<mtime в ms в hex>"`;
- `If-None-Match` проверяется первым: `*` или точное совпадение строки тега
  даёт `304` с `ETag` и `Last-Modified`. Иначе `If-Modified-Since`
  сравнивает mtime с секундной точностью (`modified <= since + 1s`);
- `Range` поддерживает один диапазон `bytes=start-end`, `start-` и `-suffix`.
  Несколько диапазонов (`a-b,c-d`) игнорируются, отдаётся весь файл с `200`.
  Некорректный диапазон — `416` с `Content-Range: bytes */<len>`;
- успешный диапазон — `206` с `Content-Range: bytes start-end/len`;
- выставляются `Content-Type`, `Accept-Ranges: bytes`,
  `X-Content-Type-Options: nosniff`; без сжатия ещё `Content-Length`,
  `ETag`, `Last-Modified`;
- сжатие на лету включается, если `compression.enabled`, статус `200`,
  метод не `HEAD`, длина не меньше `min_bytes`, нет предсжатого sibling и
  тип сжимаемый. Тогда выбирается `br` или `gzip`, выставляются
  `Content-Encoding` и `Vary: accept-encoding`, а `Content-Length` и `ETag`
  снимаются: длина сжатого потока неизвестна;
- `HEAD` и пустой файл отдают заголовки без тела;
- тело — `ReaderStream` по открытому файлу, для диапазона с `seek`.

Сжимаемые типы (`elira_proxy::compressible`): `text/*`, `application/json`,
`application/javascript`, `application/xml`, `application/rss+xml`,
`application/atom+xml`, `image/svg+xml`.

Ответ статики проходит через `Proxy::apply_route`, поэтому получает
`add_headers`/`remove_headers`, `X-Request-Id`, удаление `Server` при
`server_header = false` и `Alt-Svc`. Сам `Server: elira` в ответ статики не
добавляется: `apply_route` его только удаляет. Исключение — быстрый путь
`sendfile`, который пишет заголовки сам.

## Быстрый путь sendfile

`crates/elira/src/sendfile.rs` перехватывает первый запрос на открытом
HTTP/1.1-соединении до hyper. `server::serve_stream` вызывает `try_serve`
только при `sendfile = true`, `tls.is_none()` и отсутствии ACME. `sendfile`
не используется на TLS, HTTP/2 и HTTP/3, а также после первого запроса:
hyper уже владеет сокетом.

`try_serve` делает `peek` до 16 КиБ и разбирает запрос вручную. Он
отказывается от быстрого пути и оставляет байты hyper, если:

- платформа не Linux (проверка `cfg!(target_os = "linux")`);
- версия не `HTTP/1.1` или метод не `GET`/`HEAD`;
- в заголовках есть `Range`, `If-None-Match`, `If-Modified-Since` или
  `Upgrade`;
- нет `Host` или заголовок не помещается в 16 КиБ;
- `Proxy::static_file` вернул `None`: маршрут не статический, у маршрута
  есть `add_headers`/`remove_headers`, `auth_file`, ACL, per-route limiter,
  `error_pages`, выключен `server_header` или задан `Alt-Svc`;
- файл не существует или не является обычным файлом;
- тип файла сжимаемый и клиент принимает `br`/`gzip`;
- для принимаемого `br`/`gzip` существует предсжатый sibling;
- глобальный rate limiter не разрешает запрос (тогда его обработает
  `Proxy::handle` и вернёт `429`).

Если путь выбран, `try_serve` вычитывает ровно заголовок, пишет ответ сам:

```
HTTP/1.1 200 OK
content-type: <по расширению>
content-length: <len>
etag: W/"..."
last-modified: ...
connection: close
```

и отдаёт файл через `sendfile(2)` (дубликат fd, `AsyncFd`, куски до 1 МиБ).
`HEAD` получает заголовки без тела. После ответа соединение закрывается;
keep-alive на быстром пути нет. В ответе нет `Server`, `Accept-Ranges`,
`X-Content-Type-Options`, `X-Request-Id` и `Alt-Svc`; access-лог пишется
через `Runtime::write_log`, метрики — только глобальные
`elira_requests_total`, гистограмма и счётчик соединений. Per-route,
per-upstream и byte-метрики на этом пути не обновляются. Ошибка открытия
файла после отправки заголовков просто закрывает соединение.

На не-Linux `send_file` возвращает ошибку, но `try_serve` до неё не доходит:
проверка платформы стоит первой.

## Кэш

`elira-cache` — рабочий in-memory кэш. `Proxy` создаёт его при
`cache.enabled` и использует для GET-ответов upstream'ов; статика,
redirect'ы и ответы самого прокси не кэшируются.

Ключ — `canonical_host + path_and_query`: host без порта, путь с query.
Заголовки запроса в ключ не входят, но `Vary` учитывается отдельно.

Запрос не участвует в кэше вовсе, если содержит `Authorization` или
`Cookie`: такие данные не должны переходить между клиентами.

Ответ кэшируется, если одновременно:

- кэш включён;
- метод `GET`, запрос не `Upgrade`;
- статус upstream'а `200`;
- `Content-Length` известен и не больше `cache.max_item_bytes`;
- нет `Set-Cookie`;
- `Cache-Control` не содержит `no-store`, `private`, `no-cache` и успешно
  разбирается;
- `Vary` не равен `*`.

Тело такого ответа полностью буферизуется (`BodyExt::collect`) и кладётся
в кэш вместе со статусом и заголовками без hop-by-hop, `Content-Length`,
`Connection`-токенов и `Age`. Заголовки с не-UTF-8 значением в запись не
попадают. Ответы с chunked-телом или неизвестной длиной не кэшируются.

TTL записи:

- `Cache-Control: s-maxage`, иначе `max-age`, ограничивают
  `cache.ttl_secs` сверху;
- без них действует `cache.ttl_secs`;
- нулевой TTL означает «сразу протух» и не сохраняется.

`Vary` создаёт отдельный вариант под тем же ключом. Значения полей
сравниваются как объединённые значения заголовков запроса; отсутствующий
заголовок совпадает только с отсутствующим. `Vary: *` не кэшируется.

На HIT:

- ответ собирается из записи, получает `X-Cache: HIT` и `Age` в секундах;
- заголовки берутся из записи; `Server: elira` повторно не добавляется,
  поэтому в кэше может оказаться `Server` upstream'а или ничего, а при
  `server_header = false` `apply_route` удаляет его и с HIT-ответа;
- сжатие не применяется;
- ответ проходит `apply_route`;
- в расширения ответа кладётся `Labels`, поэтому HIT учитывается в
  per-route/per-upstream метриках.

На промахе ставится `X-Cache: MISS`, даже если ответ не попал в кэш
(например, из-за `Cache-Control` или неизвестной длины).

Вытеснение:

- при вставке сначала удаляются все протухшие варианты;
- затем удаляется самый старый вариант по `stored_at`, при равенстве — по
  номеру вставки;
- тело больше `cache.max_bytes` не принимается;
- бюджет считается только по телам, без заголовков;
- `max_bytes = 0` отключает кэш даже при `enabled = true`.

Кэш живёт в процессе. `POST /cache/purge` на admin-листенере очищает кэш
текущего runtime; `SIGHUP` создаёт новый `Proxy` и тем самым новый пустой
кэш. `/status` показывает `cache.bytes` и `cache.entries`, либо `null`.

## Аутентификация и ACL

Проверки выполняются после выбора маршрута и до кэша, upstream'а и статики.
Порядок:

1. Глобальный rate limiter — в `Proxy::handle`.
2. Глобальный `max_body_bytes` и `Transfer-Encoding` — до Host.
3. Per-route `max_body_bytes`.
4. Per-route rate limiter.
5. ACL (`IpAcl::allows`): `ip_deny` проверяется первым и всегда сильнее
   `ip_allow`. Пустой `ip_allow` разрешает всё, что не попало в deny.
   Отказ — `403`.
6. `auth_file`: HTTP Basic. Заголовок разбирается вручную, схема
   регистронезависима, пароль проверяется bcrypt по хэшу из htpasswd.
   Неудача — `401` с `WWW-Authenticate: Basic realm="elira"`.

htpasswd читается при сборке `Proxy`, то есть при старте и на каждом
`SIGHUP`; битый файл отменяет reload. Пустые строки и строки, начинающиеся
с `#`, пропускаются; строка без `:` или с пустым именем/хэшем — ошибка
загрузки. Дубликаты имён перекрываются последним.

ACL и auth работают и для статики, и для upstream'ов, и для redirect.
Исключение — `CONNECT`: он обрабатывается до маршрутизации и не проходит ни
ACL, ни auth, ни per-route timeout. Для `CONNECT` остаются глобальный rate
limiter, список `connect.allow` и семафор туннелей.

Admin-листенер использует тот же `BasicAuth`: если задан
`metrics.auth_file`, аутентификация требуется для всех путей, включая
`/metrics`. Файл читается один раз при старте; reload его не перечитывает.

## Rate limit и лимиты тела

Rate limiter — token bucket на IP peer'а (`elira-limit`):

- `limits.requests_per_second = 0` отключает глобальный лимитер;
- `burst` — ёмкость ведра; при `0` `Proxy::new` берёт
  `max(burst, requests_per_second)`, то есть ведро равно rate;
- новый клиент получает полное ведро;
- отказ не списывает токен;
- таблица ограничена 10 000 адресами; при переполнении сначала удаляются
  записи, неактивные дольше 60 секунд, а если таких нет — новый клиент
  получает отказ;
- время передаётся аргументом, поэтому алгоритм тестируется без sleep.

Per-route limiter (`requests_per_second`/`burst`) — отдельный bucket,
созданный для маршрута; он не заменяет глобальный, а проверяется после него.
Оба отказа дают `429` с `Retry-After: 1`. Глобальная проверка стоит первой,
поэтому исчерпанный глобальный bucket отвечает `429` даже на маршруте со
своим лимитом.

`limits.max_body_bytes` и `route.max_body_bytes` проверяют только
`Content-Length`: если он больше лимита — `413`. `0` выключает
соответствующий лимит. Chunked-тело этими лимитами не ограничивается;
для него действует только `request_body_timeout_secs` (таймаут простоя, не
размер).

`Transfer-Encoding` допускается только в виде одного `chunked`. `gzip,
chunked` и несколько значений дают `501` на запрос. На ответ upstream'а
действует то же правило: не-plain-chunked даёт `502`.

## FastCGI, CGI и модули

Маршрут с `fastcgi_pass`, `cgi_pass` или `module` не идёт в `Pool`. Тело
запроса буферизуется с тем же лимитом, что и обычный запрос, затем:

- FastCGI: параметры CGI собираются из метода, URI, Host, заголовков и peer'а,
  `SCRIPT_FILENAME` — из `fastcgi_root` и пути; ответ разбирается по протоколу
  FastCGI;
- CGI: скрипт запускается без shell, с очищенным окружением и таймаутом;
- модуль: JSON-запрос передаётся в `elira_handle` загруженной библиотеки,
  JSON-ответ становится HTTP-ответом.

Ответ проходит те же `error_pages`, route headers и метрики, что и
проксированный.

## Воркеры

При `workers > 1` бинарник становится супервизором: он запускает N дочерних
процессов с `ELIRA_WORKER=1`, каждый биндит те же порты с `SO_REUSEPORT`.
Родитель пересылает SIGHUP, перезапускает упавшие процессы и по SIGUSR2
делает rolling restart. Клиентские TCP-соединения не передаются между
процессами: worker получает SIGTERM, перестаёт принимать новые запросы и
дожидается активных до `connection_drain_secs`. Передача уже установленного
TLS/HTTP-соединения потребовала бы SCM_RIGHTS и переноса состояния hyper;
это не делается. `READY=1` в systemd отправляет родитель после
готовности всех воркеров.

## CONNECT и Upgrade

`CONNECT` обрабатывается в начале `Proxy::forward`, до Host и маршрута:

- при `connect.enabled = false` — `405`;
- target берётся из authority, а если hyper положил его в path — из path;
  без `host:port` — `400`;
- target должен строково совпасть с одним из `connect.allow`; иначе `403`;
- permit берётся из отдельного семафора `tunnels` с ёмкостью
  `limits.max_connections`; при исчерпании — `503`;
- TCP-соединение открывается с таймаутом `limits.upstream_timeout_secs`;
  ошибка — `502`;
- клиент получает `200`, затем задача ждёт `hyper::upgrade::on` и запускает
  `tunnel` с двусторонней копией.

`CONNECT` не проходит через пул, не использует TLS к цели (это и есть
открытый TCP-туннель), не учитывает `timeout_secs` маршрута и не пишет
отдельных метрик. Работает только по HTTP/1.1: в HTTP/2 и HTTP/3 hyper не
даёт upgrade-путь для такого туннеля.

`Upgrade` (websockets и другие протоколы) определяется по наличию `Upgrade`
и токена `upgrade` в `Connection`. Тело у такого запроса запрещено:
`Content-Length != "0"` или наличие `Transfer-Encoding` дают `400`.
Фактически это HTTP/1.1-механизм: в HTTP/2 и HTTP/3 нет ни такого
заголовка, специфичного для соединения, ни hyper upgrade-пути.

Туннель не идёт через пул соединений: `forward_upgrade` открывает отдельный
`TcpStream` к `host:port` upstream'а, вручную сериализует заголовки в
HTTP/1.1, пишет их, читает ответ до `\r\n\r\n` (лимит 64 КиБ), пропускает
`1xx` кроме `101`. На `101` заголовки `Connection: upgrade` и `Upgrade`
(значение upstream'а, если он его прислал) возвращаются клиенту, байты,
пришедшие сразу после заголовков, отправляются клиенту до `tunnel`. На
не-`101` ответ передаётся с пустым телом и `Server: elira`.

`Upgrade` всегда открывает открытый TCP, независимо от `tls = true` у
upstream'а: TLS к бэкенду на этом пути не устанавливается. Ответы upgrade
не проходят `apply_route`, поэтому не получают `add_headers`,
`remove_headers`, `X-Request-Id` и `Alt-Svc`; `Server: elira` в них
вставляется безусловно, даже при `server_header = false`.

`CONNECT` и `Upgrade` используют `limits.websocket_idle_secs`: `tunnel`
разбивает оба потока на направления и закрывает туннель, если в любом
направлении нет данных дольше лимита. Ноль отключает проверку. Оба вида
туннелей используют семафор `tunnels` и не увеличивают
`elira_connections_in_flight`: этот счётчик считает клиентские соединения,
а не туннели внутри них.

## Ответ

Проксированный ответ (`Proxy::forward`):

- hop-by-hop заголовки и токены `Connection` удаляются;
- `Content-Length` upstream'а не копируется: framing строит hyper;
- `Server` заменяется на `elira` (заголовок upstream'а не сохраняется);
- для `101` возвращаются `Connection: upgrade` и `Upgrade`;
- при сжатии выставляются `Content-Encoding` и `Vary: accept-encoding`;
- тело оборачивается `timeout_body` с `upstream_body_timeout_secs`.

Сжатие ответа upstream'а включается, если:

- `compression.enabled` и клиент прислал `Accept-Encoding`;
- статус `200`, метод не `HEAD`;
- нет `Content-Encoding`;
- тип сжимаемый;
- известная длина не меньше `min_bytes`; при неизвестной длине сжатие
  допускается.

Выбор кодировки — `br`, если `q(br) > 0` и `q(br) >= q(gzip)`, иначе
`gzip`, если `q(gzip) > 0`. `identity` и `*` не разбираются. Тело сжимается
потоково через `async-compression`, поэтому длина ответа не сохраняется.

Перед отправкой клиенту `apply_error_page` может заменить ответ, если для
его статуса настроен `error_pages`. Страница берётся из `error_root` или
`root` маршрута; это отдельный `Files`, который отдаёт файл по пути из
конфигурации. Fallback на `root` в коде есть, но статический маршрут
возвращается раньше `apply_error_page`, поэтому на практике для
проксирующего маршрута нужен `error_root`. Если файл отдался успешно, статус
исходного ответа сохраняется; если файл сам вернул ошибку, его статус
остаётся как есть.
Error pages применяются только к ответам, полученным от upstream, и только
после обычной ветки проксирования: ответы, которые `forward` вернул как
`Err` (`502`, `504`, `429` и т.п.), до `apply_error_page` не доходят, а
статический маршрут (`root`) возвращается раньше и свои `error_pages` не
использует. Подмена заменяет ответ целиком и теряет расширение `Labels`,
поэтому такой ответ не попадёт в per-route/per-upstream метрики.

`apply_route` для ответов, прошедших общий путь (upstream, статика,
redirect, кэш):

1. удаляет `remove_headers`;
2. вставляет `add_headers` (после удаления, поэтому add побеждает);
3. добавляет `X-Request-Id`, только если его ещё нет;
4. удаляет `Server`, если `server_header = false`; шаг идёт после
   `add_headers`, поэтому скрыть `Server` сильнее, чем добавить его
   маршрутом;
5. вставляет `Alt-Svc`, если задан `[http3]`.

`Alt-Svc` имеет вид `h3=":<port>"; ma=86400`, где порт берётся из
`http3.listen`. Заголовок появляется даже если h3-листенер не поднялся.

Ответы, сгенерированные самим прокси (`400`, `401`, `403`, `404` при
отсутствии маршрута, `405` для выключенного CONNECT, `413`, `429`, `501`,
`502`, `503`, `504`), возвращаются из `forward` как `Err` и не проходят
`apply_route`. В них нет `Server`, `X-Request-Id`, `Alt-Svc` и
route-заголовков; есть `Content-Type: text/plain` и
`Cache-Control: no-store`. Любые ответы `Files` (включая `301`, `400`,
`403`, `404`, `405`, `416`) и ответы redirect через `apply_route`
проходят. Ответы upgrade-ветки не проходят.

Request id:

- TCP access-лог всегда генерирует собственный 16-символьный hex id, а не
  берёт клиентский `X-Request-Id`;
- в upstream уходит клиентский `X-Request-Id` (1..64 байта), иначе
  сгенерированный;
- в ответе `apply_route` оставляет заголовок upstream'а, если тот его
  прислал, иначе вставляет значение, выбранное в `forward` (клиентское или
  сгенерированное);
- быстрый путь `sendfile` id только логирует, в ответ заголовок не пишет.

`Server: elira` вставляется только в проксированный ответ и в ответ
`forward_upgrade`. Статика, redirect и ответы из кэша его не добавляют: в
них остаётся только заголовок upstream'а, если он был скопирован, а при
`server_header = false` `apply_route` его удаляет. Маршрутные
`remove_headers` могут удалить `Server` независимо от флага, а
`add_headers` — добавить или переопределить его. На ответах ошибок и на
`sendfile` `Server` отсутствует.

Для метрик в ответ вставляется расширение `Labels` с меткой маршрута
(`host + path` из конфигурации) и именем upstream'а. Оно появляется на
обычном upstream-ответе и на HIT кэша; статика, redirect и ответы самого
прокси метку не получают, поэтому `elira_route_*` для них не растёт.

## Access-лог

`elira-accesslog::Entry` содержит peer, метод, версию, Host, path, статус,
число байт, длительность, User-Agent и request id. `line()` рендерит
common-log-подобную строку, `json()` — плоский JSON; оба экранируют
управляющие символы, кавычки и обратный слэш. Отсутствующий User-Agent в
тексте — `-`, в JSON — `null`.

Дополнительно `Format` разбирает nginx-подобный шаблон из `log.template`:
`$remote_addr`, `$remote_port`, `$host`, `$request`, `$request_method`,
`$request_uri`, `$server_protocol`, `$status`, `$body_bytes_sent`,
`$http_user_agent`, `$http_referer`, `$request_time`, `$request_id`,
`$time_iso8601`, `$time_local`. `$$` — литеральный доллар, неизвестная
переменная — ошибка сборки runtime. `$time_iso8601` и `$time_local` всегда
в UTC. Шаблон сильнее `log.format`.

`Runtime::write_log`:

1. рендерит строку шаблоном или `text`/`json`;
2. отправляет её в syslog, если задан `log.syslog` (датаграмма
   `<14>elira: <line>`);
3. пишет в `log.file`, если он задан, иначе в `tracing::info!(target:
   "access", ...)`; `tracing_subscriber::fmt()` в `main` пишет это в stdout.

`log.syslog` открывается при сборке runtime; недоступный сокет отменяет
старт/reload. Ошибка отправки отдельной строки игнорируется.

TCP-путь пишет запись после получения заголовков ответа. `bytes` берётся из
`response.body().size_hint().exact()`, иначе `0`; у потоковых и сжатых тел
точная длина обычно неизвестна, поэтому в логе будет `0`. `duration` — время
до готовности заголовков, а не до конца передачи тела; исключение —
`sendfile`, где запись пишется после передачи файла и `duration` включает
саму передачу. HTTP/3 считает так же и логирует через замыкание, которое
загружает текущий runtime, поэтому `log.file`, шаблон и syslog применяются и
к h3.

`AccessLog`:

- держит один append-only дескриптор под `Mutex`;
- пишет строку и считает байты;
- при превышении `log.max_bytes` (строго больше) переименовывает текущий файл
  в `<path>.1`, сдвигает `<path>.N` в `<path>.N+1`, открывает новый файл;
- хранит `log.keep` файлов, минимум один;
- не переоткрывает файл по внешнему сигналу сам: `SIGHUP` пересобирает
  `Runtime` и тем самым открывает новый дескриптор. Это же позволяет
  использовать внешний logrotate: переименовать файл и послать `SIGHUP`.

## Метрики, status и admin-листенер

`Metrics` хранит глобальные атомики и две таблицы меток:

- `elira_requests_total{class="1xx".."5xx","other"}`;
- `elira_request_duration_seconds` — гистограмма с границами от 1 мс до
  10 с и `+Inf`;
- `elira_connections_in_flight`;
- `elira_upstreams{state="up"|"down"}`;
- `elira_route_requests_total{route,class}` и
  `elira_route_duration_seconds_{sum,count}{route}`;
- `elira_upstream_requests_total{upstream,class}` и
  `elira_upstream_duration_seconds_{sum,count}{upstream}`;
- `elira_cache_requests_total{result="hit"|"miss"}`;
- `elira_request_bytes_total`, `elira_response_bytes_total`;
- `elira_reloads_total{result="ok"|"failed"}`.

Метки маршрутов и upstream'ов ограничены `MAX_LABELS = 200`: после
переполнения новые имена отбрасываются. `elira_reloads_total{result="ok"}`
увеличивается после успешной публикации runtime, а
`elira_reloads_total{result="failed"}` — только когда `Config::load` не смог
разобрать или провалидировать файл. Ошибка `Runtime::build` (например,
битый PEM, шаблон лога или syslog) reload отменяет, но счётчик `failed` при
этом не увеличивается. Байтовые счётчики зависят от `size_hint().exact()` и
часто получают `0` для потоковых тел.

`observe` вызывается на TCP-пути (включая `sendfile`) после получения
ответа; h3 вызывает `record_request`, route/upstream/cache/response-bytes,
но не `request_bytes`. Счётчик соединений увеличивается в `serve_conn` и
`sendfile`, уменьшается при завершении; h3 его не трогает. `render()` не
сбрасывает состояние и печатает фиксированный порядок серий.

Admin-листенер `[metrics]` создаётся в `main::run` через `server::bind_tcp`
(с тем же `reuse_port`) и `spawn_metrics`:

| Метод и путь | Ответ |
| --- | --- |
| `GET /metrics` | Prometheus text, `text/plain; version=0.0.4; charset=utf-8` |
| `GET /status` | JSON: upstream'ы, серверы, `healthy`, `active`, `balance`, `retries`, `cache` |
| `POST /reload` | `202 {"reload":"queued"}`; то же, что `SIGHUP` |
| `POST /drain` | `202 {"drain":"started"}`; graceful shutdown |
| `POST /cache/purge` | `200 {"purged":true\|false}` для текущего runtime |

Всё остальное — `404`. Если задан `metrics.auth_file`, любой путь требует
Basic-аутентификацию; ошибка — `401` с `WWW-Authenticate` и JSON-телом.
`/status` загружает текущий `Runtime` на каждый запрос, поэтому видит новый
набор пулов после `SIGHUP`. `/reload` отправляет новое значение в watch-
канал сигналов; `/drain` взводит общий stop; `/cache/purge` вызывает
`Proxy::purge_cache`.

У листенера нет TLS, семафора соединений, таймаутов из `[limits]` и
отдельного счётчика соединений; его задачи не дожидаются остановки. Порт и
`auth_file` фиксируются при старте: изменение `metrics.listen`, добавление
или удаление секции и смена `auth_file` требуют рестарта (reload пишет
`warn` только про адрес/наличие).

Health-цикл описан в разделе «Upstream». Он читает `Runtime` на каждом
тике, поэтому смена `health.*` и `health_path` применяется без перезапуска
задачи.

## Крейты

| Крейт | Ответственность |
| --- | --- |
| `elira` | Бинарник и библиотека: команды `run`/`check`/`migrate`, сигналы, `Runtime` в `ArcSwap`, TCP-листенер, HTTP/1.1 и HTTP/2, PROXY protocol, `sendfile`, файл/шаблон/syslog access-лога, admin-листенер, graceful shutdown, readiness |
| `elira-config` | Типы TOML с `deny_unknown_fields`, значения по умолчанию, валидация (включая SNI-имена, error pages, TLS-версии), ошибки загрузки; сокетов не открывает |
| `elira-proxy` | `Proxy`, `Router`, `Pool`, пересылка запросов, гигиена заголовков, retries, таймауты, per-route лимиты, `CONNECT` и `Upgrade`, кэш, error pages, сжатие, health-пробы, статика, JSON для `/status` |
| `elira-tls` | Чтение PEM, сборка rustls `ServerConfig`, ALPN `h2`/`http/1.1`, SNI-resolver, `h3` для QUIC, минимальная версия TLS, verifier клиентских сертификатов |
| `elira-upstream` | HTTPS-коннектор к upstream'ам: системные и дополнительные корни, `insecure`, SNI, опциональный `h2`, `tls13_only`, общий `client_config` для health-проб |
| `elira-auth` | HTTP Basic по htpasswd с bcrypt, `IpAcl` по CIDR; используется и admin-листенером |
| `elira-limit` | Token bucket на IP, ограничение таблицы и очистка по idle |
| `elira-cache` | In-memory кэш с бюджетом по байтам, TTL из `Cache-Control`, `Vary`, проверкой credentials и вытеснением |
| `elira-accesslog` | `Entry`, text/JSON, nginx-подобные шаблоны, экранирование, syslog, генерация request id |
| `elira-metrics` | Атомарные счётчики, гистограмма, метки route/upstream, cache/bytes/reload счётчики, рендер Prometheus |
| `elira-h3` | QUIC-эндпоинт, h3-сервер, мост тела запроса, метрики, mTLS, access-лог через runtime |
| `elira-acme` | TLS-ALPN-01 через `rustls-acme`, кэш сертификатов и аккаунта, фоновое продление |
| `elira-migrate` | Конвертация подмножества nginx-конфига в TOML с предупреждениями |

Ключевые внешние зависимости: hyper и hyper-util для HTTP/1.1, HTTP/2 и
клиента к upstream; rustls, tokio-rustls и hyper-rustls для TLS; quinn, h3 и
h3-quinn для HTTP/3; arc-swap для подмены runtime; async-compression для
gzip и brotli; socket2 для `SO_REUSEPORT`; ipnet для CIDR; httpdate для
дат статики.

## Известные ограничения

- HTTP/3 использует один сертификат `[http3].cert`/`key`; списка
  SNI-сертификатов, как в `[tls.certificates]`, у QUIC нет. `tls.min_version`
  к ACME и QUIC не применяется: QUIC всегда TLS 1.3, ACME собирает свою
  конфигурацию.
- SNI-сертификаты `[tls]` перебираются в порядке массива: wildcard из
  ранней записи может перекрыть точное имя из поздней. Если `cert`/`key` не
  заданы, клиент без SNI не получит сертификат, и handshake завершится
  ошибкой.
- ACME поддерживает только TLS-ALPN-01: порт 443 должен быть доступен
  извне. `Acme` создаётся один раз при старте, `SIGHUP` его не перечитывает
  и не перезапускает. На ACME-ветке нет 10-секундного таймаута handshake и
  нет mTLS. Против реального CA ACME не проверялся.
- `sendfile` работает только на Linux, только на открытом HTTP/1.1, только
  для первого запроса на соединении и только при отсутствии диапазонов,
  условий, `Upgrade`, сжатия, предсжатого sibling'а, route-заголовков, auth,
  ACL, per-route limiter, `error_pages`, скрытого `Server` и `Alt-Svc`.
  Ответ закрывает соединение, не содержит `Server`, `Accept-Ranges`,
  `X-Content-Type-Options`, `X-Request-Id`, `Alt-Svc` и не обновляет
  route/upstream/byte-метрики.
- Кэш — не полноценный HTTP-кэш: нет revalidation (`If-None-Match`,
  `If-Modified-Since`), нет `Range`, нет stale-while-revalidate, нет общего
  кэша между процессами; запросы с `Authorization`/`Cookie` обходят кэш
  целиком; HIT-ответ отдаётся без сжатия. Кэш очищается при reload и по
  `POST /cache/purge`. Ключ не учитывает порт Host: `example.com` и
  `example.com:8443` с одним путём попадут в один ключ, если оба дошли до
  upstream-ветки. Ответ, который буферизуется для кэша, читается через
  `BodyExt::collect` до обёртки `upstream_body_timeout_secs`, поэтому
  таймаут простоя тела к нему не применяется.
- Метрики per-route и per-upstream считают только проксированные ответы:
  статика и redirect не получают `Labels`. `sendfile` обновляет только
  глобальные счётчики и гистограмму. HTTP/3 не обновляет
  `elira_connections_in_flight` и `elira_request_bytes_total`.
  `elira_reloads_total{result="failed"}` не считает ошибки `Runtime::build`
  (битый PEM, шаблон или syslog): такие reload отменяются, но счётчик
  остаётся прежним. Байтовые счётчики часто равны нулю для потоковых тел.
- HTTP/3 не поддерживает PROXY protocol, `CONNECT` и `Upgrade`.
  `max_headers`/`max_header_bytes` к нему не применяются. Reload
  перезапускает слушатель и рвёт живые QUIC-соединения.
- Health-проверки активные, без пассивной проверки по ответам `5xx`;
  проверка — один HTTP/1.1 GET, путь общий или per-upstream. Если все
  серверы помечены мёртвыми, трафик всё равно идёт (fail-open).
- Повторы не покрывают ответы `5xx` и запросы с телом. Тело повторной
  попытки не переигрывается.
- `max_body_bytes` и `route.max_body_bytes` проверяют только
  `Content-Length`; chunked-тело не ограничено размером.
  `request_body_timeout_secs`/`upstream_body_timeout_secs` ограничивают
  простой, а не объём.
- `Upgrade` к upstream'у всегда открывает открытый TCP и игнорирует
  `tls = true`; TLS-бэкенд за websocket не поддерживается. Ответы upgrade не
  проходят `apply_route` и не получают route-заголовки, `X-Request-Id` и
  `Alt-Svc`.
- `CONNECT` обрабатывается до маршрутизации и не подчиняется route ACL,
  auth и `timeout_secs`; ограничение — только `connect.allow`, глобальный
  rate limiter и семафор туннелей. По HTTP/2 и HTTP/3 туннель не
  устанавливается.
- Статика поддерживает один диапазон; несколько диапазонов отдаются целиком
  с `200`, `If-Range` не реализован, `If-None-Match` сравнивает строки без
  weak-семантики.
- Error pages применяются только к ответам upstream'а: ответы самого прокси
  (`502`, `504`, `429` и т.п.) до них не доходят, а статический маршрут
  возвращается раньше и свои `error_pages` не использует. Для проксирующего
  маршрута без `error_root` список `error_pages` молча не используется;
  `root` в этой ветке недоступен, потому что маршрут не может иметь
  одновременно `upstream` и `root`.
- Ответы, сгенерированные самим прокси (включая `401`, `403`, `404`, `413`,
  `429`, `502`, `503`, `504`), не проходят `apply_route`: в них нет
  `Server`, `X-Request-Id`, `Alt-Svc`, `add_headers` и `remove_headers`.
- `Server: elira` добавляется только к обычному проксированному ответу и к
  ответу `forward_upgrade`. Статика, redirect и HIT-ответы кэша заголовок не
  добавляют.
- `bytes` в access-логе равен `0`, когда точная длина тела неизвестна
  (потоковые и сжатые ответы), а `duration` обычно измеряется до заголовков,
  а не до конца передачи тела. Исключение — `sendfile`: он логирует после
  передачи и включает её время в `duration`.
- `listen`, `proxy_protocol`, `sendfile`, `reuse_port`,
  `limits.idle_timeout_secs`, `limits.request_body_timeout_secs`,
  `metrics.listen`, `metrics.auth_file` и `[acme]` меняются только
  рестартом. Reload предупреждает лишь о части из них.
- Reload пересобирает пулы, кэш и rate limiter: keep-alive соединения к
  upstream'ам, кэшированные ответы и накопленные токены не сохраняются.
- `SIGUSR2` требует `reuse_port = true`; без него сигнал игнорируется.
  Новый процесс должен успеть создать файл готовности за 15 секунд, иначе
  старый процесс его убивает и продолжает работать. На не-Unix платформах
  reload и hot restart недоступны.
