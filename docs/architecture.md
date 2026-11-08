# Архитектура Elira

Документ описывает, как устроен текущий код: где живёт каждый шаг обработки
запроса, какие данные переживают `SIGHUP`, а какие захвачены при старте.
Конфигурация разбирается в `elira-config`, сетевой цикл и сборка `Runtime` —
в `crates/elira/src/server.rs`, решения о маршруте, содержимом ответа и
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
            -> rate limit по IP peer'а
            -> Proxy::forward
                 -> CONNECT (до маршрутизации)
                 -> проверка Transfer-Encoding и Content-Length
                 -> Host -> canonical_host
                 -> Router по host и path
                 -> ACL, затем Basic auth
                 -> cache lookup (GET)
                 -> Files / Redirect / Pool
                 -> заголовки ответа, сжатие, тело
       -> метрики и access-лог
  -> graceful shutdown / idle watchdog

UDP (QUIC)
  -> HTTP/3 listener на [http3].listen
  -> тот же Proxy::handle
  -> access-лог через tracing::info (файл не используется)
  -> метрики TCP-листенера не обновляются
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
rate limiter, ACL, `X-Forwarded-For` и в `peer` для статики. Включать
`proxy_protocol` можно только на порту, доступном исключительно через
балансировщик: иначе клиент подделает адрес.

## TLS, ALPN и клиентские сертификаты

TLS-конфигурация лежит в `Runtime.tls` и загружается из `ArcSwap` при
установке каждого нового соединения (`serve_stream`). Поэтому `SIGHUP`
применяется к новым соединениям, уже установленные остаются на старом
сертификате.

`elira_tls::server_config_with_client_auth` собирает rustls `ServerConfig`:

- ALPN предлагается в порядке `h2`, затем `http/1.1`
  (`ALPN_PROTOCOLS` в `crates/elira-tls/src/lib.rs`). Клиент, приславший
  только неизвестный ALPN, получает ошибку handshake; клиент без ALPN
  обслуживается по HTTP/1.1.
- HTTP/2 включается только при согласованном `h2`
  (`stream.get_ref().1.alpn_protocol() == Some(b"h2")`). Cleartext h2c нет.
- `client_auth = "off"` не читает `client_ca` вовсе. `optional` и `required`
  строят `WebPkiClientVerifier`; `optional` добавляет
  `allow_unauthenticated`, то есть сертификат проверяется, если прислан, но
  его отсутствие не блокирует соединение.
- Провайдер rustls выбирается явно (`aws_lc_rs`), потому что в процессе
  слинкованы два бэкенда (quinn тянет свой набор).

Handshake ограничен 10 секундами. Клиент, который не прислал ClientHello, не
держит permit и не блокирует accept. Ошибка или таймаут handshake пишутся в
лог на уровне `debug`, метрика не меняется.

При `[acme]` ветка TLS другая: `Acme::accept` из `elira-acme` завершает
handshake через `rustls-acme`, ALPN там `h2`, `http/1.1`, `acme-tls/1`.
TLS-ALPN-01 validation connection возвращается как
`io::ErrorKind::ConnectionAborted` и просто закрывается. На этом пути нет
10-секундного таймаута и нет mTLS: `Acme` строит конфигурацию с
`with_no_client_auth()`. ACME и `[tls]` взаимоисключающие, это проверяет
`elira-config`.

Статический `[tls]` строит `NamedResolver` из `elira-tls`: точное имя или
`*.example.com` выбирает сертификат из `[[tls.certificates]]`, остальные
клиенты получают сертификат по умолчанию. Wildcard совпадает ровно с одним
уровнем. `client_ca` + `client_auth` включают проверку клиентских
сертификатов через `WebPkiClientVerifier`. `[acme]` использует resolver
`rustls-acme` для перечисленных доменов; mTLS на ACME-пути не включается.

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

При остановке вызывается `graceful_shutdown`, затем `drain` с лимитом
5 секунд. Счётчик `elira_connections_in_flight` увеличивается в
`serve_conn` и уменьшается после завершения соединения.

## HTTP/3

HTTP/3 живёт на отдельном UDP-листенере (`[http3]`) и использует quinn и h3.
`elira_h3::serve` собирает QUIC-конфигурацию через
`elira_tls::quic_server_config`: ALPN только `h3`. Сокет создаётся через
`socket2` с `SO_REUSEPORT` при `reuse_port = true`; при `AddrInUse` bind
повторяется до 20 раз с интервалом 100 мс, потому что сокет освобождает
driver-задача quinn, а не `Drop` эндпоинта.

Peer берётся из `conn.remote_address()`. PROXY protocol на этом пути не
разбирается. `[http3].client_auth` включает mTLS тем же verifier'ом, что и
TCP; `certificates` (SNI) действует только на TCP. Тело запроса
ограничено `limits.request_body_timeout_secs`, ответы учитываются в
`Metrics` так же, как на TCP.

Тело запроса перекладывается из QUIC-потока в `StreamBody` через
`mpsc::channel` ёмкостью 4: канал делает body `Send + Sync`, чего требует
hyper-клиент на upstream-плече. Это потоковая передача, а не полная
буферизация, вопреки doc-комментарию в начале `elira-h3`.

После этого вызывается тот же `Proxy::handle` со схемой `"https"`. Из ответа
удаляются `Content-Length` и `Transfer-Encoding`: во фрейминге HTTP/3 длину
задаёт поток. Trailers пересылаются.

Отличия от TCP-пути:

- access-лог идёт через замыкание, которое читает текущий `Runtime`, поэтому
  `log.file`, шаблон и syslog работают и здесь;
- `Metrics` передаётся в h3: общие счётчики, маршруты, upstream'ы, кэш и
  размер тела ответа обновляются;
- `CONNECT` и `Upgrade` не работают: `Proxy` реализует их через
  `hyper::upgrade::on`, а h3-соединение не даёт hyper upgrade-путь.
  Формально запрос дойдёт до `connect`/`forward_upgrade`, туннель не
  установится;
- `max_headers`/`max_header_bytes` из `[limits]` не применяются;
- `Alt-Svc` на h3-ответах всё равно выставляется, потому что это делает тот
  же `Proxy::apply_route`.

## Runtime, SIGHUP и SIGUSR2

`Runtime` (`crates/elira/src/server.rs`) содержит:

- `Proxy` — маршруты, пулы, клиент к upstream'ам, лимитер, кэш, сжатие;
- `Option<Arc<rustls::ServerConfig>>` — TLS статического `[tls]`;
- `LogFormat`;
- `Health`;
- `Option<Http3>`;
- `Option<Arc<AccessLog>>` — открытый файл access-лога.

`Runtime::build` читает сертификаты, собирает `Proxy` и открывает файл лога.
Если открыть файл не удалось, reload не применяется.

Runtime лежит в `ArcSwap` и загружается на каждый запрос, поэтому `SIGHUP`
применяется к следующему запросу на уже открытом keep-alive соединении.
`sendfile` загружает runtime один раз перед hyper.

По `SIGHUP` (`main::reload`):

1. `Config::load` читает и валидирует файл. При ошибке в лог пишется
   `reload failed, keeping the old config`, старый runtime остаётся.
2. Сравниваются захваченные поля: `listen`, `metrics.listen`,
   `limits.max_connections`, `max_headers`, `max_header_bytes`. Расхождения
   дают `warn`; применяются они только после рестарта.
3. `Runtime::build` собирает TLS, `Proxy`, формат лога и файл access-лога.
   Ошибка сборки (например, битый PEM) отменяет весь reload.
4. Если `health.enabled`, все upstream'ы проверяются один раз до публикации,
   чтобы после reload не было интервала, в котором всё снова «здорово».
5. Новый runtime публикуется через `ArcSwap::store`.
6. HTTP/3-задача прерывается (`abort`), дожидается завершения и запускается
   заново уже с `http3` из нового runtime. Живые QUIC-соединения рвутся.

Что не переживает reload и меняется только рестартом, часто без
предупреждения: `listen`, `proxy_protocol`, `sendfile`, `reuse_port`,
`limits.idle_timeout_secs`, наличие и адрес `[metrics]`, `[acme]`.
`[acme]` создаётся один раз в `main::run` из стартового конфига и в
`Runtime` не входит; reload его не перечитывает и не перезапускает.

Пересборка `Proxy` означает новое состояние: пулы соединений к upstream'ам,
кэш и token bucket лимитера создаются заново. Старые keep-alive соединения к
бэкендам и накопленный кэш после reload не сохраняются.

`SIGUSR2` делает hot restart: `spawn_replacement` запускает тот же бинарник с
теми же аргументами, текущий процесс ждёт 750 мс, отправляет stop и уходит в
обычный drain. Требуется `reuse_port = true`; без него сигнал игнорируется с
`warn`. Новый процесс биндит TCP, metrics и HTTP/3 через `SO_REUSEPORT`.
`SIGINT` и `SIGTERM` просто останавливают процесс.

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
портом. Это исключает расхождение, когда `admin:80@example.com` маршрутизируется
как `example.com`, а бэкенд видит исходную строку.

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
`apply_route`; upstream — через общий путь с кэшем и сжатием.

## Upstream

Каждый `[[upstreams]]` превращается в `Pool`:

- `servers: Vec<Authority>`;
- `health: Vec<AtomicBool>` — по флагу на сервер;
- `active: Vec<AtomicUsize>` — счётчик активных запросов;
- `next: AtomicUsize` — атомарный курсор;
- `balance`, `retries`, `scheme` (`http` или `https` по флагу `tls`).

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
`HttpsConnector<HttpConnector>`:

- `HttpConnector`: connect timeout 5 секунд, `nodelay`, `enforce_http(true)`;
- `pool_idle_timeout` 30 секунд;
- HTTPS-соединитель строится в `elira-upstream::https_connector`: системные
  корни, дополнительный PEM из `[upstream_tls].ca`, `insecure` с
  `NoCertificateVerification` (подпись handshake всё равно проверяется),
  `http2` добавляет `h2` в ALPN. SNI берётся из authority URI; отдельного
  `sni` в конфиге нет, хотя поле есть в `TlsOptions`.

Запрос к upstream идёт по схеме пула. Для каждого запроса собирается
`HeaderMap`:

- удаляются hop-by-hop заголовки: `connection`, `keep-alive`,
  `proxy-authenticate`, `proxy-authorization`, `proxy-connection`, `te`,
  `trailer`, `transfer-encoding`, `upgrade`;
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
он оборачивает `client.request`, то есть ожидание заголовков ответа.
`CONNECT` использует только глобальный таймаут, потому что обрабатывается до
маршрутизации.

Health-проверки (`Proxy::check_health`) выполняются циклом
`server::spawn_health_loop`:

- при `health.enabled` интервал `health.interval_secs`, иначе 30 секунд;
- каждый сервер получает обычный HTTP/1.1 `GET path` с `Connection: close`;
- ответ `2xx`/`3xx` — жив, всё остальное, ошибка и таймаут — мёртв;
- таймаут применяется отдельно к connect, записи и чтению;
- пулы с `scheme == "https"` пропускаются целиком и остаются помеченными
  живыми: пробник говорит по открытому HTTP;
- метрики `up`/`down` обновляются после каждого тика, включая тики с
  выключенными проверками.

Reload при включённых проверках делает один внеочередной проход до
публикации. Метрики после этого обновятся только на следующем тике.

## Статика

Маршрут с `root` обслуживает `elira_proxy::files::Files`. Поля `Files`
фиксируются при сборке `Proxy`: `root`, `index`, `spa`, `try_files`,
`autoindex`, `compression.enabled`, `compression.min_bytes`.

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
  есть `add_headers`/`remove_headers`, `auth_file`, ACL, выключен
  `server_header` или задан `Alt-Svc`;
- файл не существует или не является обычным файлом;
- тип файла сжимаемый и клиент принимает `br`/`gzip`;
- для принимаемого `br`/`gzip` существует предсжатый sibling;
- rate limiter не разрешает запрос (тогда его обработает `Proxy::handle` и
  вернёт `429`).

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
`X-Content-Type-Options`, `X-Request-Id` и `Alt-Svc`; access-лог и метрики
пишутся вручную. Ошибка открытия файла после отправки заголовков просто
закрывает соединение.

На не-Linux `send_file` возвращает ошибку, но `try_serve` до неё не доходит:
проверка платформы стоит первой.

## Кэш

`elira-cache` — рабочий in-memory кэш, а не заготовка. `Proxy` создаёт его
при `cache.enabled` и использует для GET-ответов upstream'ов; статика,
redirect'ы и ответы самого прокси не кэшируются.

Ключ — `canonical_host + path_and_query`: host без порта, путь с query.
Заголовки запроса в ключ не входят.

Ответ кэшируется, если одновременно:

- кэш включён;
- метод `GET`, запрос не `Upgrade`;
- статус upstream'а `200`;
- `Content-Length` известен и не больше `cache.max_item_bytes`;
- нет `Set-Cookie`;
- `Cache-Control` не содержит `no-store` и `private`.

Тело такого ответа полностью буферизуется (`BodyExt::collect`) и кладётся
в кэш вместе со статусом и заголовками без hop-by-hop и `Content-Length`.
Ответы с chunked-телом или неизвестной длиной не кэшируются.

На HIT ответ собирается из записи, получает `X-Cache: HIT`, проходит
`apply_route` и отдаётся без сжатия. На промахе — `X-Cache: MISS` и обычный
путь. Заголовки на HIT берутся из записи, а `Server: elira` повторно не
добавляется: в кэш попадает `Server` upstream'а, если тот его прислал, или
ничего. При `server_header = false` `apply_route` удаляет `Server` и с
HIT-ответа.

Ограничения кэша:

- бюджет считается только по телам, без заголовков;
- запись живёт `cache.ttl_secs` от вставки, продления нет;
- при вставке сначала удаляются протухшие записи, затем самые старые по
  времени вставки (при равном времени — по номеру вставки);
- тело больше `cache.max_bytes` не принимается вовсе;
- `max_bytes = 0` отключает кэш даже при `enabled = true`;
- `Vary` учитывается: под одним ключом хранится по записи на каждую
  комбинацию значений, `Vary: *` не кэшируется;
- запросы с `Authorization` или `Cookie` не читают и не пишут кэш, ответы с
  `Set-Cookie`, `no-store`, `private` или `no-cache` не сохраняются;
- `s-maxage`/`max-age` сокращают TTL, но не удлиняют его; на HIT
  выставляется `Age`;
- нет revalidation, инвалидации, `Range` и условных запросов;
- кэш живёт в процессе и создаётся заново при `SIGHUP`, поэтому reload его
  очищает.

## Аутентификация и ACL

Проверки выполняются после выбора маршрута и до кэша, upstream'а и статики.
Порядок жёсткий:

1. ACL (`IpAcl::allows`): `ip_deny` проверяется первым и всегда сильнее
   `ip_allow`. Пустой `ip_allow` разрешает всё, что не попало в deny.
   Отказ — `403`.
2. `auth_file`: HTTP Basic. Заголовок разбирается вручную, схема
   регистронезависима, пароль проверяется bcrypt по хэшу из htpasswd.
   Неудача — `401` с `WWW-Authenticate: Basic realm="elira"`.

htpasswd читается при сборке `Proxy`, то есть при старте и на каждом
`SIGHUP`; битый файл отменяет reload. Пустые строки и строки, начинающиеся
с `#`, пропускаются; строка без `:` или с пустым именем/хэшем — ошибка
загрузки. Дубликаты имён перекрываются последним.

ACL и auth работают и для статики, и для upstream'ов, и для redirect.
Исключение — `CONNECT`: он обрабатывается до маршрутизации и не проходит ни
ACL, ни auth, ни per-route timeout. Для `CONNECT` остаётся только общий rate
limiter.

## Rate limit и лимит тела

Rate limiter — token bucket на IP peer'а (`elira-limit`):

- `limits.requests_per_second = 0` отключает лимитер;
- `burst` — ёмкость ведра; при `0` `Proxy::new` берёт
  `max(burst, requests_per_second)`, то есть ведро равно rate;
- новый клиент получает полное ведро;
- отказ не списывает токен;
- таблица ограничена 10 000 адресами; при переполнении сначала удаляются
  записи, неактивные дольше 60 секунд, а если таких нет — новый клиент
  получает отказ;
- время передаётся аргументом, поэтому алгоритм тестируется без sleep.

Превышение — `429` с `Retry-After: 1`. Проверка стоит первой в
`Proxy::handle`, раньше проверки тела, маршрута и ACL.

`limits.max_body_bytes` проверяет только `Content-Length`: если он больше
лимита — `413`. Chunked-тело этим лимитом не ограничивается. Значение `0`
выключает проверку.

`Transfer-Encoding` допускается только в виде одного `chunked`. `gzip,
chunked` и несколько значений дают `501` на запрос. На ответ upstream'а
действует то же правило: не-plain-chunked даёт `502`.

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
- клиент получает `200`, затем задача ждёт `hyper::upgrade::on` и делает
  `copy_bidirectional`.

`CONNECT` не проходит через пул, не использует TLS к цели (это и есть
открытый TCP-туннель), не учитывает `timeout_secs` маршрута и не пишет
отдельных метрик. Работает только по HTTP/1.1: в HTTP/2 и HTTP/3 hyper не
даёт upgrade-путь для такого туннеля.
`Upgrade` (websockets и другие протоколы) определяется по наличию `Upgrade`
и токена `upgrade` в `Connection`. Тело у такого запроса запрещено:
`Content-Length != "0"` или наличие `Transfer-Encoding` дают `400`.

Туннель не идёт через пул соединений: `forward_upgrade` открывает отдельный
`TcpStream` к `host:port` upstream'а, вручную сериализует заголовки в
HTTP/1.1, пишет их, читает ответ до `\r\n\r\n` (лимит 64 КиБ), пропускает
`1xx` кроме `101`. На `101` заголовки `Connection: upgrade` и `Upgrade`
(значение upstream'а, если он его прислал) возвращаются клиенту, байты,
пришедшие сразу после заголовков, отправляются клиенту до
`copy_bidirectional`. На не-`101` ответ передаётся с пустым телом и
`Server: elira`.

`Upgrade` всегда открывает открытый TCP, независимо от `tls = true` у
upstream'а: TLS к бэкенду на этом пути не устанавливается. Ответы upgrade
не проходят `apply_route`, поэтому не получают `add_headers`,
`remove_headers`, `X-Request-Id` и `Alt-Svc`; `Server: elira` в них
вставляется безусловно, даже при `server_header = false`.

Оба вида туннелей используют один и тот же семафор `tunnels` и не
увеличивают `elira_connections_in_flight`: этот счётчик считает клиентские
соединения, а не туннели внутри них.

## Ответ

Проксированный ответ (`Proxy::forward`):

- hop-by-hop заголовки и токены `Connection` удаляются;
- `Content-Length` upstream'а не копируется: framing строит hyper;
- `Server` заменяется на `elira` (заголовок upstream'а не сохраняется);
- для `101` возвращаются `Connection: upgrade` и `Upgrade`;
- при сжатии выставляются `Content-Encoding` и `Vary: accept-encoding`.

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

`apply_route` для ответов, прошедших общий путь (upstream, статика,
redirect, кэш):

1. удаляет `remove_headers`;
2. вставляет `add_headers` (после удаления, поэтому add побеждает);
3. добавляет `X-Request-Id`, только если его ещё нет;
4. удаляет `Server`, если `server_header = false`; этот шаг идёт после
   `add_headers`, поэтому спрятать `Server` сильнее, чем добавить его
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
`forward_upgrade`. Статика, redirect и ответы из кэша его не добавляют: в них
остаётся только заголовок upstream'а, если он был скопирован, а при
`server_header = false` `apply_route` его удаляет. На ответах ошибок и на
`sendfile` `Server` отсутствует.

## Access-лог

`elira-accesslog::Entry` содержит peer, метод, версию, Host, path, статус,
число байт, длительность, User-Agent и request id. `line()` рендерит
common-log-подобную строку, `json()` — плоский JSON. Оба экранируют
управляющие символы, кавычки и обратный слэш, поэтому одна запись не может
разорвать строку. Отсутствующий User-Agent в тексте — `-`, в JSON — `null`.

TCP-путь пишет запись после получения заголовков ответа. `bytes` берётся из
`response.body().size_hint().exact()`, иначе `0`; у потоковых и сжатых тел
точная длина обычно неизвестна, поэтому в логе будет `0`. `duration` — время
до готовности заголовков, а не до конца передачи тела.

Формат берётся из `Runtime.log` на каждый запрос. Если `log.file` задан,
`Runtime::build` открывает `AccessLog`; иначе строка идёт через
`tracing::info!(target: "access", ...)`.

`AccessLog`:

- держит один append-only дескриптор под `Mutex`;
- пишет строку и считает байты;
- при превышении `log.max_bytes` (строго больше) переименовывает текущий файл
  в `<path>.1`, сдвигает `<path>.N` в `<path>.N+1`, открывает новый файл;
- хранит `log.keep` файлов, минимум один;
- не переоткрывает файл по внешнему сигналу сам: `SIGHUP` пересобирает
  `Runtime` и тем самым открывает новый дескриптор. Это же позволяет
  использовать внешний logrotate: переименовать файл и послать `SIGHUP`.

HTTP/3 пишет только через `tracing`, `log.file` на этом пути игнорируется.

## Метрики и health

`Metrics` хранит атомики для глобальных счётчиков и `Mutex<BTreeMap>` для
маршрутов и upstream'ов (не больше 200 меток каждого вида):

- `elira_requests_total{class}` и `elira_request_duration_seconds`;
- `elira_route_requests_total` / `elira_route_duration_seconds_*`;
- `elira_upstream_requests_total` / `elira_upstream_duration_seconds_*`;
- `elira_cache_requests_total{result="hit"|"miss"}`;
- `elira_request_bytes_total`, `elira_response_bytes_total`;
- `elira_reloads_total{result="ok"|"failed"}`;
- `elira_connections_in_flight`, `elira_upstreams{state}`.

`Proxy` кладёт `Labels` (маршрут и имя пула) в extensions ответа, а
листенер снимает их и записывает метрики. TCP-путь делает это в
`serve_conn` и `sendfile`, h3 — в `elira-h3::request`. Счётчик соединений
увеличивается в `serve_conn` и `sendfile`, уменьшается при завершении.
`render()` не сбрасывает состояние и печатает фиксированный порядок серий.

Отдельный листенер `[metrics]` создаётся в `main::run` через
`server::bind_tcp` (с тем же `reuse_port`) и `spawn_metrics`:

- `GET /metrics` — Prometheus text (`text/plain; version=0.0.4`);
- `GET /status` — JSON с пулами, серверами, health-флагами, активными
  запросами и статистикой кэша;
- `POST /reload` — тот же путь, что `SIGHUP`;
- `POST /drain` — graceful shutdown;
- `POST /cache/purge` — очистка кэша;
- всё остальное — `404`.

`/status` и `purge` загружают текущий `Runtime` на каждый запрос, поэтому
видят новый набор пулов после `SIGHUP`. `metrics.auth_file` включает Basic
auth для всех путей. У листенера нет TLS, семафора соединений и таймаутов
из `[limits]`; его соединения не дожидаются остановки. Порт фиксируется при
старте, изменение `metrics.listen` или наличие секции требуют рестарта.

Health-цикл описан в разделе «Upstream». Он читает `Runtime` на каждом
тике, поэтому смена `health.*` применяется без перезапуска задачи.

## Крейты

| Крейт | Ответственность |
| --- | --- |
| `elira` | Бинарник и библиотека: команды `run`/`check`/`migrate`, сигналы, `Runtime` в `ArcSwap`, TCP-листенер, HTTP/1.1 и HTTP/2, PROXY protocol, `sendfile`, файл access-лога, metrics-листенер, graceful shutdown |
| `elira-config` | Типы TOML с `deny_unknown_fields`, значения по умолчанию, валидация, ошибки загрузки; сокетов не открывает |
| `elira-proxy` | `Proxy`, `Router`, `Pool`, пересылка запросов, гигиена заголовков, retries, таймауты, `CONNECT` и `Upgrade`, кэш и сжатие, health-пробы, статика, JSON для `/status` |
| `elira-tls` | Чтение PEM, сборка rustls `ServerConfig`, ALPN `h2`/`http/1.1`, `h3` для QUIC, verifier клиентских сертификатов |
| `elira-upstream` | HTTPS-коннектор к upstream'ам: системные и дополнительные корни, `insecure`, опциональный `h2` в ALPN |
| `elira-auth` | HTTP Basic по htpasswd с bcrypt, `IpAcl` по CIDR |
| `elira-limit` | Token bucket на IP, ограничение таблицы и очистка по idle |
| `elira-cache` | In-memory кэш ответов с бюджетом по байтам, TTL и вытеснением |
| `elira-accesslog` | `Entry`, текстовый и JSON-формат, экранирование, генерация request id |
| `elira-metrics` | Атомарные счётчики, гистограмма, рендер Prometheus |
| `elira-h3` | QUIC-эндпоинт, h3-сервер, мост тела запроса, access-лог |
| `elira-acme` | TLS-ALPN-01 через `rustls-acme`, кэш сертификатов и аккаунта, фоновое продление |
| `elira-migrate` | Конвертация подмножества nginx-конфига в TOML с предупреждениями |

Ключевые внешние зависимости: hyper и hyper-util для HTTP/1.1, HTTP/2 и
клиента к upstream; rustls, tokio-rustls и hyper-rustls для TLS; quinn, h3 и
h3-quinn для HTTP/3; arc-swap для подмены runtime; async-compression для
gzip и brotli; socket2 для `SO_REUSEPORT`; ipnet для CIDR; httpdate для
дат статики.

## Известные ограничения

- `[tls]` — один статический сертификат на листенер. `with_single_cert` не
  использует SNI, поэтому разные сертификаты для разных имён требуют
  отдельных процессов или портов. `[acme]` использует resolver
  `rustls-acme` и умеет несколько доменов, но против реального CA не
  проверялся; проверен только разбор конфигурации и сборка состояния.
- ACME поддерживает только TLS-ALPN-01: порт 443 должен быть доступен
  извне. `Acme` создаётся один раз при старте, `SIGHUP` его не перечитывает
  и не перезапускает. На ACME-ветке нет 10-секундного таймаута handshake и
  нет mTLS.
- `sendfile` работает только на Linux, только на открытом HTTP/1.1, только
  для первого запроса на соединении и только при отсутствии диапазонов,
  условий, `Upgrade`, сжатия, предсжатого sibling'а, route-заголовков, auth,
  ACL, скрытого `Server` и `Alt-Svc`. Ответ закрывает соединение и не
  содержит части обычных заголовков.
- Кэш — не полноценный HTTP-кэш: ключ не учитывает заголовки запроса
  (включая `Authorization`, `Cookie` и `Vary`), нет revalidation,
  инвалидации, `Range`, ответов с chunked-телом; кэш живёт в одном процессе
  и очищается при reload. HIT-ответ отдаётся без сжатия.
- Метрики покрывают только TCP-путь. HTTP/3 не обновляет ни счётчики
  запросов, ни гистограмму, ни `connections_in_flight`. HTTP/3 также
  игнорирует `log.file` и пишет access-лог только в `tracing`.
- HTTP/3 не поддерживает PROXY protocol, mTLS, `CONNECT` и `Upgrade`.
  `max_headers`/`max_header_bytes` к нему не применяются. Reload
  перезапускает слушатель и рвёт живые QUIC-соединения.
- Health-проверки не умеют TLS: пулы с `tls = true` пропускаются и всегда
  считаются живыми. Пассивной проверки по ответам `5xx` нет. Проверка — один
  HTTP/1.1 GET, путь общий для всех серверов.
- Повторы не покрывают ответы `5xx` и запросы с телом. Тело повторной
  попытки не переигрывается.
- `limits.max_body_bytes` проверяет только `Content-Length`; chunked-тело
  не ограничено. `Transfer-Encoding`, отличный от одного `chunked`, даёт
  `501` на запрос и `502` на ответ upstream'а.
- `Upgrade` к upstream'у всегда открывает открытый TCP и игнорирует
  `tls = true`; TLS-бэкенд за websocket не поддерживается. Ответы upgrade не
  проходят `apply_route` и не получают route-заголовки, `X-Request-Id` и
  `Alt-Svc`.
- `CONNECT` обрабатывается до маршрутизации и не подчиняется route ACL,
  auth и `timeout_secs`; ограничение — только `connect.allow`, общий rate
  limiter и семафор туннелей. По HTTP/2 и HTTP/3 туннель не устанавливается.
- Статика поддерживает один диапазон; несколько диапазонов отдаются целиком
  с `200`, `If-Range` не реализован, `If-None-Match` сравнивает строки без
  weak-семантики.
- Ответы, сгенерированные самим прокси (включая `401`, `403`, `404`, `413`,
  `429`, `502`, `503`, `504`), не проходят `apply_route`: в них нет
  `Server`, `X-Request-Id`, `Alt-Svc`, `add_headers` и `remove_headers`.
- `Server: elira` добавляется только к обычному проксированному ответу и к
  ответу `forward_upgrade`. Статика, redirect и HIT-ответы кэша заголовок не
  добавляют: в статике его нет вовсе, а в кэш попадает только `Server`
  upstream'а, если тот его прислал.
- `bytes` в access-логе равен `0`, когда точная длина тела неизвестна
  (потоковые и сжатые ответы), а `duration` измеряется до заголовков, а не
  до конца передачи тела.
- `listen`, `proxy_protocol`, `sendfile`, `reuse_port`,
  `limits.idle_timeout_secs`, `metrics.listen` и `[acme]` меняются только
  рестартом. Reload предупреждает лишь о части из них.
- Reload пересобирает пулы, кэш и rate limiter: keep-alive соединения к
  upstream'ам, кэшированные ответы и накопленные токены не сохраняются.
- `SIGUSR2` требует `reuse_port = true`; без него сигнал игнорируется.
  На не-Unix платформах reload и hot restart недоступны.
