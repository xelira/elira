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
- Сжатие gzip для подходящих ответов при `Accept-Encoding: gzip`, с `Vary` и
  потоковой передачей тела.
- Ограничение частоты запросов на IP через token bucket и лимит тела по
  `Content-Length`.
- `trusted_proxies` для `X-Forwarded-For`; заголовки `Forwarded`,
  `X-Forwarded-*`, `X-Real-IP` и их underscore-алиасы от клиента отбрасываются.
- PROXY protocol версий 1 и 2 до TLS и HTTP.
- Access-лог в текстовом или JSON-формате с request id на каждый запрос.
- Prometheus-метрики на отдельном листенере: запросы по классам статусов,
  гистограмма задержки, число соединений в работе и состояние upstream'ов.
- Перезагрузка конфигурации по `SIGHUP`: маршруты, upstream'ы, сертификаты и
  формат лога применяются без разрыва HTTP/1.1 и HTTP/2 соединений.
- Ограничения на число и размер заголовков, число соединений, idle-таймаут,
  таймаут upstream'а и размер тела запроса.
- Удаление hop-by-hop заголовков, включая токены из `Connection`.
- Graceful shutdown по `SIGINT` и `SIGTERM` с ограниченным временем на
  завершение соединений.
- Команда `elira check` для разбора и валидации конфигурации без открытия
  сокетов.
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
