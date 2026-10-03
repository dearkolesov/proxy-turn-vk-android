# Нагрузочное тестирование сервера

Проводите тесты на staging-инфраструктуре, через тот же тип сети и балансировщика, который будет использоваться в эксплуатации. Не направляйте генератор на production пользователей.

## Profile HTTP API

В репозитории есть `scripts/profile-api-loadtest.go`: он запускает виртуальные устройства с одним staging profile password, одновременно запрашивает challenge, подписывает `/api/profile/status` и повторяет цикл с заданным интервалом. Запускайте генератор из той же сети/NAT, через который придут пользователи, и направляйте его через тестовый load balancer на все ноды.

```sh
read -rsp 'Staging profile password: ' PROFILE_PASSWORD
export PROFILE_PASSWORD
printf '\n'
go run scripts/profile-api-loadtest.go \
  -endpoint http://vpn-staging.example.org:56000 \
  -clients 400 -duration 10m -interval 8s
unset PROFILE_PASSWORD
```

`http_200` означает полный успешный challenge+HMAC цикл; отдельно выводятся `429`, `503`, транспортные ошибки и p50/p95/p99 времени цикла. Начальный burst имитирует одновременное появление 400 клиентов, следующие циклы дают около 50 обращений в секунду. Проверяйте `/metrics` на каждой ноде: `qwdtt_server_profile_challenge_rejected_total`, `qwdtt_server_profile_challenge_errors_total`, active connections и PostgreSQL pool gauges.

Этот тест проверяет control API и БД, но **не** создаёт 400 WireGuard/DTLS туннелей и не измеряет пропускную способность VPN. У profile status искусственные device IDs не занимают слоты; это специально изолирует нагрузку challenge/auth/status.

## Полные туннели и отказ ноды

Для data plane используйте отдельный staging кластер, production-совместимый клиент или протокольно совместимый tunnel harness и UDP load balancer с affinity по UDP flow. Создайте 100 тестовых ключей с `max_devices=4`, подготовьте 400 уникальных устройств и проведите ramp-up сначала по 10 новых туннелей в секунду, затем отдельный reconnect storm всеми устройствами.

После подключения держите двусторонний трафик 30 минут, проверьте DNS/NAT и распределение сессий по нодам. Выведите один узел из балансировки и завершите его процесс: активные туннели на этой ноде ожидаемо оборвутся, клиенты должны переподключиться к оставшимся; туннели других нод должны сохраниться. Отдельно перезапустите ноду и проверьте восстановление peers/credentials из PostgreSQL. Проверьте повтор admin create с тем же `Idempotency-Key`, а также одновременную выдачу четвёртого и пятого устройства на один профиль.

При отказе общей PostgreSQL ожидайте `503` от readiness и challenge API; балансировщик должен перестать отправлять на ноды, не имеющие доступа к общей БД. Не рассчитывайте на перенос уже открытого UDP-туннеля между узлами: клиенты переподключаются.

## Метрики и критерии

Фиксируйте p50/p95/p99 connect time, handshake failures, packet loss/disconnects, throughput, CPU/RAM каждой ноды, PostgreSQL CPU/IO/connection pool и все HTTP `429`/`5xx`. При здоровой БД ожидается ноль `5xx`, отсутствие ложных `429` на целевом burst из 400 challenge и соблюдение лимита устройств при конкурентном подключении. Абсолютные latency/throughput SLO определите по целевым VPS и реальному профилю трафика до прогона; unit/integration burst-тест не заменяет staging-проверку полных туннелей.
