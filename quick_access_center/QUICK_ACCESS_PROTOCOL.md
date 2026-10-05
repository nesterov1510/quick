# Контракт ticket-входа Quick Access ↔ MSB Activity

## Статус и важные ограничения

Quick Access реализует клиентскую сторону API MSB Activity: серверный `POST /api/quick-access/v1/authorize` и браузерный POST на `/quick-access/callback`. Реализация целевого сервиса находится в другом репозитории; владелец сообщил, что эти endpoints уже реализованы, но проверить исходники или выполнить end-to-end сценарий из этого checkout нельзя. Перед production сверьте контракт с развернутой версией MSB Activity.

**Передача PAT пока блокирует безопасное включение.** По описанию реализации MSB Activity показывает постоянный токен один раз в HTML профиля. Это нарушает требование не помещать постоянные токены в HTML/браузер. Не копируйте такой токен в Quick Access и не включайте вход в production до серверной CLI-команды или защищённого server-to-server provisioning. Уже показанный токен следует отозвать; новый выпускать после исправления способа выдачи.

Vault Quick Access имеет один общий аккаунт и не изолирует записи по сотрудникам. PAT связан с существующим пользователем MSB Activity и scope `quick_access:login`, но любой пользователь общего Quick Access Vault может запустить вход под этой целевой учётной записью. Это не персональный SSO сотрудников.

## Конфигурация Quick Access

`VAULT_QUICK_ACCESS_SITES` — отдельный allowlist **точных URL карточек**, которым разрешён ticket-вход. URL из карточки сам по себе не расширяет список. Wildcards, userinfo, query и fragment отклоняются; адрес не используется для произвольного построения endpoint: Quick Access берёт только origin из разрешённой карточки и добавляет фиксированные пути ниже.

`VAULT_QUICK_ACCESS_ALLOW_PRIVATE_HTTP=0` по умолчанию. Включение допускает только private IP literals/localhost и небезопасно для PAT и callback; это только для изолированной разработки. Для production требуются валидный HTTPS на Quick Access и MSB Activity, стандартная проверка TLS-сертификата, без redirects и без proxy из окружения.

PAT устанавливается на сервере Quick Access через `vault_control/set_quick_access_token.py`: скрытый terminal prompt, не аргумент командной строки или stdin. В существующей SQLite-таблице Vault хранится Fernet-шифротекст. В Quick Access HTML/JavaScript, cookie, URL и логах PAT не появляется.

## Протокол

### 1. Явный запуск

Пользователь входит в Quick Access, разблокирует Vault и нажимает карточку. Запуск — только CSRF-защищённый `POST /vault/app/{app_id}/quick-access`; GET не запускает вход. Маршрут проверяет основную и Vault-сессии, Vault-CSRF, точный allowlist и привязку сохранённого токена к текущему URL карточки. Rate limit Quick Access: 6 попыток за 60 секунд на карточку и 30 за 60 секунд на общий Vault-аккаунт.

### 2. Quick Access → MSB Activity (server-to-server)

Quick Access создаёт случайные `state` и `attempt_id` и отправляет запрос только на фиксированный endpoint origin, взятый из разрешённого URL карточки:

```http
POST /api/quick-access/v1/authorize
Authorization: Bearer <service PAT>
Content-Type: application/json
Accept: application/json
Cache-Control: no-store
```

```json
{
  "service": "msb-activity",
  "callback_uri": "https://msb-activity.example.com/quick-access/callback",
  "state": "<случайное состояние этой попытки>",
  "attempt_id": "<случайный идентификатор этой попытки>"
}
```

`callback_uri` — фиксированный путь `/quick-access/callback` на том же origin целевого сервиса. Он должен точно совпадать с `QUICK_ACCESS_CALLBACK_URL` в MSB Activity. В запросе есть bearer PAT, поэтому Quick Access отключает redirects и системные proxy, проверяет TLS и ограничивает timeout пятью секундами. PAT никогда не отправляется на адрес, взятый из заголовков или динамического redirect.

Успех — строго JSON с единственным полем:

```http
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-store
```

```json
{"code":"<opaque one-use code>"}
```

Код проверяется на URL-safe формат. Целевой сервис задаёт TTL через `QUICK_ACCESS_CODE_TTL_SECONDS`: по сообщённой реализации default — 30 секунд, максимум — 60. Ошибки сети и ответа показываются как общие безопасные сообщения без деталей токена или пользователя.

### 3. Quick Access → браузер → callback MSB Activity

Quick Access возвращает no-store handoff-страницу с CSP, `Referrer-Policy: no-referrer` и формой. Браузер делает top-level **POST**, а не GET/redirect/query:

```http
POST /quick-access/callback
Origin: https://quick.example.com
Content-Type: application/x-www-form-urlencoded
```

Форма содержит только данные одной попытки:

```text
code=<one-use code>
state=<state>
service=msb-activity
callback_uri=<точный callback URI>
attempt_id=<attempt ID>
```

Одноразовые значения неизбежно проходят через тело этой формы; постоянный PAT — нет. В MSB Activity ожидаемый `Origin` должен быть задан статически как точный `QUICK_ACCESS_ORIGIN`; нельзя выводить его из `Host`, `X-Forwarded-Host`, `Referer`, IP или значения формы.

### 4. Проверка, погашение и локальная сессия в MSB Activity

По предоставленному описанию целевой сервис должен:

- проверить bearer PAT по хэшу, его срок/отзыв, сервис `msb-activity`, callback и активность связанного существующего пользователя; токен действует только со scope `quick_access:login`;
- связать ticket с пользователем, callback, service, state и attempt; хранить хэш случайного кода, а не открытый код; TTL — не более 60 секунд;
- на callback принять только POST и точный `Origin`, проверить все связанные поля и погасить код атомарно: повторный/конкурентный redeem отклоняется;
- повторно применить локальные проверки блокировки, роли, IP и активности; создать обычную сессию существующего пользователя без создания аккаунта и повышения прав;
- устанавливать обычную локальную `access_token` cookie, а после успеха ответить `303` на `/dashboard` или `/admin/dashboard` согласно текущей роли из БД;
- применять rate limits, общие сообщения об ошибках, HTTPS в production и не писать токен/код/state в логи. HTTPS-отказ — `403`; logout выполняется обычным POST `/logout`.

Quick Access не может подтвердить реализацию этих target-side проверок без тестов и развернутого MSB Activity.

## Сквозная проверка перед production

1. Обе стороны доступны только по HTTPS с действительными сертификатами; `QUICK_ACCESS_ORIGIN` и `QUICK_ACCESS_CALLBACK_URL` заданы точными URL.
2. Quick Access не отправляет PAT в браузер; в HTML handoff находятся только code/state/service/callback/attempt.
3. Успешная попытка создаёт сессию только существующего активного пользователя и сохраняет его локальную роль.
4. Проверить неверный/отсутствующий Origin, неверные state/service/callback/attempt, истёкший/повторный/параллельно погашенный код, отозванный PAT, заблокированного пользователя и отказ по IP/роли.
5. Проверить CSRF-защиту обычного logout, rate limits, no-store и отсутствие PAT/code/state в access, app и error logs.
6. Решить передачу токена: для соблюдения запрета на секреты в HTML использовать CLI на стороне MSB Activity или защищённое server-to-server provisioning. Текущий одноразовый показ PAT в профиле не удовлетворяет этому требованию.
