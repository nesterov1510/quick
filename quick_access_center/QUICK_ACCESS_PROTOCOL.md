# Контракт ticket-входа Quick Access ↔ целевой сервис

## Статус и границы

В репозитории реализована только сторона Quick Access. Целевого сервиса здесь нет, поэтому его API, хранение токенов/кодов, проверка callback, локальная сессия и сквозной сценарий пока не реализованы и не проверены. **Считать вход готовым или безопасно включать его в production нельзя**, пока сервис-получатель не реализует все требования ниже и обе стороны не пройдут end-to-end security-тесты.

Протокол не является универсальным SSO и не должен становиться прокси обычной формы логина. Он выдаёт обычную сессию уже существующего пользователя в целевом сервисе после серверной проверки его отдельного service PAT и однократного browser handoff-кода.

## Термины

- **Quick Access** — Flask-приложение с основным входом и отдельной общей админ-сессией Vault.
- **PAT** — отдельный постоянный токен целевого сервиса. Он относится к одному целевому пользователю/service account и ограничен scope. Он не пароль формы.
- **client_id** — публичная фиксированная идентичность Quick Access, заданная `VAULT_QUICK_ACCESS_CLIENT_ID`.
- **code** — криптографически случайный непрозрачный ticket, TTL 1–60 секунд, одно погашение.
- **state** — одноразовый случайный параметр корреляции/login-CSRF, создаётся Quick Access для каждой попытки.

## Конфигурация Quick Access

`VAULT_QUICK_ACCESS_SITES` — точный список URL карточек, отдельный от списка старого browser-extension auto-login. Сравнение строгое после безопасной нормализации. URL карточки не может сам добавить себя в allowlist. Из URL запроса клиента endpoint не строится.

`VAULT_QUICK_ACCESS_CLIENT_ID` задаётся операционно и регистрируется в целевом сервисе. `VAULT_QUICK_ACCESS_ALLOW_PRIVATE_HTTP=0` по умолчанию; включение разрешает только private IP literals/localhost и делает небезопасными и передачу PAT server-to-server, и handoff code/state в браузерном callback. Это только для изолированной разработки; публичный HTTP всегда запрещён. В production обязательно использовать HTTPS на обоих узлах.

Quick Access автоматически добавляет поля в существующую SQLite-таблицу Vault `app_credentials`: `quick_access_token_enc`, `quick_access_enabled`, `quick_access_target`. Токен шифруется существующим Fernet-ключом Vault. В браузерной форме, HTML, DOM/JavaScript, cookie, URL и логи PAT не попадает; оператор устанавливает его скрытым prompt на сервере командой из README. Ротация удаляет старый локально сохранённый ciphertext, а удаление в Vault само по себе не отзывает токен на сервисе.

Счётчик rate limit хранится в новой таблице `quick_access_rate_limits`: не более 6 попыток за 60 секунд на пару Vault-аккаунт/карточка. В текущем Vault один общий аккаунт, поэтому это общий лимит и общее владение секретами, не разделение по сотрудникам.

## Последовательность обмена

### 1. Явный запуск в Quick Access

1. Сотрудник проходит основную аутентификацию Quick Access и разблокирует Vault.
2. Он явно нажимает отмеченную карточку. Браузер отправляет POST на:

   ```http
   POST /vault/app/{app_id}/quick-access
   Content-Type: application/x-www-form-urlencoded
   Cookie: <обычная основная/Vault сессия>

   csrf_token=<Vault-CSRF>
   ```

   GET не запускает ticket-вход. Маршрут требует действующую основную сессию, Vault-сессию, отдельный Vault-CSRF, точный текущий allowlist и привязку токена к URL карточки.

3. Quick Access генерирует новый `state` из 32 случайных байтов (base64url, обычно 43 символа) и делает сервер-сервер запрос к заранее выведенному из allowlist origin. Endpoint всегда фиксирован: `POST {origin}/auth/quick-access/ticket`. Redirect запрещён; сетевой timeout — 5 секунд; системная TLS-проверка сертификата не отключается; proxy из окружения не используется.

### 2. Quick Access → целевой сервис (только сервер-сервер)

```http
POST /auth/quick-access/ticket HTTP/1.1
Host: service.example.com
Authorization: Bearer <PAT>
Content-Type: application/json
Accept: application/json
Cache-Control: no-store
```

```json
{
  "client_id": "quick-access-center",
  "redirect_uri": "https://service.example.com/auth/quick-access/callback",
  "state": "<случайный state этой попытки>"
}
```

`Authorization` содержит только отдельный PAT целевого сервиса и существует только в исходящем серверном запросе. Он не передаётся браузеру и не добавляется к URL. Нельзя следовать `3xx`, менять origin или отправлять PAT на `Location`.

#### Требования к endpoint выдачи ticket

Целевой сервис обязан:

1. В production принимать только TLS с обычной проверкой сертификата. Изолированная dev-сеть может использовать HTTP только при явном opt-in на стороне Quick Access и целевого сервиса; публичный HTTP запрещён. Отклонять неверный/отозванный токен и неверный `client_id`; не полагаться на `Host`, `X-Forwarded-Host`, `Origin`, IP либо `X-User` для установления личности.
2. Проверять токен по **хэшу**, храня постоянный PAT только в hashed form (salted/peppered according to the service's token design). Токен должен быть высокоэнтропийным, отдельным для сервиса/пользователя, минимального scope, отзываемым и ротируемым. Никогда не создавать пользователей по этому запросу.
3. Связать PAT с существующей локальной учётной записью. Перед выдачей кода применить действующие проверки блокировки, состояния аккаунта, ролей, IP-политики и прочих локальных ограничений. Не выдавать admin-права и не повышать роль.
4. Проверить точное зарегистрированное значение `redirect_uri`; не принимать произвольный callback из запроса. Привязать попытку к `client_id`, пользователю, callback, state и конкретной попытке.
5. Создать непрозрачный код генератором криптографической случайности минимум на 256 бит. Хранить только hash кода, `user_id`, `client_id`, зарегистрированный `redirect_uri`, hash/значение state, `expires_at` и метаданные попытки. TTL должен быть не более 60 секунд (рекомендуется 30).
6. Применять собственный rate limit к выдаче и погашению. Ответ и логи не должны содержать PAT, код или секреты.

Успешный ответ строго JSON:

```http
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-store
```

```json
{
  "code": "<opaque-base64url-code, 32–512 chars>",
  "state": "<точно тот же state>",
  "expires_in": 30
}
```

`expires_in` — целое число 1–60. Quick Access отвергает неверный content type, невалидный JSON, код вне URL-safe формата, state mismatch и TTL вне диапазона. Для других результатов целевой сервис возвращает generic `4xx`/`5xx` без деталей о токене/пользователе. Quick Access показывает только безопасное общее сообщение.

### 3. Quick Access → browser → callback целевого сервиса

После корректного ответа Quick Access возвращает no-store HTML handoff без внешних ресурсов: в нём находится только `code`, `state` и фиксированный callback URL. CSP разрешает форму только на allowlisted origin, inline handoff script ограничен nonce, `Referrer-Policy: no-referrer`. Страница автоматически отправляет форму; без JavaScript остаётся кнопка «Продолжить».

Браузер делает **top-level POST**, не GET/redirect/query:

```http
POST /auth/quick-access/callback HTTP/1.1
Origin: https://quick-access.example.com
Content-Type: application/x-www-form-urlencoded

code=<opaque-code>&state=<state>
```

Код и state неизбежно доступны браузеру только в теле этой одноразовой формы; **PAT никогда не доступен браузеру**. В production целевой сервис должен статически зарегистрировать точный HTTPS origin Quick Access независимо от `Host` входящего запроса. Для изолированного local-dev теста допустим только явно заданный точный localhost/private HTTP origin; это не production и не разрешает публичный HTTP. `Origin` сравнивается со статической конфигурацией точным scheme/host/port; нельзя брать ожидаемый origin из `Host`, `X-Forwarded-Host`, `Referer`, user input или динамического callback. При отсутствующем/неверном Origin, несовпавшем state или невалидном коде запрос отклоняется.

### 4. Атомарное погашение и создание обычной сессии

Проверка и погашение должны быть одной атомарной операцией/транзакцией, например условный `DELETE ... WHERE code_hash=? AND expires_at>now AND state_hash=? AND client_id=? AND redirect_uri=? RETURNING user_id`, с уникальным кодом и проверкой числа удалённых строк. Только один конкурентный callback может получить пользователя. Второй запрос, просроченный код, изменённые callback/client/state и неизвестный code должны одинаково отклоняться. Нельзя делать «проверить, затем отдельным запросом отметить использованным» без блокировки/условного update: это оставляет replay race.

После атомарного погашения целевой сервис заново проверяет, что пользователь существует, не заблокирован, активен и допускается текущей IP/роль-политикой; создаёт **обычную локальную пользовательскую сессию** с теми же правами, что стандартный login; меняет session ID; устанавливает `Secure`, `HttpOnly`, подходящий `SameSite` cookie. Код/state должны быть удалены/непереиспользуемы. На callback нельзя принимать идентификатор пользователя/роль из браузера, создавать пользователя, обходить блокировки или превращать отказ в admin login.

Ответ callback не должен перенаправлять с code/state в URL, писать их в access/app/error log, cache, analytics, trace, HTML ссылки или внешний ресурс. Ошибки — одинаковые и неразличимые для пользователя, без token/user enumeration.

## Безопасность / проверочный список целевого сервиса

- [ ] Постоянный PAT хранится только hash; в ответах, HTML, логах и telemetry его нет.
- [ ] Путь ticket и callback фиксированы; точные `client_id`, callback URL и Quick Access Origin заданы конфигурацией сервиса.
- [ ] TLS и сертификат обязательны; endpoint не возвращает redirect; токены имеют scope, срок/ротацию/отзыв.
- [ ] Ticket случайный ≥256 бит; хранится только hash; связан с user/client/callback/state/attempt; TTL ≤60 секунд.
- [ ] Погашение атомарно одноразовое; конкурентный replay, истечение, другой state/origin/callback отклоняются.
- [ ] Callback принимает только POST body, требует точный Origin и state; код не принимается в GET/query.
- [ ] Перед созданием сессии снова применяются активный статус, lockout, роли, IP policy и остальные локальные ограничения.
- [ ] Создаётся только обычная сессия существующего пользователя; нет user provisioning, admin escalation, `X-User` или доверия к host/proxy headers.
- [ ] На callback сохранены собственные CSRF/login-CSRF меры и rate limits; generic error; secret/code/state редактируются из логов.
- [ ] Есть сквозные tests: успешный login; неправильный Origin/state; отсутствующий Origin; просроченный code; параллельный и повторный redeem; отозванный токен; заблокированный пользователь; role/IP denial; login-CSRF.

## Наблюдаемые ограничения текущего Quick Access

- Единственный репозиторий этой задачи — Quick Access. Целевой сервис и его база/сессии здесь отсутствуют; сервисный API выше является контрактом, не утверждением о реализованной стороне.
- Существующий Vault имеет один общий аккаунт, а `app_credentials` не имеют `owner_user_id`; PAT нельзя считать персональным для каждого сотрудника. Используйте отдельный минимально привилегированный service account и не обещайте индивидуальную идентичность.
- Проверки Quick Access используют mock ticket API. Они подтверждают локальное шифрование, CSRF, allowlist, запрет redirects/proxy, response validation, rate limit и POST handoff, но не подтверждают target-session, Origin/state/replay enforcement второй стороны.
