# Короткая инструкция: Quick Access ↔ MSB Activity

Это краткая памятка; подробный API — в [`QUICK_ACCESS_PROTOCOL.md`](QUICK_ACCESS_PROTOCOL.md).

> **Стоп перед передачей токена.** MSB Activity сейчас показывает PAT один раз в HTML профиля. По вашему правилу постоянный токен нельзя передавать через HTML/браузер, поэтому **не копируйте его** и не включайте вход в production. Сначала добавьте на стороне MSB Activity безопасную выдачу: интерактивный CLI на сервере или защищённое server-to-server provisioning. После этого отзовите уже показанный токен и создайте новый.
>
> Подключение также нужно проверить end-to-end с реальным развернутым MSB Activity. В этом репозитории исходников целевого сервиса нет.

## 1. Разверните Quick Access

На Linux-хосте с systemd, из checkout `quick_access_center`:

```bash
cd quick_access_center
sudo ./deploy/install.sh
```

При первом запуске мастер попросит создать пароль основной панели и отдельный пароль Vault. Сохраните их в менеджере паролей. Служба `quick-access-center` слушает только `127.0.0.1:5050`; install script сам не ставит домен и TLS.

Поставьте перед ней Nginx/Caddy с действительным HTTPS-сертификатом и проксированием на `127.0.0.1:5050`. Не открывайте порт `5050` в firewall. В `access_control/access.env` и `vault_control/vault.env` разрешите только нужные IP/прокси, следуя production-разделу [`README.md`](README.md). На внешнем соединении должны работать HTTPS и Secure cookies.

Проверить запуск:

```bash
sudo systemctl status quick-access-center
sudo journalctl -u quick-access-center -f
```

## 2. Задайте точные адреса

Ниже `https://quick.example.com` — **реальный HTTPS origin Quick Access**, а `https://msb-activity.meryosab.com` — **реальный публичный origin MSB Activity**. Замените примеры на адреса вашей установки; не добавляйте `*`, query или fragment.

На стороне MSB Activity задайте значения в её production-конфигурации:

```text
APP_ENV=production
PUBLIC_BASE_URL=https://msb-activity.meryosab.com
APP_ALLOWED_ORIGINS=https://quick.example.com
QUICK_ACCESS_ORIGIN=https://quick.example.com
QUICK_ACCESS_CALLBACK_URL=https://msb-activity.meryosab.com/quick-access/callback
QUICK_ACCESS_TOKEN_TTL_DAYS=90
QUICK_ACCESS_CODE_TTL_SECONDS=30
QUICK_ACCESS_ALLOW_HTTP=0
```

Оставьте действующими rate limits для authorize и callback (`RATE_LIMIT_QUICK_ACCESS` и `RATE_LIMIT_QUICK_ACCESS_CALLBACK`). Не включайте HTTP для production.

В `quick_access_center/vault_control/vault.env` добавьте точный URL страницы входа MSB Activity:

```text
VAULT_QUICK_ACCESS_SITES=https://msb-activity.meryosab.com/login
VAULT_QUICK_ACCESS_ALLOW_PRIVATE_HTTP=0
```

Если у вас другой домен, используйте один и тот же реальный origin согласованно в карточке, allowlist и настройках MSB. После изменения перезапустите Quick Access:

```bash
sudo systemctl restart quick-access-center
```

## 3. Подготовьте карточку и запись Vault

1. В Quick Access создайте карточку с точным URL страницы входа, например `https://msb-activity.meryosab.com/login`.
2. В Vault создайте запись с названием вроде `MSB Activity — Quick Access`. Логин/пароль формы для ticket-входа не нужны.
3. **Не вставляйте PAT в браузерную форму и не копируйте его из HTML профиля MSB Activity.** После добавления безопасного terminal/server-to-server способа получите новый PAT, привязанный к существующему пользователю MSB Activity со scope `quick_access:login`.
4. На хосте Quick Access запустите CLI от имени Unix-пользователя службы. Команда спросит ID записи и PAT скрытым терминальным prompt; не передавайте PAT аргументом, через env, файл команды или stdin:

   ```bash
   SERVICE_USER=your-service-user
   APP_DIR=/absolute/path/to/quick_access_center
   sudo -u "$SERVICE_USER" env \
     MSB_QUICK_ACCESS_DATA_DIR=/var/lib/quick-access-center \
     /opt/quick-access-center-venv/bin/python \
     "$APP_DIR/vault_control/set_quick_access_token.py"
   ```

   Укажите имя Unix-пользователя службы и абсолютный путь checkout. При стандартной установке это пользователь, запустивший `sudo ./deploy/install.sh`. PAT сохраняется в существующем Vault зашифрованным и остаётся выключенным.

5. Откройте запись Vault, включите **«Вход через Quick Access без расширения»** и сохраните. После разблокировки Vault нажмите карточку MSB Activity. Успех — обычная сессия существующего пользователя и переход на `/dashboard` или `/admin/dashboard` по его текущей роли. Для выхода используйте обычный logout MSB Activity.

Пункты 3–5 пока **не выполняйте с PAT, показанным в HTML**. Когда безопасная выдача токена и сквозная проверка готовы, такой запуск использует API `POST /api/quick-access/v1/authorize`, а браузер — только одноразовый POST на `/quick-access/callback`; постоянный PAT идёт только server-to-server.

## 4. Отзыв токена и важные ограничения

- При утечке или ротации сначала отзовите PAT в MSB Activity, затем выпустите новый безопасным способом и повторите terminal provisioning. Удаление токена из Vault само по себе не отзывает его в MSB.
- В Quick Access один общий Vault-аккаунт и нет изоляции секретов по сотрудникам. Все, кто может разблокировать этот Vault, смогут инициировать вход под целевым пользователем, к которому привязан PAT. Это **не** персональный вход каждого сотрудника.
- Перед production проверьте неверный/пропущенный Origin, state/service/callback/attempt, истёкший и повторно использованный code, отозванный PAT, заблокированного пользователя, IP/role policy, logout и отсутствие секретов в логах.
