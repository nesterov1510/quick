# MSB Quick Access Center

Панель ссылок на сервисы на Flask/SQLite: карточки, категории и поиск, фоновая проверка HTTP/TCP, отдельный Vault с Fernet-шифрованием логинов и паролей. Python **3.11+**. Исходники лежат здесь; архивное виртуальное окружение не требуется.

## Запуск с нуля на Linux/macOS (на этом компьютере)

```bash
cd quick_access_center
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt

# Укажите место для базы, изображений, логов и anti-brute-force state.
export MSB_QUICK_ACCESS_DATA_DIR="$HOME/.local/share/quick-access-center"
mkdir -p "$MSB_QUICK_ACCESS_DATA_DIR"
chmod 700 "$MSB_QUICK_ACCESS_DATA_DIR"

python access_control/setup_access.py
python vault_control/setup_vault.py

# Только локальная проверка на http://127.0.0.1; в сети используйте HTTPS.
export MSB_QUICK_ACCESS_COOKIE_SECURE=0
python app.py
```

Откройте **http://127.0.0.1:5050/access-control**. Сначала введите логин/пароль из `setup_access.py`; для раздела «Пароли» используйте отдельные данные из `setup_vault.py`. Для остановки — Ctrl+C. При первом запуске пустая база создаётся автоматически в `$MSB_QUICK_ACCESS_DATA_DIR/base/quick_access.db`. Пароли не выводятся командами установки и не хранятся в открытом виде в `.env`.

Оба скрипта создают локальные, игнорируемые Git файлы `access_control/access.env` и `vault_control/vault.env` с правами `0600` (на Windows настройте ACL). Запускайте их интерактивно: потребуется два разных пароля **не короче 12 символов**. Если конфигурация уже есть, скрипт спросит подтверждение перед обновлением пароля. **Не удаляйте `VAULT_ENCRYPTION_KEY`: без него сохранённые записи Vault не расшифровать.** При наличии записей в БД скрипт откажется создавать новый ключ вместо утраченного.

### Windows PowerShell (локальная проверка)

```powershell
cd quick_access_center
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
$env:MSB_QUICK_ACCESS_DATA_DIR = "$env:LOCALAPPDATA\QuickAccessCenter"
.\.venv\Scripts\python.exe access_control\setup_access.py
.\.venv\Scripts\python.exe vault_control\setup_vault.py
$env:MSB_QUICK_ACCESS_COOKIE_SECURE = "0"
.\.venv\Scripts\python.exe app.py
```

Если порт занят, задайте `MSB_QUICK_ACCESS_PORT` (по умолчанию `5050`). Встроенный `python app.py` слушает только `127.0.0.1` и не включает интерактивный отладчик; **не выставляйте его в интернет**. Gunicorn используется только на Unix-подобных системах.

## Автовход по карточке в свои сервисы

Автовход работает для **явного списка** точных адресов страниц входа. Встроены: `https://msb-activity.meryosab.com/login`, `https://repair-partner-service.meryosab.com/ru/login`, `https://msb-career.meryosab.com/admin/login/`. Остальные сервисы добавляются ключом `VAULT_AUTOLOGIN_SITES` в `vault_control/vault.env` и файлом `browser_extension/sites.local.json` — [пошаговое подключение и требования к самим сервисам](browser_extension/ADDING_SERVICES.md). Список и отбракованные значения видны на странице Vault `/vault/`. Адреса `http://` отклоняются; для сервиса в локальной сети без TLS нужен `VAULT_AUTOLOGIN_ALLOW_PRIVATE_HTTP=1`, при этом пароль передаётся по сети открытым текстом.

Создайте карточку с **точной ссылкой** на страницу входа, нажмите на ней **🔐**, откройте Vault, сохраните логин/пароль этого сервиса и отметьте **«Использовать этот доступ для автовхода»**. Установите расширение для Chrome/Edge и подключите его к своей панели по [инструкции расширения](browser_extension/README.md). Пока Vault разблокирован, нажатие на карточку откроет сайт и заполнит его форму. **Без расширения карточка только открывает страницу входа**: браузер не разрешает обычному сайту Quick Access заполнить чужую форму. Сервисы с CAPTCHA или обязательным вторым фактором расширение не обходит.

## Доступ из сети / production

Используйте HTTPS reverse proxy (Nginx, Caddy и т. п.) и Gunicorn, доступный **только локально**. Внутри `quick_access_center/` с активированным venv и заданным постоянным `MSB_QUICK_ACCESS_DATA_DIR`:

```bash
umask 077
export MSB_QUICK_ACCESS_COOKIE_SECURE=1   # значение по умолчанию
.venv/bin/gunicorn --workers 1 --bind 127.0.0.1:5050 app:app
```

Один worker предотвращает дублирование фоновых проверок статусов в отдельных процессах. Прокси должен проксировать запросы на `http://127.0.0.1:5050`, передавать `Host`, закрывать прямой доступ к Gunicorn и перенаправлять HTTP на HTTPS. Пример для Nginx после настройки реального домена и TLS-сертификата:

```nginx
server {
    listen 443 ssl;
    server_name quick.example.com;
    ssl_certificate     /etc/letsencrypt/live/quick.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/quick.example.com/privkey.pem;
    client_max_body_size 7m;

    location / {
        proxy_pass http://127.0.0.1:5050;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $remote_addr; # заменяем, а не пересылаем чужой заголовок
        proxy_set_header X-Forwarded-Proto https;
    }
}
```

По умолчанию доступ разрешён только с `127.0.0.1,::1`. Чтобы разрешить реальные клиентские IP за этим прокси, установите в **обоих** `.env`:

```text
MAIN_ACCESS_ALLOWED_IPS=192.168.8.0/24
MAIN_ACCESS_TRUST_PROXY=1
MAIN_ACCESS_TRUSTED_PROXIES=127.0.0.1,::1
```

Для Vault — аналогичные `VAULT_ACCESS_ALLOWED_IPS`, `VAULT_ACCESS_TRUST_PROXY`, `VAULT_ACCESS_TRUSTED_PROXIES`. Укажите **свои** адреса и сеть; прокси с другого хоста должен быть явно добавлен в `*_TRUSTED_PROXIES`. Включайте `TRUST_PROXY=1` только за прокси, который очищает/дополняет `X-Forwarded-For`. Код не доверяет заголовкам от произвольного посетителя. Не используйте `ALLOWED_IPS=*` в production. После изменения `.env` перезапустите Gunicorn.

## Проверка и данные

```bash
cd quick_access_center
.venv/bin/python -m unittest discover -s tests -v
node --test browser_extension/tests/*.test.mjs   # тесты расширения, Node.js нужен только для них
```

Тесты создают временную базу, ключи и пароли: вашу рабочую базу они не меняют. `/health` намеренно доступен **только после основного входа**. Данные, изображения, журналы и состояние защиты от подбора хранятся в `MSB_QUICK_ACCESS_DATA_DIR`; делайте защищённую резервную копию этой папки **вместе с `vault_control/vault.env`**. Файлы `.env`, база, логи, изображения и `*.rar` исключены из Git.

Для ручных запросов к изменяющим маршрутам основной панели передавайте CSRF-токен из формы/страницы (для JSON — заголовок `X-CSRF-Token`). Vault использует собственный CSRF-токен. Лимит изображения — 5 МиБ по умолчанию (`MSB_QUICK_ACCESS_MAX_IMAGE_BYTES`); принимаются только проверенные PNG/JPEG/WebP/GIF. Индикатор ONLINE означает, что HTTP-сервер ответил (включая 404), либо доступен TCP-порт; это **не проверка бизнес-логики** удалённого сервиса.

### Старый архив

`quick_access_center.rar` исключён из текущего набора отслеживаемых файлов, **не удалён с локального диска**. Он содержит прежние `.env` с ключами, базу, логи и `venv`; не переносите эти файлы в новый репозиторий и не распространяйте архив. История Git по-прежнему содержит старый blob: исключение файла из текущей версии **не удаляет его из прошлых коммитов**. Если архив передавался третьим лицам, смените пароли/ключи; ротация ключа Vault требует предварительно расшифровать и повторно зашифровать существующие записи либо восстановить прежний ключ из защищённого бэкапа. Историю Git можно очистить только отдельной согласованной процедурой переписывания истории.
