# SFTP Sync — расширение для VS Code

Поддерживаемая и значительно расширенная версия **v2.0.0** от [@IlhamAhmedow](https://github.com/IlhamAhmedow/) 🚀 <br>
(форк от оригинального [liximomo's SFTP plugin](https://github.com/liximomo/vscode-sftp.git))

- 📦 VSIX релизы: https://github.com/IlhamAhmedow/vscode-sftp/releases/
- 📬 Контакт: ahmedow@ilham71.ru | [t.me/ilham2802](https://t.me/ilham2802)

---

## 🆕 Что нового в v2.0.0

### 🖥 Визуальный конфигуратор SFTP

Открывается кнопкой **`⚙ SFTP`** в нижней статус-панели или через:
`Ctrl+Shift+P` → `SFTP: Настроить сервер (визуальный редактор)`

Три вкладки:

#### 📁 Файловый менеджер

- Просмотр и навигация по файлам на удалённом сервере
- **Столбец «Загружено»** — показывает статус каждого файла:
  - ✅ Актуален — локальная копия совпадает по времени
  - ⚠ Устарел — сервер новее локального файла
  - — Нет — файла нет локально
- **Одиночный клик по файлу** — открывает локально (автоматически скачивает, если нет)
- **Кнопка 🌐** у текстовых файлов — открывает файл на сайте (требует поле «URL сайта» в конфиге)
- Кнопки ⬇ Скачать, ⬆ Загрузить в папку, 🗑 Удалить у каждого файла
- Навигация вверх по директориям

#### 📋 Логи (в реальном времени)

- Отображение всех событий расширения без открытия Output Panel
- Фильтрация по уровням: **Все / Info / Warn / Error / Конфликты**
- 📌 Автопрокрутка
- 🗑 Очистка

#### ⚙ Конфигурация

- Визуальная форма вместо ручного редактирования `sftp.json`
- Переключение протокола: SFTP (SSH) / FTP / FTPS
- Поля: хост, порт, таймаут, пользователь, пароль, приватный ключ
- Поле **URL сайта** — для открытия файлов в браузере
- Опции синхронизации: uploadOnSave, downloadOnOpen, умная синхронизация
- Настройка конфликтов, параллельных соединений, ignore-масок
- Кнопка 🔌 **Тест соединения** прямо в форме

### 🗑 Удаление файла локально + на сервере

Новая команда **«Удалить файл/папку (везде)»**:

- Удаляет файл/папку в корзину локально
- Одновременно удаляет на SFTP-сервере

Доступна в контекстном меню проводника и редактора.

### ⚠ Проверка конфликтов перед выгрузкой

Если файл **не редактировался более 1 часа**, перед выгрузкой расширение:

1. Проверяет версию файла на сервере
2. Если сервер новее — спрашивает что делать:
   - 📤 Выгрузить локальный на сервер
   - 📥 Скачать серверный локально
   - ⏭ Пропустить

### 📝 Упрощённые пути в логах

В логах отображаются **относительные пути** вместо полного пути до папки проекта.

---

## Возможности

- [Browser remote with Remote Explorer](#remote-explorer)
- Diff локального и удалённого файла
- Синхронизация директорий (в обе стороны)
- Выгрузка / Скачивание
- Автовыгрузка при сохранении
- File Watcher (отслеживание изменений)
- Несколько конфигураций / профилей
- Переключение профилей
- Поддержка временных файлов
- [Команды](#команды)
- [Отладка](#отладка)
- [FAQ](#faq)

## Команды

| Команда                     | Описание                            |
| --------------------------- | ----------------------------------- |
| `SFTP: Config`              | Создать/открыть sftp.json           |
| `SFTP: Настроить сервер`    | Открыть визуальный конфигуратор     |
| `SFTP: Upload`              | Выгрузить файл                      |
| `SFTP: Upload Folder`       | Выгрузить папку                     |
| `SFTP: Download`            | Скачать файл                        |
| `SFTP: Download Folder`     | Скачать папку                       |
| `SFTP: Sync Local → Remote` | Синхронизировать локальное → сервер |
| `SFTP: Sync Remote → Local` | Синхронизировать сервер → локальное |
| `SFTP: Delete`              | Удалить на сервере                  |
| `SFTP: Delete Both`         | Удалить локально и на сервере       |
| `SFTP: Set Profile`         | Переключить профиль                 |

## Установка

### Способ 1 (VSIX)

1. Скачайте `.vsix` файл из [релизов](https://github.com/IlhamAhmedow/vscode-sftp/releases/).
2. В VS Code: Extensions → `...` → `Install from VSIX…`
3. Выберите файл и перезагрузите.

### Способ 2 (командная строка)

```bash
cursor --install-extension sftp-2.0.0.vsix --force
```

## Быстрый старт

1. Откройте папку проекта в VS Code.
2. `Ctrl+Shift+P` → `SFTP: Config` — будет создан `.vscode/sftp.json`.
3. Заполните параметры подключения.

Или используйте **визуальный конфигуратор**: кнопка `⚙ SFTP` в нижней панели.

Пример `sftp.json`:

```json
{
  "name": "Production",
  "host": "example.com",
  "protocol": "sftp",
  "port": 22,
  "username": "user",
  "remotePath": "/var/www/html",
  "password": "password",
  "uploadOnSave": true,
  "siteUrl": "https://example.com",
  "ignore": [".git", "node_modules", ".DS_Store"]
}
```

## Примеры конфигурации

### Простой

```json
{
  "host": "host",
  "username": "username",
  "remotePath": "/remote/workspace"
}
```

### С профилями

```json
{
  "username": "username",
  "password": "password",
  "remotePath": "/remote/workspace",
  "profiles": {
    "dev": {
      "host": "dev-host",
      "remotePath": "/dev",
      "uploadOnSave": true
    },
    "prod": {
      "host": "prod-host",
      "remotePath": "/prod"
    }
  },
  "defaultProfile": "dev"
}
```

Переключение профиля: `SFTP: Set Profile`.

### Несколько контекстов

```json
[
  {
    "name": "server1",
    "context": "project/build",
    "host": "host",
    "username": "username",
    "password": "password",
    "remotePath": "/remote/project/build"
  },
  {
    "name": "server2",
    "context": "project/src",
    "host": "host",
    "username": "username",
    "password": "password",
    "remotePath": "/remote/project/src"
  }
]
```

### Connection Hopping (через прокси)

```json
{
  "name": "target",
  "remotePath": "/path/in/target",
  "host": "hopHost",
  "username": "hopUsername",
  "privateKeyPath": "~/.ssh/id_rsa",
  "hop": {
    "host": "targetHost",
    "username": "targetUsername",
    "privateKeyPath": "/Users/hopUser/.ssh/id_rsa"
  }
}
```

## Remote Explorer

Remote Explorer позволяет просматривать файлы на удалённом сервере.

Открыть: `View: Show SFTP` или кнопка SFTP в Activity Bar.

- Поддержка множественного выбора (Ctrl/Shift)
- Редактирование: `SFTP: Edit in Local`
- Сортировка через параметр `remoteExplorer.order` в sftp.json

## Отладка

1. Откройте настройки пользователя.
2. Установите `sftp.debug: true`.
3. Перезагрузите VS Code.
4. Логи: `View → Output → sftp` или вкладка **📋 Логи** в визуальном конфигураторе.

## FAQ

Смотрите [FAQ.md](./FAQ.md).

---

## Контакты

Автор: **IlhamAhmedow** — ahmedow@ilham71.ru | [t.me/ilham2802](https://t.me/ilham2802)
