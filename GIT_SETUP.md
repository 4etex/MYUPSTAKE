# 🔐 Настройка Git для нового репозитория

## Выход из старого аккаунта GitHub

### Шаг 1: Удалить сохранённые credentials
```powershell
# Удалить сохранённые credentials Windows
git credential-manager-core erase
# Или для старых версий:
git credential-manager erase
```

### Шаг 2: Очистить кэш credentials
```powershell
# Очистить кэш Git
git config --global --unset credential.helper
git config --system --unset credential.helper
```

### Шаг 3: Удалить старый remote (если есть)
```powershell
cd D:\casino
git remote remove origin
```

---

## Подключение к новому репозиторию

### Шаг 1: Проверка статуса
```powershell
cd D:\casino
git status
```

### Шаг 2: Добавить новый remote
```powershell
git remote add origin https://github.com/4etex/MYUPSTAKE.git
```

### Шаг 3: Проверить remote
```powershell
git remote -v
```

Должно показать:
```
origin  https://github.com/4etex/MYUPSTAKE.git (fetch)
origin  https://github.com/4etex/MYUPSTAKE.git (push)
```

### Шаг 4: Первый коммит (если репозиторий пустой)
```powershell
git add .
git commit -m "Initial commit: MYUPSTAKE Casino"
```

### Шаг 5: Push в новый репозиторий
```powershell
git branch -M main
git push -u origin main
```

**При первом push GitHub попросит авторизацию:**
- Откроется браузер
- Войдите в аккаунт **4etex**
- Разрешите доступ

---

## Если репозиторий уже существует

Если в репозитории уже есть файлы:

```powershell
# Получить изменения
git fetch origin

# Слить с локальными изменениями
git pull origin main --allow-unrelated-histories

# Или принудительно заменить (ОСТОРОЖНО!)
# git push -u origin main --force
```

---

## Альтернатива: Использование Personal Access Token

Если не работает авторизация через браузер:

1. GitHub → Settings → Developer settings → Personal access tokens → Tokens (classic)
2. Generate new token
3. Выберите права: `repo` (полный доступ к репозиториям)
4. Скопируйте токен

При push используйте:
```
Username: 4etex
Password: ваш_токен
```

Или в URL:
```powershell
git remote set-url origin https://4etex:ваш_токен@github.com/4etex/MYUPSTAKE.git
```

---

## Быстрая команда (всё сразу)

```powershell
cd D:\casino
git remote remove origin
git remote add origin https://github.com/4etex/MYUPSTAKE.git
git add .
git commit -m "Initial commit"
git branch -M main
git push -u origin main
```

---

## Проверка

После успешного push:
1. Откройте https://github.com/4etex/MYUPSTAKE
2. Должны быть все файлы проекта
3. Готово к деплою! 🚀


