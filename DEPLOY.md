# 🚀 Инструкция по деплою MYUPSTAKE Casino для Telegram Mini App

## 📋 Варианты деплоя

### Вариант 1: Vercel (Рекомендуется - самый простой)

#### Шаг 1: Подготовка
1. Установите Vercel CLI:
```bash
npm i -g vercel
```

2. Войдите в Vercel:
```bash
vercel login
```

#### Шаг 2: Деплой
```bash
cd D:\casino
vercel
```

Следуйте инструкциям:
- Link to existing project? **No**
- Project name: **myupstake-casino** (или любое другое)
- Directory: **./**
- Override settings? **No**

#### Шаг 3: Настройка переменных окружения
1. Зайдите на [vercel.com](https://vercel.com)
2. Откройте ваш проект
3. Settings → Environment Variables
4. Добавьте все переменные из `env.example`:

```
TELEGRAM_BOT_TOKEN=ваш_токен_бота
ADMIN_TELEGRAM_ID=8095351884
CRYPTO_BOT_TOKEN=497834:AA61moFx1FRYnPhY8sALPpQbcNNBr0EvZTA
SECRET_KEY=сгенерируйте_случайную_строку_32_символа
ALLOWED_ORIGINS=https://your-app.vercel.app,https://web.telegram.org
APP_URL=https://your-app.vercel.app
MINI_APP_URL=https://your-app.vercel.app
NODE_ENV=production
```

**Важно:** После добавления переменных сделайте **Redeploy**

#### Шаг 4: Получите URL
После деплоя вы получите URL вида: `https://myupstake-casino.vercel.app`

---

### Вариант 2: Railway (Альтернатива)

#### Шаг 1: Регистрация
1. Зайдите на [railway.app](https://railway.app)
2. Войдите через GitHub

#### Шаг 2: Создание проекта
1. New Project → Deploy from GitHub repo
2. Выберите ваш репозиторий или создайте новый
3. Railway автоматически определит Node.js проект

#### Шаг 3: Настройка переменных
1. Откройте проект → Variables
2. Добавьте все переменные из `env.example`

#### Шаг 4: Получите URL
Railway даст вам URL вида: `https://your-app.up.railway.app`

---

### Вариант 3: Render

#### Шаг 1: Регистрация
1. Зайдите на [render.com](https://render.com)
2. Войдите через GitHub

#### Шаг 2: Создание Web Service
1. New → Web Service
2. Connect ваш GitHub репозиторий
3. Настройки:
   - **Name:** myupstake-casino
   - **Environment:** Node
   - **Build Command:** `npm install && npm run build`
   - **Start Command:** `node index.js`
   - **Plan:** Free (или платный)

#### Шаг 3: Переменные окружения
1. Environment → Add Environment Variable
2. Добавьте все из `env.example`

#### Шаг 4: Деплой
Нажмите **Create Web Service** и дождитесь деплоя.

---

## 🤖 Настройка Telegram Mini App

### Шаг 1: Получите токен бота
1. Откройте [@BotFather](https://t.me/BotFather) в Telegram
2. Отправьте `/newbot` или выберите существующего бота
3. Скопируйте токен (формат: `123456:ABC-DEF...`)

### Шаг 2: Создайте Mini App
1. В [@BotFather](https://t.me/BotFather) отправьте `/newapp`
2. Выберите вашего бота
3. Укажите название: **MYUPSTAKE Casino**
4. Описание: **Crash игра с выводом средств**
5. **Photo:** Загрузите иконку (512x512px)
6. **Short name:** myupstake (будет в URL)
7. **Web App URL:** `https://your-app.vercel.app` (ваш URL после деплоя)

### Шаг 3: Настройте команды бота
В [@BotFather](https://t.me/BotFather):
```
/setcommands
```
Добавьте:
```
start - Начать игру
```

### Шаг 4: Обновите переменные
В настройках вашего хостинга обновите:
- `MINI_APP_URL` = URL вашего деплоя
- `APP_URL` = URL вашего деплоя
- `TELEGRAM_BOT_TOKEN` = токен от BotFather

---

## 🔧 Настройка Crypto Bot Webhook

### Шаг 1: Получите URL webhook
Ваш webhook URL: `https://your-app.vercel.app/api/webhook/crypto`

### Шаг 2: Настройте в Crypto Bot
1. Откройте [@CryptoBot](https://t.me/CryptoBot)
2. Отправьте `/newapp`
3. Укажите ваш webhook URL
4. Или используйте API:
```bash
curl -X POST "https://pay.crypt.bot/api/setWebhook" \
  -H "Crypto-Pay-API-Token: 497834:AA61moFx1FRYnPhY8sALPpQbcNNBr0EvZTA" \
  -H "Content-Type: application/json" \
  -d '{"url": "https://your-app.vercel.app/api/webhook/crypto"}'
```

---

## ✅ Проверка работы

### 1. Проверьте сервер
Откройте в браузере: `https://your-app.vercel.app/health`

Должен вернуться:
```json
{
  "status": "ok",
  "state": "idle",
  "roundId": "..."
}
```

### 2. Проверьте бота
1. Откройте вашего бота в Telegram
2. Отправьте `/start`
3. Должна появиться кнопка "🎮 ИГРАТЬ"
4. Нажмите - должно открыться Mini App

### 3. Проверьте игру
1. В Mini App должна загрузиться игра
2. Попробуйте поставить ставку
3. Проверьте баланс

---

## 🐛 Решение проблем

### Проблема: "CORS error"
**Решение:** Проверьте `ALLOWED_ORIGINS` - должен включать ваш домен и `https://web.telegram.org`

### Проблема: "Socket connection failed"
**Решение:** 
- Убедитесь что Socket.io работает на том же домене
- Проверьте что порт правильный (Vercel использует автоматически)

### Проблема: "Telegram WebApp не работает"
**Решение:**
- Убедитесь что открываете через бота в Telegram
- Проверьте что `MINI_APP_URL` правильный в BotFather
- Проверьте что бот запущен и работает

### Проблема: "Баланс не обновляется"
**Решение:**
- Проверьте логи на сервере
- Убедитесь что `userId` передаётся правильно
- Проверьте что Socket.io подключение активно

---

## 📝 Чеклист перед запуском

- [ ] Деплой выполнен успешно
- [ ] Все переменные окружения установлены
- [ ] BotFather настроен (Mini App создан)
- [ ] `MINI_APP_URL` указывает на ваш деплой
- [ ] Crypto Bot webhook настроен
- [ ] Бот отвечает на `/start`
- [ ] Mini App открывается из бота
- [ ] Игра загружается
- [ ] Ставки работают
- [ ] Баланс обновляется
- [ ] Депозиты работают
- [ ] Выводы работают

---

## 🔐 Безопасность

После деплоя:
1. ✅ Убедитесь что `SECRET_KEY` установлен (случайная строка)
2. ✅ `ALLOWED_ORIGINS` не содержит `*` в продакшене
3. ✅ `ADMIN_TELEGRAM_ID` правильный
4. ✅ Проверьте логи безопасности: `/api/admin/security-logs` (только админ)

---

## 📞 Поддержка

Если что-то не работает:
1. Проверьте логи на хостинге
2. Проверьте консоль браузера (F12)
3. Проверьте что все переменные окружения установлены
4. Убедитесь что бот запущен

**Удачи с запуском! 🎰**


