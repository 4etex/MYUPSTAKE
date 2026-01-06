# 🎰 MYUPSTAKE Casino - Деплой для Telegram Mini App

## 📦 Что нужно перед деплоем

1. ✅ Telegram бот создан в [@BotFather](https://t.me/BotFather)
2. ✅ Токен бота получен
3. ✅ GitHub аккаунт (для деплоя)

---

## 🚀 Быстрый старт (Railway - Рекомендуется)

### Шаг 1: Подготовка
```bash
# Генерация SECRET_KEY
node generate-secret.js
```

Скопируйте сгенерированный ключ!

### Шаг 2: GitHub
```bash
git init
git add .
git commit -m "Initial commit"
git remote add origin https://github.com/ваш_username/myupstake-casino.git
git push -u origin main
```

### Шаг 3: Railway
1. [railway.app](https://railway.app) → Login with GitHub
2. **New Project** → **Deploy from GitHub repo**
3. Выберите репозиторий
4. **Variables** → Добавьте:

```
TELEGRAM_BOT_TOKEN=ваш_токен
ADMIN_TELEGRAM_ID=8095351884
CRYPTO_BOT_TOKEN=497834:AA61moFx1FRYnPhY8sALPpQbcNNBr0EvZTA
SECRET_KEY=сгенерированный_ключ
ALLOWED_ORIGINS=https://your-app.up.railway.app,https://web.telegram.org
APP_URL=https://your-app.up.railway.app
MINI_APP_URL=https://your-app.up.railway.app
NODE_ENV=production
```

5. Скопируйте URL из Railway (например: `https://myupstake.up.railway.app`)

### Шаг 4: BotFather
1. [@BotFather](https://t.me/BotFather) → `/newapp`
2. Выберите бота
3. **Web App URL:** вставьте ваш Railway URL
4. **Short name:** myupstake

### Шаг 5: Обновите Railway
Вернитесь в Railway → Variables:
- Обновите `MINI_APP_URL` = ваш Railway URL
- Обновите `APP_URL` = ваш Railway URL
- Обновите `ALLOWED_ORIGINS` = добавьте ваш Railway URL

### Шаг 6: Redeploy
Railway → **Redeploy**

### Готово! 🎉
Откройте бота → `/start` → кнопка "🎮 ИГРАТЬ"

---

## 📋 Полная инструкция

Смотрите `DEPLOY.md` для детальной инструкции.

---

## 🔧 Локальная разработка

```bash
# Установка зависимостей
npm install

# Запуск сервера
npm run server

# Запуск фронтенда (в другом терминале)
npm start
```

Создайте `.env` файл с переменными из `env.example`

---

## 🐛 Проблемы?

### Socket.io не работает
- Railway/Render поддерживают WebSocket
- Vercel может не работать с Socket.io (используйте Railway)

### CORS ошибки
- Проверьте `ALLOWED_ORIGINS` - должен включать ваш домен
- Добавьте `https://web.telegram.org`

### Mini App не открывается
- Проверьте URL в BotFather
- Убедитесь что бот запущен
- Проверьте логи на сервере

---

## 📞 Поддержка

Проверьте логи в Railway/Render dashboard для диагностики.


