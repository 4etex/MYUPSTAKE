# ⚡ Быстрый деплой на Railway (Рекомендуется)

Railway идеально подходит для Socket.io и Node.js приложений.

## 🚀 Шаги деплоя (5 минут)

### 1. Подготовка репозитория
```bash
cd D:\casino
git init
git add .
git commit -m "Initial commit"
```

### 2. Создайте репозиторий на GitHub
1. Зайдите на [github.com](https://github.com)
2. New repository → `myupstake-casino`
3. Скопируйте команды для push

```bash
git remote add origin https://github.com/ваш_username/myupstake-casino.git
git branch -M main
git push -u origin main
```

### 3. Деплой на Railway
1. Зайдите на [railway.app](https://railway.app)
2. Login with GitHub
3. **New Project** → **Deploy from GitHub repo**
4. Выберите `myupstake-casino`
5. Railway автоматически определит проект

### 4. Настройка переменных
1. Откройте проект → **Variables**
2. Добавьте все переменные:

```
TELEGRAM_BOT_TOKEN=ваш_токен_от_botfather
ADMIN_TELEGRAM_ID=8095351884
CRYPTO_BOT_TOKEN=497834:AA61moFx1FRYnPhY8sALPpQbcNNBr0EvZTA
SECRET_KEY=сгенерируйте_32_символа_случайно
ALLOWED_ORIGINS=https://your-app.up.railway.app,https://web.telegram.org
APP_URL=https://your-app.up.railway.app
MINI_APP_URL=https://your-app.up.railway.app
NODE_ENV=production
PORT=3001
```

**Генерация SECRET_KEY:**
```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

### 5. Получите URL
После деплоя Railway даст вам URL вида:
`https://myupstake-casino-production.up.railway.app`

Скопируйте этот URL!

### 6. Настройка BotFather
1. Откройте [@BotFather](https://t.me/BotFather)
2. `/newapp` → выберите вашего бота
3. Укажите:
   - **Name:** MYUPSTAKE Casino
   - **Web App URL:** `https://myupstake-casino-production.up.railway.app`
   - **Short name:** myupstake

### 7. Обновите переменные в Railway
Вернитесь в Railway → Variables и обновите:
- `MINI_APP_URL` = ваш Railway URL
- `APP_URL` = ваш Railway URL
- `ALLOWED_ORIGINS` = добавьте ваш Railway URL

### 8. Перезапустите
Railway → Deployments → три точки → **Redeploy**

### 9. Проверка
1. Откройте вашего бота в Telegram
2. `/start` → должна быть кнопка "🎮 ИГРАТЬ"
3. Нажмите → должна открыться игра!

---

## 🎯 Альтернатива: Render.com

Если Railway не подходит:

1. Зайдите на [render.com](https://render.com)
2. **New** → **Web Service**
3. Connect GitHub → выберите репозиторий
4. Настройки:
   - **Name:** myupstake-casino
   - **Environment:** Node
   - **Build Command:** `npm install && npm run build`
   - **Start Command:** `node index.js`
5. Добавьте переменные окружения
6. **Create Web Service**

---

## ✅ Готово!

Ваше приложение должно работать! 🎉

**Проверьте:**
- [ ] Бот отвечает на `/start`
- [ ] Кнопка "ИГРАТЬ" появляется
- [ ] Mini App открывается
- [ ] Игра загружается
- [ ] Ставки работают

**Проблемы?** Смотрите логи в Railway/Render dashboard.


