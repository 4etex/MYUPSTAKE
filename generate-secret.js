// Генератор SECRET_KEY для .env
const crypto = require('crypto');
const secret = crypto.randomBytes(32).toString('hex');
console.log('\n🔐 Сгенерированный SECRET_KEY:\n');
console.log(secret);
console.log('\n📋 Добавьте в .env:\n');
console.log(`SECRET_KEY=${secret}\n`);


