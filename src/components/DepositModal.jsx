import React, { useState, useEffect } from 'react';
import './DepositModal.css';

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL || 'http://localhost:3001';

const DepositModal = ({ isOpen, onClose, userId, onBalanceUpdate }) => {
  const [packages, setPackages] = useState([]);
  const [selectedPackage, setSelectedPackage] = useState(null);
  const [paymentMethod, setPaymentMethod] = useState('crypto'); // 'crypto' or 'stars'
  const [loading, setLoading] = useState(false);
  const [pendingInvoice, setPendingInvoice] = useState(null);

  // Загружаем пакеты при открытии
  useEffect(() => {
    if (isOpen) {
      fetch(`${BACKEND_URL}/api/deposit/packages`)
        .then(res => res.json())
        .then(data => setPackages(data.packages || []))
        .catch(err => console.error('Failed to load packages:', err));
    }
  }, [isOpen]);

  // Проверяем статус платежа
  useEffect(() => {
    if (!pendingInvoice) return;
    
    const checkStatus = async () => {
      try {
        const res = await fetch(`${BACKEND_URL}/api/deposit/status/${pendingInvoice}`);
        const data = await res.json();
        
        if (data.status === 'completed') {
          setPendingInvoice(null);
          setLoading(false);
          if (onBalanceUpdate) onBalanceUpdate(data.newBalance);
          onClose();
          alert(`✅ Успешно! +${data.stars} ⭐ зачислено на баланс!`);
        }
      } catch (err) {
        console.error('Status check error:', err);
      }
    };
    
    const interval = setInterval(checkStatus, 3000);
    return () => clearInterval(interval);
  }, [pendingInvoice, onBalanceUpdate, onClose]);

  const handleCryptoPayment = async (pkg) => {
    setLoading(true);
    try {
      const res = await fetch(`${BACKEND_URL}/api/deposit/crypto`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ userId, packageId: pkg.id })
      });
      
      const data = await res.json();
      
      if (data.ok) {
        setPendingInvoice(data.invoiceId);
        // Открываем ссылку на оплату
        window.open(data.payUrl, '_blank');
      } else {
        alert('Ошибка создания платежа: ' + (data.error || 'Unknown'));
        setLoading(false);
      }
    } catch (err) {
      console.error('Payment error:', err);
      alert('Ошибка подключения к серверу');
      setLoading(false);
    }
  };

  const handleStarsPayment = async (pkg) => {
    // Telegram Stars оплата через WebApp API
    if (!window.Telegram?.WebApp) {
      alert('Telegram Stars доступны только в Telegram приложении');
      return;
    }
    
    setLoading(true);
    try {
      const res = await fetch(`${BACKEND_URL}/api/deposit/stars`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ userId, packageId: pkg.id })
      });
      
      const data = await res.json();
      
      if (data.ok) {
        // Создаём инвойс для Telegram Stars
        const invoice = {
          title: data.title,
          description: data.description,
          currency: 'XTR', // Telegram Stars
          prices: data.prices,
          payload: data.payload
        };
        
        // Открываем инвойс через Telegram WebApp
        window.Telegram.WebApp.openInvoice(invoice, (status) => {
          if (status === 'paid') {
            // Получаем payment info
            const paymentInfo = window.Telegram.WebApp.paymentInfo;
            
            // Подтверждаем оплату
            fetch(`${BACKEND_URL}/api/deposit/stars/confirm`, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ 
                userId, 
                invoiceId: data.invoiceId,
                telegramPaymentId: paymentInfo?.payment_id || 'webapp_payment'
              })
            }).then(res => res.json()).then(confirmData => {
              if (confirmData.ok) {
                if (onBalanceUpdate) onBalanceUpdate(confirmData.newBalance);
                window.Telegram.WebApp.showAlert(`✅ Успешно! +${confirmData.stars} ⭐ зачислено!`);
              } else {
                window.Telegram.WebApp.showAlert('Ошибка подтверждения: ' + confirmData.error);
              }
              setLoading(false);
              onClose();
            }).catch(err => {
              console.error('Confirm error:', err);
              window.Telegram.WebApp.showAlert('Ошибка соединения');
              setLoading(false);
            });
          } else {
            setLoading(false);
          }
        });
      } else {
        alert('Ошибка: ' + data.error);
        setLoading(false);
      }
    } catch (err) {
      console.error('Stars payment error:', err);
      alert('Ошибка соединения');
      setLoading(false);
    }
  };

  const handlePayment = (pkg) => {
    if (paymentMethod === 'crypto') {
      handleCryptoPayment(pkg);
    } else {
      handleStarsPayment(pkg);
    }
  };

  if (!isOpen) return null;

  return (
    <div className="deposit-overlay" onClick={onClose}>
      <div className="deposit-modal" onClick={e => e.stopPropagation()}>
        <div className="deposit-header">
          <h2>💎 Пополнение баланса</h2>
          <button className="close-btn" onClick={onClose}>✕</button>
        </div>

        {/* Выбор метода оплаты */}
        <div className="payment-methods">
          <button 
            className={`method-btn ${paymentMethod === 'crypto' ? 'active' : ''}`}
            onClick={() => setPaymentMethod('crypto')}
          >
            <span className="method-icon">💎</span>
            <span className="method-name">Crypto Bot</span>
            <span className="method-desc">TON, BTC, ETH</span>
          </button>
          <button 
            className={`method-btn ${paymentMethod === 'stars' ? 'active' : ''}`}
            onClick={() => setPaymentMethod('stars')}
          >
            <span className="method-icon">⭐</span>
            <span className="method-name">Telegram Stars</span>
            <span className="method-desc">Apple Pay, Google Pay</span>
          </button>
        </div>

        {/* Список пакетов */}
        <div className="packages-list">
          {packages.map((pkg) => (
            <div 
              key={pkg.id} 
              className={`package-item ${selectedPackage?.id === pkg.id ? 'selected' : ''}`}
              onClick={() => setSelectedPackage(pkg)}
            >
              <div className="package-stars">
                <span className="stars-amount">{pkg.stars.toLocaleString()}</span>
                <span className="stars-icon">⭐</span>
                <span className="bonus-badge">+{pkg.bonus}</span>
              </div>
              <div className="package-price">
                {paymentMethod === 'crypto' ? (
                  <span className="price-ton">{pkg.ton} TON</span>
                ) : (
                  <span className="price-usd">${pkg.usd}</span>
                )}
              </div>
            </div>
          ))}
        </div>

        {/* Кнопка оплаты */}
        {selectedPackage && (
          <button 
            className="pay-btn"
            onClick={() => handlePayment(selectedPackage)}
            disabled={loading}
          >
            {loading ? (
              <span className="loading-text">Ожидание оплаты...</span>
            ) : (
              <>
                <span>Оплатить</span>
                <span className="pay-amount">
                  {paymentMethod === 'crypto' 
                    ? `${selectedPackage.ton} TON` 
                    : `$${selectedPackage.usd}`
                  }
                </span>
              </>
            )}
          </button>
        )}

        {pendingInvoice && (
          <div className="pending-notice">
            <div className="pending-spinner"></div>
            <p>Ожидание подтверждения оплаты...</p>
            <p className="pending-hint">Завершите оплату в открывшемся окне</p>
          </div>
        )}
      </div>
    </div>
  );
};

export default DepositModal;

