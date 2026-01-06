import React, { useState, useEffect } from 'react';
import './WithdrawModal.css';

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL || 'http://localhost:3001';

const WithdrawModal = ({ isOpen, onClose, userId, balance, onBalanceUpdate }) => {
  const [amount, setAmount] = useState('');
  const [walletAddress, setWalletAddress] = useState('');
  const [method, setMethod] = useState('TON');
  const [loading, setLoading] = useState(false);
  const [withdrawals, setWithdrawals] = useState([]);
  const [activeTab, setActiveTab] = useState('new'); // 'new' or 'history'

  // Загружаем историю выводов
  useEffect(() => {
    if (isOpen && userId) {
      fetch(`${BACKEND_URL}/api/withdraw/status/${userId}`)
        .then(res => res.json())
        .then(data => {
          if (data.ok) setWithdrawals(data.withdrawals || []);
        })
        .catch(console.error);
    }
  }, [isOpen, userId]);

  const handleWithdraw = async () => {
    if (!amount || !walletAddress) {
      alert('Заполните все поля');
      return;
    }
    
    const amt = parseFloat(amount);
    if (amt < 100) {
      alert('Минимальная сумма вывода: 100 ⭐');
      return;
    }
    
    if (amt > balance) {
      alert('Недостаточно средств');
      return;
    }
    
    setLoading(true);
    try {
      const res = await fetch(`${BACKEND_URL}/api/withdraw/request`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          userId,
          amount: amt,
          walletAddress,
          method
        })
      });
      
      const data = await res.json();
      
      if (data.ok) {
        alert('✅ ' + data.message);
        setAmount('');
        setWalletAddress('');
        if (onBalanceUpdate) onBalanceUpdate(balance - amt);
        setActiveTab('history');
        // Обновляем историю
        fetch(`${BACKEND_URL}/api/withdraw/status/${userId}`)
          .then(r => r.json())
          .then(d => { if (d.ok) setWithdrawals(d.withdrawals || []); });
      } else {
        alert('❌ ' + (data.error || 'Ошибка'));
      }
    } catch (err) {
      console.error(err);
      alert('Ошибка соединения');
    }
    setLoading(false);
  };

  const getStatusBadge = (status) => {
    switch (status) {
      case 'pending': return <span className="status-badge pending">⏳ Ожидает</span>;
      case 'approved': return <span className="status-badge approved">✅ Одобрено</span>;
      case 'rejected': return <span className="status-badge rejected">❌ Отклонено</span>;
      default: return <span className="status-badge">{status}</span>;
    }
  };

  if (!isOpen) return null;

  return (
    <div className="withdraw-overlay" onClick={onClose}>
      <div className="withdraw-modal" onClick={e => e.stopPropagation()}>
        <div className="withdraw-header">
          <h2>💸 Вывод средств</h2>
          <button className="close-btn" onClick={onClose}>✕</button>
        </div>

        {/* Tabs */}
        <div className="withdraw-tabs">
          <button 
            className={`tab-btn ${activeTab === 'new' ? 'active' : ''}`}
            onClick={() => setActiveTab('new')}
          >
            Новый вывод
          </button>
          <button 
            className={`tab-btn ${activeTab === 'history' ? 'active' : ''}`}
            onClick={() => setActiveTab('history')}
          >
            История
          </button>
        </div>

        {activeTab === 'new' ? (
          <div className="withdraw-form">
            <div className="balance-info">
              <span>Доступно:</span>
              <span className="balance-value">{Math.round(balance)} ⭐</span>
            </div>

            <div className="form-group">
              <label>Сумма вывода</label>
              <input
                type="number"
                value={amount}
                onChange={(e) => setAmount(e.target.value)}
                placeholder="Минимум 100"
                min="100"
              />
            </div>

            <div className="form-group">
              <label>Метод вывода</label>
              <div className="method-buttons">
                <button 
                  className={`method-btn ${method === 'TON' ? 'active' : ''}`}
                  onClick={() => setMethod('TON')}
                >
                  💎 TON
                </button>
                <button 
                  className={`method-btn ${method === 'USDT' ? 'active' : ''}`}
                  onClick={() => setMethod('USDT')}
                >
                  💵 USDT
                </button>
              </div>
            </div>

            <div className="form-group">
              <label>Адрес кошелька ({method})</label>
              <input
                type="text"
                value={walletAddress}
                onChange={(e) => setWalletAddress(e.target.value)}
                placeholder={method === 'TON' ? 'UQ...' : '0x... или TRC20'}
              />
            </div>

            <div className="withdraw-info">
              <p>⏱ Обработка в течение 24 часов</p>
              <p>💰 Минимум: 100 ⭐</p>
              <p>📊 Курс: 100 ⭐ ≈ 0.15 {method}</p>
            </div>

            <button 
              className="withdraw-btn"
              onClick={handleWithdraw}
              disabled={loading || !amount || !walletAddress}
            >
              {loading ? 'Отправка...' : 'Запросить вывод'}
            </button>
          </div>
        ) : (
          <div className="withdraw-history">
            {withdrawals.length === 0 ? (
              <div className="empty-history">
                <p>📋 История выводов пуста</p>
              </div>
            ) : (
              withdrawals.map((w, idx) => (
                <div key={idx} className="history-item">
                  <div className="history-main">
                    <span className="history-amount">{w.amount} ⭐</span>
                    {getStatusBadge(w.status)}
                  </div>
                  <div className="history-details">
                    <span>{w.method} → {w.walletAddress?.slice(0, 15)}...</span>
                    <span>{new Date(w.createdAt).toLocaleDateString()}</span>
                  </div>
                </div>
              ))
            )}
          </div>
        )}
      </div>
    </div>
  );
};

export default WithdrawModal;

