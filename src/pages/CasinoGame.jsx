import React, { useState, useEffect, useRef } from 'react';
import { io } from 'socket.io-client';
import './CasinoGame.css';
import DepositModal from '../components/DepositModal';
import WithdrawModal from '../components/WithdrawModal';

// Connect to backend Socket.io server
// В продакшене используем тот же домен, в разработке - localhost
const getBackendUrl = () => {
  if (process.env.NODE_ENV === 'production') {
    // В продакшене бэкенд на том же домене
    return window.location.origin;
  }
  return process.env.REACT_APP_BACKEND_URL || 'http://localhost:3001';
};

const BACKEND_URL = getBackendUrl();

const CasinoGame = () => {
  const [currentMultiplier, setCurrentMultiplier] = useState(1.0);
  const [balance, setBalance] = useState(1000);
  const [betAmount, setBetAmount] = useState(100);
  const [hasBet, setHasBet] = useState(false);
  const [currentBetAmount, setCurrentBetAmount] = useState(0);
  const [state, setState] = useState('idle');
  const [countdown, setCountdown] = useState(null);
  const [logs, setLogs] = useState([]);
  const [imageUrl, setImageUrl] = useState('https://customer-assets.emergentagent.com/job_tg-casino-fonts/artifacts/4jljl1tc_Original2-ezgif.com-gif-maker%20%281%29.gif');
  
  // Получаем userId из Telegram WebApp или генерируем
  const getUserId = () => {
    if (window.Telegram?.WebApp?.initDataUnsafe?.user?.id) {
      // Используем Telegram ID
      return String(window.Telegram.WebApp.initDataUnsafe.user.id);
    }
    // Fallback для разработки
    const stored = localStorage.getItem('casino_userId');
    if (stored) return stored;
    const newId = 'user_' + Math.random().toString(36).substr(2, 9);
    localStorage.setItem('casino_userId', newId);
    return newId;
  };
  
  const [userId] = useState(getUserId());
  const [onlineCount, setOnlineCount] = useState(2);
  
  // Auto cashout state
  const [autoCashoutEnabled, setAutoCashoutEnabled] = useState(false);
  const [autoCashoutAt, setAutoCashoutAt] = useState(2.0);
  const [hasAutoCashedOut, setHasAutoCashedOut] = useState(false);
  
  // Animation states
  const [isCrashed, setIsCrashed] = useState(false);
  const [isWon, setIsWon] = useState(false);
  const [showCrashText, setShowCrashText] = useState(false);
  
  // Next round bet (bet during playing phase)
  const [nextRoundBet, setNextRoundBet] = useState(null);
  
  // Crash history
  const [crashHistory, setCrashHistory] = useState([]);
  
  // Deposit modal
  const [showDepositModal, setShowDepositModal] = useState(false);
  
  // Withdraw modal
  const [showWithdrawModal, setShowWithdrawModal] = useState(false);
  
  const socketRef = useRef(null);
  const countdownTimerRef = useRef(null);
  
  const IMAGE_URLS = {
    heart: 'https://customer-assets.emergentagent.com/job_tg-casino-fonts/artifacts/4jljl1tc_Original2-ezgif.com-gif-maker%20%281%29.gif',
    gift: 'https://customer-assets.emergentagent.com/job_tg-casino-fonts/artifacts/yrev3x42_Original3-ezgif.com-gif-maker.gif',
    bear: 'https://customer-assets.emergentagent.com/job_5447c050-b077-4c8d-9ea0-f7a95aed1df4/artifacts/pik42j5o_Original1-ezgif.com-gif-maker%20%281%29.gif',
    rocket: 'https://customer-assets.emergentagent.com/job_0e0ff2d8-721e-45b2-a598-ac01f6bf2aea/artifacts/4rkonu6u_Original2-ezgif.com-gif-maker.gif'
  };

  // Add log
  const addLog = (text) => {
    const timestamp = new Date().toLocaleTimeString('ru-RU');
    setLogs(prev => [{ text, timestamp, id: Date.now() }, ...prev.slice(0, 9)]);
  };

  // Update image based on multiplier
  const updateImage = (mult) => {
    let selected = IMAGE_URLS.heart;
    
    if (mult >= 6) {
      selected = IMAGE_URLS.rocket;
    } else if (mult >= 4) {
      selected = IMAGE_URLS.bear;
    } else if (mult >= 2) {
      selected = IMAGE_URLS.gift;
    }
    
    if (imageUrl !== selected) {
      setImageUrl(selected);
    }
  };

  // Инициализация Telegram WebApp
  useEffect(() => {
    if (window.Telegram?.WebApp) {
      const tg = window.Telegram.WebApp;
      tg.ready();
      tg.expand(); // Разворачиваем на весь экран
      
      // Настраиваем тему
      if (tg.colorScheme === 'dark') {
        document.documentElement.style.backgroundColor = '#000000';
      }
      
      // Показываем главную кнопку (опционально)
      // tg.MainButton.setText('Играть');
      // tg.MainButton.show();
    }
  }, []);

  // Socket.io event handlers
  useEffect(() => {
    // Initialize socket с правильным URL
    const socketUrl = BACKEND_URL;
    socketRef.current = io(socketUrl, {
      transports: ['websocket', 'polling'],
      reconnection: true,
      reconnectionDelay: 1000,
      reconnectionAttempts: 5
    });
    const socket = socketRef.current;

    // Connection
    socket.on('connect', () => {
      addLog('✓ Подключено к серверу');
    });

    socket.on('disconnect', () => {
      addLog('⚠️ Отключено от сервера');
    });

    socket.on('connect_error', (error) => {
      console.error('Socket connection error:', error);
      addLog('❌ Ошибка подключения к серверу');
    });

    socket.on('error', (error) => {
      console.error('Socket error:', error);
      addLog('❌ Ошибка соединения');
    });

    // Получение текущего состояния при подключении
    socket.on('state', (data) => {
      console.log('Received state:', data);
      setState(data.state);
      
      if (data.round) {
        setCurrentMultiplier(data.round.multiplier || 1.0);
        
        if (data.state === 'betting' && data.round.bettingTimeLeft > 0) {
          // Восстанавливаем таймер для фазы ставок
          setCountdown(data.round.bettingTimeLeft);
          
          // Очищаем предыдущий таймер
          if (countdownTimerRef.current) {
            clearInterval(countdownTimerRef.current);
          }
          
          // Запускаем таймер с оставшимся временем
          let sec = data.round.bettingTimeLeft;
          countdownTimerRef.current = setInterval(() => {
            sec--;
            if (sec <= 0) {
              clearInterval(countdownTimerRef.current);
              setCountdown(null);
              countdownTimerRef.current = null;
            } else {
              setCountdown(sec);
            }
          }, 1000);
          
          addLog(`🎲 Фаза ставок (осталось ${data.round.bettingTimeLeft}с)`);
        } else if (data.state === 'playing') {
          setCountdown(null);
          if (countdownTimerRef.current) {
            clearInterval(countdownTimerRef.current);
            countdownTimerRef.current = null;
          }
          addLog(`🚀 Раунд уже идет`);
        } else {
          setCountdown(null);
        }
      } else {
        setCountdown(null);
      }
    });

    // Online count update
    socket.on('onlineCount', (data) => {
      setOnlineCount(data.count);
    });

    // Payment completed notification
    socket.on('paymentCompleted', (data) => {
      if (data.oddserId === userId) {
        addLog(`💎 Пополнение: +${data.stars}⭐`);
        // Обновляем баланс
        fetch(`${BACKEND_URL}/api/balance/${userId}`)
          .then(response => response.json())
          .then(balData => setBalance(balData.balance))
          .catch(er => console.error(er));
      }
    });

    // Round start
    socket.on('roundStart', (data) => {
      setState('betting');
      setHasBet(false);
      setCurrentBetAmount(0);
      setCurrentMultiplier(1.0);
      setImageUrl(IMAGE_URLS.heart);
      setHasAutoCashedOut(false);
      setIsCrashed(false);
      setIsWon(false);
      setShowCrashText(false);
      addLog('🎲 Новый раунд — окно ставок');
      
      // Countdown
      const bettingTime = data.bettingTime || 10;
      setCountdown(bettingTime);
      
      if (countdownTimerRef.current) {
        clearInterval(countdownTimerRef.current);
      }
      
      let sec = bettingTime;
      countdownTimerRef.current = setInterval(() => {
        sec--;
        if (sec <= 0) {
          clearInterval(countdownTimerRef.current);
          setCountdown(null);
          countdownTimerRef.current = null;
        } else {
          setCountdown(sec);
        }
      }, 1000);
    });

    // Round play
    socket.on('roundPlay', () => {
      setState('playing');
      setCountdown(null);
      addLog('🚀 Раунд начался');
    });

    // Multiplier update + Auto cashout
    socket.on('multiplier', (data) => {
      const mult = parseFloat(data.multiplier);
      setCurrentMultiplier(mult);
      updateImage(mult);
    });

    // Round end with crash animation
    socket.on('roundEnd', (data) => {
      addLog(`💥 Раунд завершен (краш ${data.crashAt}x)`);
      setState('idle');
      setCurrentMultiplier(data.crashAt);
      
      // Add to crash history
      setCrashHistory(prev => [data.crashAt, ...prev].slice(0, 15));
      
      // Trigger crash animation
      setIsCrashed(true);
      setShowCrashText(true);
      
      setHasBet(false);
      setCurrentBetAmount(0);
      
      // Reset animations after delay
      setTimeout(() => {
        setIsCrashed(false);
        setShowCrashText(false);
        setCurrentMultiplier(1.0);
        setImageUrl(IMAGE_URLS.heart);
      }, 2500);
    });

    // Bet result
    socket.on('betResult', async (result) => {
      console.log('betResult received:', result);
      if (result.ok) {
        addLog('✅ Ставка принята');
        setHasBet(true);
        setCurrentBetAmount(result.bet.amount);
        setHasAutoCashedOut(false); // Reset for new bet
        // Fetch updated balance
        try {
          const response = await fetch(`${BACKEND_URL}/api/balance/${userId}`);
          const data = await response.json();
          setBalance(data.balance);
        } catch (e) {
          console.error('Balance fetch error:', e);
          // Пробуем получить баланс из ответа если есть
          if (result.bet && result.bet.balance !== undefined) {
            setBalance(result.bet.balance);
          }
        }
      } else {
        addLog('❌ Ставка отклонена: ' + (result.reason || 'Неизвестная ошибка'));
      }
    });

    // Cashout result with win animation
    socket.on('cashoutResult', async (result) => {
      if (result.ok) {
        addLog(`💰 Вывод +${result.payout}`);
        setHasBet(false);
        setCurrentBetAmount(0);
        
        // Trigger win animation
        setIsWon(true);
        setTimeout(() => setIsWon(false), 1500);
        
        // Fetch updated balance
        try {
          const response = await fetch(`${BACKEND_URL}/api/balance/${userId}`);
          const data = await response.json();
          setBalance(data.balance);
        } catch (e) {
          console.error('Balance fetch error:', e);
        }
      } else {
        addLog('⚠️ Вывод не удался');
      }
    });

    // Initial balance fetch
    fetch(`${BACKEND_URL}/api/balance/${userId}`)
      .then(res => res.json())
      .then(data => setBalance(data.balance))
      .catch(err => console.error('Initial balance fetch error:', err));

    addLog('🎮 MYUPSTAKE запущен');

    // Cleanup
    return () => {
      if (countdownTimerRef.current) {
        clearInterval(countdownTimerRef.current);
      }
      if (socketRef.current) {
        socketRef.current.disconnect();
      }
    };
  }, [userId]);

  // Auto cashout effect
  useEffect(() => {
    if (
      autoCashoutEnabled &&
      hasBet &&
      !hasAutoCashedOut &&
      state === 'playing' &&
      currentMultiplier >= autoCashoutAt &&
      socketRef.current
    ) {
      // Auto cashout triggered!
      socketRef.current.emit('cashout', { userId });
      setHasAutoCashedOut(true);
      addLog(`🤖 Автовывод на ${autoCashoutAt}x`);
    }
  }, [currentMultiplier, autoCashoutEnabled, autoCashoutAt, hasBet, hasAutoCashedOut, state, userId]);

  // Place bet
  const handlePlaceBet = () => {
    if (!socketRef.current || !socketRef.current.connected) {
      addLog('⚠️ Нет подключения к серверу');
      return;
    }
    
    if (betAmount <= 0 || betAmount > balance) {
      addLog('⚠️ Некорректная сумма ставки');
      return;
    }
    
    // If game is playing, queue bet for next round
    if (state === 'playing' || state === 'idle') {
      setNextRoundBet(betAmount);
      addLog(`⏳ Ставка ${betAmount} поставлена на следующий раунд`);
      return;
    }
    
    if (state === 'betting') {
      socketRef.current.emit('placeBet', { userId, amount: betAmount });
    }
  };
  
  // Effect to place queued bet when new round starts
  useEffect(() => {
    if (state === 'betting' && nextRoundBet && socketRef.current) {
      socketRef.current.emit('placeBet', { userId, amount: nextRoundBet });
      addLog(`🎯 Автоставка ${nextRoundBet} размещена`);
      setNextRoundBet(null);
    }
  }, [state, nextRoundBet, userId]);

  // Cashout
  const handleCashout = () => {
    if (!hasBet || state !== 'playing') {
      addLog('⚠️ Вывод невозможен');
      return;
    }
    if (socketRef.current) {
      socketRef.current.emit('cashout', { userId });
    }
  };

  // Quick bet amounts
  const quickBets = [50, 100, 250, 500, 1000];

  // Get multiplier color class
  const getMultiplierClass = () => {
    if (isCrashed) return 'crashed';
    if (isWon) return 'won';
    if (currentMultiplier >= 5) return 'extreme';
    if (currentMultiplier >= 3) return 'high';
    if (currentMultiplier >= 2) return 'medium';
    return 'low';
  };

  // Get crash history item color
  const getCrashColor = (value) => {
    if (value >= 10) return '#ff3366'; // pink/red for 10x+
    if (value >= 5) return '#ff9500';  // orange for 5x+
    if (value >= 2) return '#00ff88';  // green for 2x+
    return '#888888';                   // gray for low
  };

  // Main action button handler
  const handleMainAction = () => {
    if (hasBet && state === 'playing') {
      handleCashout();
    } else {
      handlePlaceBet();
    }
  };

  // Format balance (round to integer, handle NaN)
  const formatBalance = (val) => {
    if (val === null || val === undefined || isNaN(val)) return 0;
    return Math.round(val);
  };

  return (
    <div className="casino-app">
      {/* Header */}
      <header className="casino-header">
        <div className="header-top-row">
          <div className="logo">
            <div className="logo-icon">
              <img 
                src="https://customer-assets.emergentagent.com/job_tg-casino-fonts/artifacts/0txpkq2b_unnamed%20%2815%29%282%29.png" 
                alt="Logo" 
                style={{
                  width: '100%',
                  height: '100%',
                  objectFit: 'cover',
                  borderRadius: '8px'
                }}
              />
            </div>
            <span className="logo-text">MYUPSTAKE</span>
          </div>
          
          <div className="balance-container-top">
            <button 
              className="withdraw-btn-header"
              onClick={() => setShowWithdrawModal(true)}
            >
              ↑
            </button>
            <div className="balance">
              <span className="balance-amount">{formatBalance(balance)}</span>
              <span className="balance-currency">⭐</span>
            </div>
            <button 
              className="deposit-btn"
              onClick={() => setShowDepositModal(true)}
            >
              +
            </button>
          </div>
        </div>
        
        <div className="header-right">
          <div className="online-indicator-top">
            <span className="online-dot"></span>
            <span className="online-text">{onlineCount}</span>
          </div>
        </div>
      </header>

      {/* Deposit Modal */}
      <DepositModal 
        isOpen={showDepositModal}
        onClose={() => setShowDepositModal(false)}
        userId={userId}
        onBalanceUpdate={(newBalance) => setBalance(newBalance)}
      />
      
      {/* Withdraw Modal */}
      <WithdrawModal 
        isOpen={showWithdrawModal}
        onClose={() => setShowWithdrawModal(false)}
        userId={userId}
        balance={balance}
        onBalanceUpdate={(newBalance) => setBalance(newBalance)}
      />

      {/* Crash History Bar */}
      {crashHistory.length > 0 && (
        <div className="crash-history">
          {crashHistory.map((crash, index) => (
            <div 
              key={index} 
              className="crash-history-item"
              style={{ 
                background: `${getCrashColor(crash)}20`,
                borderColor: getCrashColor(crash),
                color: getCrashColor(crash)
              }}
            >
              {crash.toFixed(2)}x
            </div>
          ))}
        </div>
      )}

      {/* Main game stage */}
      <div className={`game-stage ${isCrashed ? 'crashed' : ''} ${isWon ? 'won' : ''}`}>
        <div className={`crash-overlay ${isCrashed ? 'active' : ''}`}></div>
        <div className={`crash-text ${showCrashText ? 'active' : ''}`}>CRASH!</div>
        
        <div className={`multiplier ${getMultiplierClass()}`}>
          {currentMultiplier.toFixed(2)}x
        </div>
        
        {countdown !== null && (
          <div className="countdown">Ставки: {countdown}с</div>
        )}
        
        {nextRoundBet && (
          <div className="next-round-badge">
            ⏳ Ставка {nextRoundBet} на след. раунд
          </div>
        )}
        
        <div className="center-visual">
          <div className={`image-circle ${isCrashed ? 'crashed' : ''}`}>
            <img src={imageUrl} alt="Casino" />
          </div>
        </div>
      </div>

      {/* Betting controls */}
      <div className="controls">
        <div className="input-wrapper">
          <label className="input-label">СУММА СТАВКИ</label>
          <input
            type="number"
            className="bet-input"
            value={betAmount}
            onChange={(e) => setBetAmount(Number(e.target.value))}
            min="1"
          />
        </div>
        
        {/* ONE BIG ACTION BUTTON - под суммой ставки */}
        <button 
          className={`main-action-btn ${hasBet && state === 'playing' ? 'cashout' : 'bet'} ${nextRoundBet ? 'queued' : ''}`}
          onClick={handleMainAction}
          disabled={hasBet && state !== 'playing'}
        >
          {hasBet && state === 'playing' ? (
            <>
              <span className="btn-text">ЗАБРАТЬ</span>
              <span className="btn-amount">{Math.round((currentBetAmount || 0) * (currentMultiplier || 1))}</span>
            </>
          ) : nextRoundBet ? (
            <span className="btn-text">СТАВКА В ОЧЕРЕДИ ({nextRoundBet})</span>
          ) : hasBet ? (
            <span className="btn-text">ЖДЁМ РАУНД...</span>
          ) : (
            <span className="btn-text">ПОСТАВИТЬ</span>
          )}
        </button>
        
        {/* Quick bet buttons */}
        <div className="quick-bets">
          {quickBets.map((amount) => (
            <button
              key={amount}
              className="quick-bet-btn"
              onClick={() => setBetAmount(amount)}
            >
              {amount}
            </button>
          ))}
        </div>
        
        {/* Auto Cashout */}
        <div className="auto-cashout">
          <button
            className={`auto-cashout-toggle ${autoCashoutEnabled ? 'active' : ''}`}
            onClick={() => setAutoCashoutEnabled(!autoCashoutEnabled)}
          />
          <span className={`auto-cashout-label ${autoCashoutEnabled ? 'active' : ''}`}>
            Авто
          </span>
          <input
            type="number"
            className={`auto-cashout-input ${autoCashoutEnabled ? 'active' : ''}`}
            value={autoCashoutAt}
            onChange={(e) => setAutoCashoutAt(Math.max(1.01, Number(e.target.value)))}
            min="1.01"
            step="0.1"
            disabled={!autoCashoutEnabled}
          />
          <span className="auto-cashout-suffix">x</span>
          <div className="quick-multipliers">
            {[1.5, 2, 3, 5].map((mult) => (
              <button
                key={mult}
                className={`quick-mult-btn ${autoCashoutAt === mult ? 'active' : ''}`}
                onClick={() => {
                  setAutoCashoutAt(mult);
                  setAutoCashoutEnabled(true);
                }}
              >
                {mult}x
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Log section */}
      <div className="log-container">
        <div className="log-header">ИСТОРИЯ</div>
        <div className="log">
          {logs.map((log) => (
            <div key={log.id}>
              [{log.timestamp}] {log.text}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

export default CasinoGame;