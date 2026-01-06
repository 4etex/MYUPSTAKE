import React, { useState, useEffect } from 'react';
import './App.css';
import LoadingSpinner from './components/LoadingSpinner';
import CasinoGame from './pages/CasinoGame';

function App() {
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Hide loading screen after 2.5 seconds
    const timer = setTimeout(() => {
      setLoading(false);
    }, 2500);

    return () => clearTimeout(timer);
  }, []);

  return (
    <div className="App">
      {loading && <LoadingSpinner />}
      <CasinoGame />
    </div>
  );
}

export default App;