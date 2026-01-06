import React from 'react';
import './LoadingSpinner.css';

const LoadingSpinner = () => {
  return (
    <div className="loading-screen">
      <div className="spinner-container">
        <svg viewBox="25 25 50 50" className="loading-spinner">
          <circle r="20" cy="50" cx="50"></circle>
        </svg>
        <p className="loading-text">MYUPSTAKE</p>
      </div>
    </div>
  );
};

export default LoadingSpinner;