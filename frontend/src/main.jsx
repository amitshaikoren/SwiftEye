import React from 'react';
import ReactDOM from 'react-dom/client';
import Plotly from 'plotly.js-dist';
import App from './App';
import './styles.css';

// Make Plotly available globally for chart components
window.Plotly = Plotly;

ReactDOM.createRoot(document.getElementById('root')).render(<App />);
