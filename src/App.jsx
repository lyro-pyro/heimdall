import { useState } from 'react';
import InputPanel from './components/InputPanel';
import LogViewer from './components/LogViewer';
import InsightsPanel from './components/InsightsPanel';
import ResultDisplay from './components/ResultDisplay';
import IocPanel from './components/IocPanel';
import { analyzeContent } from './services/api';

export default function App() {
  const [result, setResult] = useState(null);
  const [inputContent, setInputContent] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');

  const handleAnalyze = async (payload) => {
    setIsLoading(true);
    setError('');
    setResult(null);
    setInputContent(payload.content);

    try {
      const data = await analyzeContent(payload);
      setResult(data);
    } catch (err) {
      setError(err.message || 'ANALYSIS_ERR:// FAILED');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="app-container">
      {/* Retrowave Top Navbar */}
      <header className="top-navbar">
        <div className="crosshair-corners"></div>
        <div className="micro-data">
          <span>SRC: 11-2A</span>
          <span className="hl">LATENCY: 14ms</span>
        </div>
        
        <div className="navbar-logo" style={{ position: 'absolute', left: '50%', transform: 'translateX(-50%)', top: '16px' }}>
          <h1 style={{ 
            fontFamily: '"Orbitron", "Share Tech Mono", monospace', 
            fontWeight: 700,
            fontSize: '28px',
            color: 'var(--accent-orange)',
            textShadow: '0 0 8px rgba(255, 77, 41, 0.6), 0 0 16px rgba(255, 77, 41, 0.2)',
            letterSpacing: '0.2em',
            margin: 0
          }}>
            HEIMDALL
          </h1>
        </div>

        <div className="system-status">
          <span>[ ONLINE ]</span>
          <div className="status-blip"></div>
        </div>
      </header>

      {/* Grid Layout */}
      <div className="dashboard-grid">
        
        {/* Left Column */}
        <aside className="sidebar-left">
          <div className="crosshair-corners"></div>
          <InputPanel
            onAnalyze={handleAnalyze}
            isLoading={isLoading}
          />
        </aside>

        {/* Center Column — Telemetry, Registry, Debug */}
        <main className="main-content">
          <div className="crosshair-corners"></div>
          
          {error && (
            <div className="empty-state">
              <span className="cyber-loader">!</span>
              <h3 style={{ color: 'var(--accent-orange)' }}>CRITICAL EXCEPTION</h3>
              <p>{error}</p>
            </div>
          )}

          {!result && !isLoading && !error && (
            <div className="empty-state">
              <span className="cyber-loader">_</span>
              <h3>AWAITING_INPUT</h3>
              <p>STANDBY MODE // PORT 025</p>
            </div>
          )}

          {isLoading && (
            <div className="empty-state">
              <span className="cyber-loader">▨</span>
              <h3>PROCESSING_DATA</h3>
              <p>CHECKSUM: EVALUATING...</p>
            </div>
          )}

          {result && (
            <>
              <InsightsPanel data={result} />
              <IocPanel iocs={result.iocs} />
              <ResultDisplay data={result} />
            </>
          )}
        </main>

        {/* Right Column — Log Monitor */}
        <aside className="sidebar-right">
          <div className="crosshair-corners"></div>

          <div className="panel-header" style={{ marginBottom: '16px', background: 'transparent', border: 'none', padding: 0 }}>
            <span>[ LOG_MONITOR ] // CORE.BIN</span>
            <span className="deco">SYS-OK</span>
          </div>

          {!result && !isLoading && !error && (
            <div className="sidebar-placeholder">
              [ NO_DATA ]<br />AWAITING SYNCHRONIZATION
            </div>
          )}
          
          {result && (
            <LogViewer
              content={inputContent}
              findings={result.findings}
            />
          )}
        </aside>

      </div>
    </div>
  );
}
