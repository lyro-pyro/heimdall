import { useState, useRef } from 'react';

const INPUT_TYPES = [
  { key: 'log', label: 'LOG.BIN', desc: 'Process log chunks' },
  { key: 'text', label: 'TXT.RAW', desc: 'Process plain text' },
  { key: 'file', label: 'FILE.SYS', desc: 'Ingest payload file' },
  { key: 'sql', label: 'DB.QUERY', desc: 'Analyze SQL injection' },
  { key: 'chat', label: 'COM.LINK', desc: 'Analyze packet logs' },
];

export default function InputPanel({ onAnalyze, isLoading }) {
  const [inputType, setInputType] = useState('log');
  const [content, setContent] = useState('');
  const [options, setOptions] = useState({ mask: true, block_high_risk: true, log_analysis: true });
  const fileInputRef = useRef(null);

  const handleSubmit = () => {
    if (!content.trim()) return;
    onAnalyze({ input_type: inputType, content, options });
  };

  const toggleOption = (key) => setOptions((p) => ({ ...p, [key]: !p[key] }));

  return (
    <div className="input-panel">
      <div className="panel-header" style={{ marginBottom: '24px', background: 'transparent', border: 'none', padding: 0 }}>
        <span>[ IO_ROUTING ]</span>
        <span className="deco">PORT_07</span>
      </div>

      <div className="type-selector">
        {INPUT_TYPES.map((t) => (
          <button
            key={t.key}
            className={`type-btn ${inputType === t.key ? 'active' : ''}`}
            onClick={() => setInputType(t.key)}
          >
            {t.label}
          </button>
        ))}
      </div>

      {(inputType === 'file' || inputType === 'log') && (
        <div className="file-drop-zone" onClick={() => fileInputRef.current?.click()}>
          <div className="crosshair-corners"></div>
          <div className="drop-icon">⇪</div>
          <div className="drop-text">MOUNT SOURCE DRIVE</div>
          <div className="drop-hint">SUPPORTED: .LOG, .TXT, .JSON, .PDF, .DOCX</div>
          <input type="file" ref={fileInputRef} style={{ display: 'none' }} accept=".log,.txt,.json,.pdf,.doc,.docx" onChange={(e) => {
            const file = e.target.files[0];
            if (file) {
              const reader = new FileReader();
              const isTextFile = file.name.match(/\.(log|txt|csv|json)$/i);
              if (isTextFile) {
                reader.onload = (ev) => setContent(ev.target.result);
                reader.readAsText(file);
              } else {
                reader.onload = (ev) => setContent(ev.target.result.split(',')[1] || ev.target.result);
                reader.readAsDataURL(file);
              }
            }
          }} />
        </div>
      )}

      <div style={{ marginBottom: '32px' }}>
        <div className="micro-data" style={{ marginBottom: '8px' }}>// DATA_STREAM_BUFFER</div>
        <textarea
          className="text-input"
          placeholder="AWAITING MANUAL INPUT OR FILE UPLOAD..."
          value={content}
          onChange={(e) => setContent(e.target.value)}
        />
      </div>



      <div className="options-group">
        <div className="micro-data" style={{ marginBottom: '8px' }}>HEURISTIC_FLAGS:</div>
        <div className="option-toggle" onClick={() => toggleOption('mask')}>
          <span className="option-label">ENCRYPT SENSITIVE</span>
          <div className={`toggle-switch ${options.mask ? 'on' : ''}`} />
        </div>
        <div className="option-toggle" onClick={() => toggleOption('block_high_risk')}>
          <span className="option-label">FIREWALL CRITICAL</span>
          <div className={`toggle-switch ${options.block_high_risk ? 'on' : ''}`} />
        </div>
        <div className="option-toggle" onClick={() => toggleOption('log_analysis')}>
          <span className="option-label">DEEP DIAGNOSTICS</span>
          <div className={`toggle-switch ${options.log_analysis ? 'on' : ''}`} />
        </div>
      </div>

      <button
        className="analyze-btn"
        onClick={handleSubmit}
        disabled={isLoading || !content.trim()}
        style={{ height: '60px', marginTop: '24px' }}
      >
        {isLoading ? 'EXECUTING_SCAN...' : 'INITIATE SYSTEM SCAN'}
      </button>
    </div>
  );
}
