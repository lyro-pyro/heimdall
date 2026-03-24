import { useState } from 'react';

/**
 * LogViewer — displays analyzed log content with two viewing modes:
 *   1. Raw View: line-by-line with colored risk indicators (original behavior)
 *   2. Structured View: table with timestamp, level, service, message columns
 */
export default function LogViewer({ content, findings, structuredLogs }) {
  const [viewMode, setViewMode] = useState('raw');

  if (!content && (!structuredLogs || structuredLogs.length === 0)) return null;

  // ── Findings Map (for raw view) ──────────────────────────────────────────
  const findingsMap = {};
  if (findings) {
    for (const f of findings) {
      if (!findingsMap[f.line]) findingsMap[f.line] = [];
      findingsMap[f.line].push(f);
    }
  }

  const getLineClass = (lineFindings) => {
    if (!lineFindings) return 'log-line';
    const risks = lineFindings.map((f) => f.risk);
    if (risks.includes('critical')) return 'log-line flagged-critical';
    if (risks.includes('high')) return 'log-line flagged';
    if (risks.includes('medium')) return 'log-line flagged-medium';
    return 'log-line flagged-low';
  };

  // ── Level Styling ───────────────────────────────────────────────────────
  const getLevelClass = (level) => {
    const l = (level || '').toUpperCase();
    if (l === 'CRITICAL') return 'log-level-critical';
    if (l === 'ERROR') return 'log-level-error';
    if (l === 'WARNING') return 'log-level-warning';
    return 'log-level-info';
  };

  const hasStructured = structuredLogs && structuredLogs.length > 0;

  return (
    <div className="log-viewer-wrapper">
      <div className="crosshair-corners"></div>

      {/* View Toggle */}
      {hasStructured && (
        <div className="log-view-toggle">
          <button
            className={`toggle-btn ${viewMode === 'raw' ? 'active' : ''}`}
            onClick={() => setViewMode('raw')}
          >
            RAW_VIEW
          </button>
          <button
            className={`toggle-btn ${viewMode === 'structured' ? 'active' : ''}`}
            onClick={() => setViewMode('structured')}
          >
            STRUCT_VIEW
          </button>
        </div>
      )}

      {/* ── Raw View ──────────────────────────────────────────────────────── */}
      {viewMode === 'raw' && content && (
        <div className="log-scroll-area">
          {content.split('\n').map((line, idx) => {
            const lineNum = idx + 1;
            const lineFindings = findingsMap[lineNum];
            return (
              <div key={idx} className={getLineClass(lineFindings)}>
                <span className="line-number">{String(lineNum).padStart(4, '0')}</span>
                <span className="line-content">{line || ' '}</span>
                <div className="line-badges">
                  {lineFindings &&
                    lineFindings.map((f, i) => (
                      <span key={i} className={`line-badge badge ${f.risk}`}>
                        [{f.type}]
                      </span>
                    ))}
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* ── Structured View ───────────────────────────────────────────────── */}
      {viewMode === 'structured' && hasStructured && (
        <div className="log-scroll-area structured-log-table-wrap">
          <table className="structured-log-table">
            <thead>
              <tr>
                <th>TIMESTAMP</th>
                <th>LEVEL</th>
                <th>SERVICE</th>
                <th>MESSAGE</th>
              </tr>
            </thead>
            <tbody>
              {structuredLogs.map((log, idx) => (
                <StructuredLogRow key={idx} log={log} getLevelClass={getLevelClass} />
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}


/**
 * StructuredLogRow — expandable row showing a structured log entry.
 * Clicking expands to reveal metadata (IP, user_id, endpoint, error_code).
 */
function StructuredLogRow({ log, getLevelClass }) {
  const [expanded, setExpanded] = useState(false);
  const meta = log.metadata || {};
  const hasMeta = meta.ip_address || meta.user_id || meta.endpoint || meta.error_code;

  // Format timestamp for display
  const formatTs = (ts) => {
    try {
      const d = new Date(ts);
      return d.toISOString().replace('T', ' ').substring(0, 19);
    } catch {
      return ts || '—';
    }
  };

  return (
    <>
      <tr
        className={`structured-log-row ${hasMeta ? 'expandable' : ''}`}
        onClick={() => hasMeta && setExpanded(!expanded)}
      >
        <td className="ts-cell">{formatTs(log.timestamp)}</td>
        <td><span className={`log-level-badge ${getLevelClass(log.log_level)}`}>{log.log_level}</span></td>
        <td className="service-cell">{log.service}</td>
        <td className="msg-cell">{log.message}</td>
      </tr>
      {expanded && hasMeta && (
        <tr className="meta-row">
          <td colSpan={4}>
            <div className="meta-content">
              {meta.ip_address && <span className="meta-tag">IP: {meta.ip_address}</span>}
              {meta.user_id && <span className="meta-tag">USER: {meta.user_id}</span>}
              {meta.endpoint && <span className="meta-tag">ENDPOINT: {meta.endpoint}</span>}
              {meta.error_code && <span className="meta-tag">ERR_CODE: {meta.error_code}</span>}
            </div>
          </td>
        </tr>
      )}
    </>
  );
}
