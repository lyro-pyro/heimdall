export default function ResultDisplay({ data }) {
  if (!data || !data.findings.length) return null;

  return (
    <div className="panel">
      <div className="crosshair-corners"></div>
      <div className="panel-header">
        <span>[ REGISTRY ]</span>
        <span className="deco">HEX_DUMP</span>
      </div>

      <div className="panel-body" style={{ padding: 0 }}>
        <div style={{ padding: '16px' }}>
          <table className="data-table">
            <thead>
              <tr>
                <th>INDEX</th>
                <th>SIGNATURE</th>
                <th>CLASS</th>
              </tr>
            </thead>
            <tbody>
              {data.findings.map((f, i) => (
                <tr key={i}>
                  <td style={{ color: 'var(--text-muted)' }}>0x{String(f.line).padStart(4, '0')}</td>
                  <td>
                    <div className="data-type">{f.type.toUpperCase()}</div>
                    {f.mitre_tactic && (
                      <div style={{ fontSize: '0.65rem', color: 'var(--accent-orange)', marginTop: '4px' }}>
                        ▶ {f.mitre_technique} [{f.mitre_tactic.toUpperCase()}]
                      </div>
                    )}
                    <div style={{ fontSize: '0.6rem', color: 'var(--text-secondary)', marginTop: '4px', maxWidth: '250px' }}>
                      // {f.reasoning || "Static signature match"}
                    </div>
                  </td>
                  <td style={{ verticalAlign: 'top', paddingTop: '8px' }}><span className={`badge ${f.risk}`}>{f.risk.substring(0,4)}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div className="panel-header" style={{ borderTop: '1px solid var(--border-line)' }}>
          <span>[ DEBUG_PAYLOAD ]</span>
        </div>
        <div className="json-display">
          <pre>{JSON.stringify(data, null, 2)}</pre>
        </div>
      </div>
    </div>
  );
}
