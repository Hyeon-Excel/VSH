import React from 'react';

interface Finding {
  id: string;
  file: string;
  line: number;
  severity: string;
  message: string;
  // ... other fields
}

interface FindingsTableProps {
  findings: Finding[];
  onSelect: (finding: Finding) => void;
}

function FindingsTable({ findings, onSelect }: FindingsTableProps) {
  return (
    <div style={{ marginTop: 20 }}>
      <h2>Findings</h2>
      <table style={{ width: '100%', borderCollapse: 'collapse' }}>
        <thead>
          <tr>
            <th style={{ border: '1px solid #ccc', padding: 5 }}>File</th>
            <th style={{ border: '1px solid #ccc', padding: 5 }}>Line</th>
            <th style={{ border: '1px solid #ccc', padding: 5 }}>Severity</th>
            <th style={{ border: '1px solid #ccc', padding: 5 }}>Message</th>
          </tr>
        </thead>
        <tbody>
          {findings.map((f) => (
            <tr key={f.id} onClick={() => onSelect(f)} style={{ cursor: 'pointer' }}>
              <td style={{ border: '1px solid #ccc', padding: 5 }}>{f.file}</td>
              <td style={{ border: '1px solid #ccc', padding: 5 }}>{f.line}</td>
              <td style={{ border: '1px solid #ccc', padding: 5 }}>
                <span style={{
                  backgroundColor: f.severity === 'CRITICAL' ? 'red' : f.severity === 'HIGH' ? 'orange' : 'yellow',
                  color: 'white',
                  padding: '2px 5px',
                  borderRadius: 3
                }}>
                  {f.severity}
                </span>
              </td>
              <td style={{ border: '1px solid #ccc', padding: 5 }}>{f.message}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default FindingsTable;