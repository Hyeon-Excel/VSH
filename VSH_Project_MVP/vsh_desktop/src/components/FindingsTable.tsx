import React from 'react';

interface Finding {
  id: string;
  file: string;
  line: number;
  end_line: number;
  severity: string;
  rule_id: string;
  message: string;
  evidence: string;
  reachability_status: string;
  reachability_confidence: number;
  l2_reasoning: {
    is_vulnerable: boolean;
    confidence: number;
    reasoning: string;
    attack_scenario: string;
    fix_suggestion: string;
  };
  l3_validation: {
    validated: boolean;
    exploit_possible: boolean;
    confidence: number;
    evidence: string;
    recommended_fix: string;
  };
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
                  backgroundColor: f.severity === 'CRITICAL' ? '#dc3545' : 
                                   f.severity === 'HIGH' ? '#fd7e14' : 
                                   f.severity === 'MEDIUM' ? '#ffc107' : '#6c757d',
                  color: 'white',
                  padding: '3px 8px',
                  borderRadius: 4,
                  fontWeight: 'bold',
                  fontSize: '12px'
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