import React from 'react';

interface DashboardProps {
  summary: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    top_risky_files: [string, number][];
  };
}

function Dashboard({ summary }: DashboardProps) {
  return (
    <div style={{ marginTop: 20 }}>
      <h2>Dashboard</h2>
      <div style={{ display: 'flex', gap: 10 }}>
        <div style={{ border: '1px solid #ccc', padding: 10, borderRadius: 5 }}>
          <h3>Total Findings</h3>
          <p>{summary.total}</p>
        </div>
        <div style={{ border: '1px solid red', padding: 10, borderRadius: 5 }}>
          <h3>Critical</h3>
          <p>{summary.critical}</p>
        </div>
        <div style={{ border: '1px solid orange', padding: 10, borderRadius: 5 }}>
          <h3>High</h3>
          <p>{summary.high}</p>
        </div>
        <div style={{ border: '1px solid yellow', padding: 10, borderRadius: 5 }}>
          <h3>Medium</h3>
          <p>{summary.medium}</p>
        </div>
        <div style={{ border: '1px solid green', padding: 10, borderRadius: 5 }}>
          <h3>Low</h3>
          <p>{summary.low}</p>
        </div>
      </div>
      <h3>Top Risky Files</h3>
      <ul>
        {summary.top_risky_files.map(([file, count]) => (
          <li key={file}>{file}: {count} issues</li>
        ))}
      </ul>
    </div>
  );
}

export default Dashboard;