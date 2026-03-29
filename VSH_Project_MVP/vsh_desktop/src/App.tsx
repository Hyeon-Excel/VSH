import React, { useState } from 'react';
import axios from 'axios';

const API_BASE = 'http://localhost:3000'; // Python API

interface Finding {
  id: string;
  file: string;
  line: number;
  severity: string;
  message: string;
  l2_reasoning: { is_vulnerable: boolean; confidence: number; reasoning: string };
  l3_validation: { validated: boolean; exploit_possible: boolean };
}

function App() {
  const [path, setPath] = useState('');
  const [findings, setFindings] = useState<Finding[]>([]);
  const [summary, setSummary] = useState<any>({});
  const [loading, setLoading] = useState(false);

  const scanFile = async () => {
    setLoading(true);
    try {
      const res = await axios.post(`${API_BASE}/scan/file`, { path });
      setFindings(res.data.findings);
      setSummary(res.data.summary);
    } catch (e) {
      alert('Scan failed');
    }
    setLoading(false);
  };

  const scanProject = async () => {
    setLoading(true);
    try {
      const res = await axios.post(`${API_BASE}/scan/project`, { path });
      setFindings(res.data.findings);
      setSummary(res.data.summary);
    } catch (e) {
      alert('Scan failed');
    }
    setLoading(false);
  };

  return (
    <div style={{ padding: 20 }}>
      <h1>VSH Security Scanner</h1>
      <input
        type="text"
        placeholder="Enter file or project path"
        value={path}
        onChange={(e) => setPath(e.target.value)}
        style={{ width: 400 }}
      />
      <button onClick={scanFile} disabled={loading}>Scan File</button>
      <button onClick={scanProject} disabled={loading}>Scan Project</button>
      {loading && <p>Scanning...</p>}
      <div>
        <h2>Summary</h2>
        <p>Total: {summary.total}, Critical: {summary.critical}, High: {summary.high}</p>
      </div>
      <div>
        <h2>Findings</h2>
        <table>
          <thead>
            <tr>
              <th>File</th>
              <th>Line</th>
              <th>Severity</th>
              <th>Message</th>
              <th>L2 Vulnerable</th>
              <th>L3 Exploit</th>
            </tr>
          </thead>
          <tbody>
            {findings.map((f) => (
              <tr key={f.id}>
                <td>{f.file}</td>
                <td>{f.line}</td>
                <td>{f.severity}</td>
                <td>{f.message}</td>
                <td>{f.l2_reasoning.is_vulnerable ? 'Yes' : 'No'}</td>
                <td>{f.l3_validation.exploit_possible ? 'Yes' : 'No'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export default App;