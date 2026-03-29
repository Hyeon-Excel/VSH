import React, { useState } from 'react';
import axios from 'axios';
import { ipcRenderer } from 'electron';
import Dashboard from './components/Dashboard';
import FindingsTable from './components/FindingsTable';
import DetailPanel from './components/DetailPanel';
import CodePreview from './components/CodePreview';

const API_BASE = process.env.NODE_ENV === 'development' ? 'http://localhost:3000' : 'http://localhost:3000'; // TODO: config

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

function App() {
  const [path, setPath] = useState('');
  const [findings, setFindings] = useState<Finding[]>([]);
  const [summary, setSummary] = useState<any>({});
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [watchMode, setWatchMode] = useState(false);

  const selectFile = async () => {
    const result = await ipcRenderer.invoke('dialog:openFile');
    if (result) setPath(result);
  };

  const selectFolder = async () => {
    const result = await ipcRenderer.invoke('dialog:openDirectory');
    if (result) setPath(result);
  };

  const scan = async (mode: 'file' | 'project') => {
    setLoading(true);
    setError('');
    try {
      const res = await axios.post(`${API_BASE}/scan/${mode}`, { path });
      setFindings(res.data.findings);
      setSummary(res.data.summary);
    } catch (e: any) {
      setError(e.response?.data?.detail || 'Scan failed');
    }
    setLoading(false);
  };

  const toggleWatch = async () => {
    if (watchMode) {
      await axios.post(`${API_BASE}/watch/stop`, { path });
    } else {
      await axios.post(`${API_BASE}/watch/start`, { path });
    }
    setWatchMode(!watchMode);
  };

  const exportReport = () => {
    const dataStr = JSON.stringify({ findings, summary }, null, 2);
    const dataUri = 'data:application/json;charset=utf-8,'+ encodeURIComponent(dataStr);
    const exportFileDefaultName = 'vsh-report.json';
    const linkElement = document.createElement('a');
    linkElement.setAttribute('href', dataUri);
    linkElement.setAttribute('download', exportFileDefaultName);
    linkElement.click();
  };

  return (
    <div style={{ display: 'flex', height: '100vh' }}>
      <div style={{ flex: 1, padding: 20 }}>
        <h1>VSH Security Scanner</h1>
        <div>
          <button onClick={selectFile}>Select File</button>
          <button onClick={selectFolder}>Select Project</button>
          <span>{path}</span>
        </div>
        <div>
          <button onClick={() => scan('file')} disabled={loading || !path}>Scan File</button>
          <button onClick={() => scan('project')} disabled={loading || !path}>Scan Project</button>
          <button onClick={toggleWatch}>{watchMode ? 'Stop Watch' : 'Start Watch'}</button>
          <button onClick={exportReport} disabled={!findings.length}>Export JSON</button>
        </div>
        {loading && <p>Loading...</p>}
        {error && <p style={{ color: 'red' }}>{error}</p>}
        <Dashboard summary={summary} />
        <FindingsTable findings={findings} onSelect={setSelectedFinding} />
      </div>
      <div style={{ flex: 1, padding: 20, borderLeft: '1px solid #ccc' }}>
        {selectedFinding && (
          <>
            <DetailPanel finding={selectedFinding} />
            <CodePreview finding={selectedFinding} />
          </>
        )}
      </div>
    </div>
  );
}

export default App;