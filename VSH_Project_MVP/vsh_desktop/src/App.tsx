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
    <div style={{ display: 'flex', height: '100vh', fontFamily: 'Arial, sans-serif' }}>
      <div style={{ flex: 1, padding: 20, backgroundColor: '#f5f5f5' }}>
        <h1 style={{ color: '#333', marginBottom: 20 }}>🛡️ VSH Security Scanner</h1>
        
        <div style={{ marginBottom: 20, padding: 15, backgroundColor: 'white', borderRadius: 8, boxShadow: '0 2px 4px rgba(0,0,0,0.1)' }}>
          <h3>📂 Select Target</h3>
          <div style={{ display: 'flex', gap: 10, alignItems: 'center', marginBottom: 10 }}>
            <button 
              onClick={selectFile} 
              disabled={loading}
              style={{ 
                padding: '8px 16px', 
                backgroundColor: loading ? '#ccc' : '#2196F3', 
                color: 'white', 
                border: 'none', 
                borderRadius: 4, 
                cursor: loading ? 'not-allowed' : 'pointer' 
              }}
            >
              📄 Select File
            </button>
            <button 
              onClick={selectFolder} 
              disabled={loading}
              style={{ 
                padding: '8px 16px', 
                backgroundColor: loading ? '#ccc' : '#2196F3', 
                color: 'white', 
                border: 'none', 
                borderRadius: 4, 
                cursor: loading ? 'not-allowed' : 'pointer' 
              }}
            >
              📁 Select Project
            </button>
          </div>
          <div style={{ fontSize: '14px', color: '#666' }}>
            Selected: {path || 'None'}
          </div>
        </div>

        <div style={{ marginBottom: 20, padding: 15, backgroundColor: 'white', borderRadius: 8, boxShadow: '0 2px 4px rgba(0,0,0,0.1)' }}>
          <h3>🔍 Scan Actions</h3>
          <div style={{ display: 'flex', gap: 10, alignItems: 'center', marginBottom: 10 }}>
            <button 
              onClick={() => scan('file')} 
              disabled={loading || !path}
              style={{ 
                padding: '10px 20px', 
                backgroundColor: (loading || !path) ? '#ccc' : '#4CAF50', 
                color: 'white', 
                border: 'none', 
                borderRadius: 4, 
                cursor: (loading || !path) ? 'not-allowed' : 'pointer',
                fontWeight: 'bold'
              }}
            >
              {loading ? '⏳ Scanning...' : '🔍 Scan File'}
            </button>
            <button 
              onClick={() => scan('project')} 
              disabled={loading || !path}
              style={{ 
                padding: '10px 20px', 
                backgroundColor: (loading || !path) ? '#ccc' : '#4CAF50', 
                color: 'white', 
                border: 'none', 
                borderRadius: 4, 
                cursor: (loading || !path) ? 'not-allowed' : 'pointer',
                fontWeight: 'bold'
              }}
            >
              {loading ? '⏳ Scanning...' : '🔍 Scan Project'}
            </button>
            <button 
              onClick={toggleWatch} 
              disabled={!path}
              style={{ 
                padding: '10px 20px', 
                backgroundColor: !path ? '#ccc' : (watchMode ? '#ff9800' : '#2196F3'), 
                color: 'white', 
                border: 'none', 
                borderRadius: 4, 
                cursor: !path ? 'not-allowed' : 'pointer',
                fontWeight: 'bold'
              }}
            >
              {watchMode ? '⏸️ Stop Watch' : '👀 Start Watch'}
            </button>
            <button 
              onClick={exportReport} 
              disabled={!findings.length}
              style={{ 
                padding: '10px 20px', 
                backgroundColor: !findings.length ? '#ccc' : '#9C27B0', 
                color: 'white', 
                border: 'none', 
                borderRadius: 4, 
                cursor: !findings.length ? 'not-allowed' : 'pointer',
                fontWeight: 'bold'
              }}
            >
              💾 Export JSON
            </button>
          </div>
          
          {loading && (
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, color: '#2196F3' }}>
              <div style={{ 
                width: 20, 
                height: 20, 
                border: '2px solid #f3f3f3', 
                borderTop: '2px solid #2196F3', 
                borderRadius: '50%', 
                animation: 'spin 1s linear infinite' 
              }}></div>
              <span>Analyzing code with VSH engine... Please wait.</span>
            </div>
          )}
          
          {error && (
            <div style={{ 
              padding: 10, 
              backgroundColor: '#ffebee', 
              border: '1px solid #ff4444', 
              borderRadius: 4, 
              color: '#c62828',
              marginTop: 10
            }}>
              ❌ <strong>Error:</strong> {error}
            </div>
          )}
          
          {watchMode && (
            <div style={{ 
              padding: 10, 
              backgroundColor: '#e8f5e8', 
              border: '1px solid #4CAF50', 
              borderRadius: 4, 
              color: '#2e7d32',
              marginTop: 10
            }}>
              👀 <strong>Watch Mode Active:</strong> Monitoring {path} for changes...
            </div>
          )}
        </div>

        <Dashboard summary={summary} />
        <FindingsTable findings={findings} onSelect={setSelectedFinding} />
      </div>
      <div style={{ flex: 1, padding: 20, borderLeft: '1px solid #ccc', backgroundColor: '#fafafa' }}>
        {selectedFinding ? (
          <>
            <DetailPanel finding={selectedFinding} />
            <CodePreview finding={selectedFinding} />
          </>
        ) : (
          <div style={{ 
            display: 'flex', 
            flexDirection: 'column', 
            alignItems: 'center', 
            justifyContent: 'center', 
            height: '100%',
            color: '#666'
          }}>
            <div style={{ fontSize: '48px', marginBottom: 20 }}>👈</div>
            <h3>Select a finding to view details</h3>
            <p>Click on any finding in the table to see detailed analysis and code preview.</p>
          </div>
        )}
      </div>
      
      <style>{`
        @keyframes spin {
          0% { transform: rotate(0deg); }
          100% { transform: rotate(360deg); }
        }
      `}</style>
    </div>
  );
}

export default App;