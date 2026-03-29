import React, { useEffect, useState } from 'react';
import axios from 'axios';

interface SettingsPageProps {
  apiBase: string;
  onBack: () => void;
}

const defaultConfig = {
  llm: {
    provider: 'mock',
    gemini_api_key: '',
    openai_api_key: '',
    model: 'gemini-1.5-pro',
    enable_l2: true,
    enable_l3: true
  },
  tools: {
    syft_enabled: true,
    syft_path: '',
    syft_auto_detect: true
  },
  scan: {
    watch_on_save: true,
    auto_scan_on_select: false,
    enable_sbom: true,
    max_files_per_scan: 200,
    exclude_dirs: ['.git', 'node_modules', 'venv', '__pycache__', 'dist', 'build'],
    include_extensions: ['.py', '.js', '.ts', '.jsx', '.tsx']
  },
  output: {
    export_path: './exports',
    save_json: true,
    save_markdown: true,
    save_diagnostics: true,
    auto_open_report_after_scan: false
  },
  ui: {
    theme: 'dark',
    show_code_preview: true,
    show_attack_scenario: true,
    show_validation_panel: true
  },
  system: {
    api_base_url: 'http://localhost:3000',
    config_version: 1
  }
};

function SettingsPage({ apiBase, onBack }: SettingsPageProps) {
  const [config, setConfig] = useState<any>(defaultConfig);
  const [unsaved, setUnsaved] = useState(false);
  const [status, setStatus] = useState<any>({});
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const [activeTab, setActiveTab] = useState('AI');
  const [llmTestResult, setLlmTestResult] = useState<string>('');
  const [syftResult, setSyftResult] = useState<string>('');

  useEffect(() => {
    const loadSettings = async () => {
      try {
        const res = await axios.get(`${apiBase}/settings`);
        setConfig(res.data);
      } catch (e: any) {
        setError('Unable to load settings. Using defaults.');
      }
      await refreshSystemStatus();
    };
    loadSettings();
  }, [apiBase]);

  const refreshSystemStatus = async () => {
    try {
      const res = await axios.get(`${apiBase}/system/status`);
      setStatus(res.data);
      setError('');
    } catch (e: any) {
      setError('Unable to fetch system status.');
    }
  };

  const updateConfig = (path: string[], value: any) => {
    setConfig((prev: any) => {
      const next = JSON.parse(JSON.stringify(prev));
      let cursor = next;
      for (let i = 0; i < path.length - 1; i++) {
        if (cursor[path[i]] === undefined) cursor[path[i]] = {};
        cursor = cursor[path[i]];
      }
      cursor[path[path.length - 1]] = value;
      return next;
    });
    setUnsaved(true);
  };

  const saveConfig = async () => {
    try {
      await axios.post(`${apiBase}/settings`, config);
      setMessage('Settings saved successfully.');
      setError('');
      setUnsaved(false);
      await refreshSystemStatus();
    } catch (e: any) {
      setError('Failed to save settings.');
      setMessage('');
    }
  };

  const resetConfig = () => {
    setConfig(defaultConfig);
    setUnsaved(true);
    setMessage('Settings reset to defaults. Save to apply.');
    setError('');
  };

  const reloadConfig = async () => {
    try {
      const res = await axios.get(`${apiBase}/settings`);
      setConfig(res.data);
      setUnsaved(false);
      setMessage('Settings reloaded.');
      setError('');
    } catch (e: any) {
      setError('Failed to reload settings.');
    }
  };

  const testLlm = async () => {
    try {
      const body = {
        provider: config.llm.provider,
        gemini_api_key: config.llm.gemini_api_key,
        openai_api_key: config.llm.openai_api_key
      };
      const res = await axios.post(`${apiBase}/settings/test-llm`, body);
      setLlmTestResult(`Status: ${res.data.connected ? 'Connected' : 'Failed'} - ${res.data.reason}`);
      setError('');
    } catch (e: any) {
      setLlmTestResult('Connection test failed.');
      setError('LLM connection test failed.');
    }
  };

  const checkSyft = async () => {
    try {
      const body = {
        syft_path: config.tools.syft_path
      };
      const res = await axios.post(`${apiBase}/settings/check-syft`, body);
      const syftState = res.data.syft;
      setSyftResult(`Syft ${syftState.installed ? 'installed' : 'not found'} (${syftState.path || 'no path'})`);
      setError('');
    } catch (e: any) {
      setSyftResult('Syft check failed.');
      setError('Syft check failed.');
    }
  };

  const sectionStyle = {
    backgroundColor: '#ffffff',
    padding: 12,
    borderRadius: 8,
    marginBottom: 12,
    border: '1px solid #ddd'
  };

  return (
    <div style={{ display: 'flex', height: '100%', fontFamily: 'Arial, sans-serif' }}>
      <div style={{ width: 200, borderRight: '1px solid #ccc', padding: 12 }}>
        <h2>Settings</h2>
        {['AI', 'Analysis Tools', 'Scan', 'Output', 'System'].map(tab => (
          <button key={tab}
            onClick={() => setActiveTab(tab)}
            style={{
              width: '100%',
              textAlign: 'left',
              padding: '8px 12px',
              marginBottom: 8,
              backgroundColor: activeTab === tab ? '#2196F3' : '#f5f5f5',
              color: activeTab === tab ? 'white' : '#222',
              border: 'none',
              borderRadius: 4,
              cursor: 'pointer'
            }}
          >{tab}</button>
        ))}
      </div>

      <div style={{ flex: 1, padding: 20, overflow: 'auto' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div>
            <h1>Settings</h1>
            <p>VSH 환경 및 분석 동작을 설정합니다</p>
          </div>
          <div>
            <button onClick={saveConfig} disabled={!unsaved} style={{ marginRight: 8, padding: '8px 12px' }}>💾 저장</button>
            <button onClick={resetConfig} style={{ marginRight: 8, padding: '8px 12px' }}>🔄 초기화</button>
            <button onClick={reloadConfig} style={{ padding: '8px 12px' }}>↻ 다시 불러오기</button>
          </div>
        </div>

        <div style={{ marginBottom: 8 }}>
          {unsaved && <span style={{ color: '#d97706' }}>저장되지 않은 변경사항 있음</span>}
          {!unsaved && <span style={{ color: '#16a34a' }}>설정 저장 완료</span>}
          {message && <div style={{ color: '#16a34a' }}>{message}</div>}
          {error && <div style={{ color: '#dc2626' }}>{error}</div>}
        </div>

        {activeTab === 'AI' && (
          <div style={sectionStyle}>
            <h3>AI 설정</h3>
            <div style={{ marginBottom: 8 }}>
              <label>LLM Provider:&nbsp;</label>
              <select value={config.llm.provider} onChange={e => updateConfig(['llm', 'provider'], e.target.value)}>
                <option value="mock">Mock</option>
                <option value="gemini">Gemini</option>
                <option value="openai">OpenAI</option>
              </select>
            </div>
            <div style={{ marginBottom: 8 }}>
              <label>Gemini API Key:&nbsp;</label>
              <input type="password" value={config.llm.gemini_api_key} onChange={e => updateConfig(['llm', 'gemini_api_key'], e.target.value)} style={{ width: 400 }} />
            </div>
            <div style={{ marginBottom: 8 }}>
              <label>OpenAI API Key:&nbsp;</label>
              <input type="password" value={config.llm.openai_api_key} onChange={e => updateConfig(['llm', 'openai_api_key'], e.target.value)} style={{ width: 400 }} />
            </div>
            <div style={{ marginBottom: 8 }}>
              <button onClick={testLlm} style={{ padding: '6px 12px' }}>🔍 연결 테스트</button>
              <span style={{ marginLeft: 12 }}>{llmTestResult}</span>
            </div>
          </div>
        )}

        {activeTab === 'Analysis Tools' && (
          <div style={sectionStyle}>
            <h3>Analysis Tools</h3>
            <div style={{ marginBottom: 8 }}>
              <label>Syft 활성화:&nbsp;</label>
              <input type="checkbox" checked={config.tools.syft_enabled} onChange={e => updateConfig(['tools', 'syft_enabled'], e.target.checked)} />
            </div>
            <div style={{ marginBottom: 8 }}>
              <label>Syft 경로:&nbsp;</label>
              <input value={config.tools.syft_path} onChange={e => updateConfig(['tools', 'syft_path'], e.target.value)} style={{ width: 400 }} />
            </div>
            <div style={{ marginBottom: 8 }}>
              <button onClick={checkSyft} style={{ padding: '6px 12px' }}>🔍 Syft 재검사</button>
              <span style={{ marginLeft: 12 }}>{syftResult}</span>
            </div>
            <div>
              <button onClick={() => updateConfig(['scan', 'enable_sbom'], !config.scan.enable_sbom)} style={{ padding: '6px 12px' }}>
                {config.scan.enable_sbom ? '✅ SBOM 활성화' : '❌ SBOM 비활성화'}
              </button>
            </div>
          </div>
        )}

        {activeTab === 'Scan' && (
          <div style={sectionStyle}>
            <h3>Scan</h3>
            <div style={{ marginBottom: 8 }}>
              <label>Watch on Save:&nbsp;</label>
              <input type="checkbox" checked={config.scan.watch_on_save} onChange={e => updateConfig(['scan', 'watch_on_save'], e.target.checked)} />
            </div>
            <div style={{ marginBottom: 8 }}>
              <label>Auto Scan on Select:&nbsp;</label>
              <input type="checkbox" checked={config.scan.auto_scan_on_select} onChange={e => updateConfig(['scan', 'auto_scan_on_select'], e.target.checked)} />
            </div>
            <div style={{ marginBottom: 8 }}>
              <label>L2 활성화:&nbsp;</label>
              <input type="checkbox" checked={config.llm.enable_l2} onChange={e => updateConfig(['llm', 'enable_l2'], e.target.checked)} />
            </div>
            <div style={{ marginBottom: 8 }}>
              <label>L3 활성화:&nbsp;</label>
              <input type="checkbox" checked={config.llm.enable_l3} onChange={e => updateConfig(['llm', 'enable_l3'], e.target.checked)} />
            </div>
            <div style={{ marginBottom: 8 }}>
              <label>Max files per scan:&nbsp;</label>
              <input type="number" value={config.scan.max_files_per_scan} onChange={e => updateConfig(['scan', 'max_files_per_scan'], Number(e.target.value))} />
            </div>
            <div style={{ marginBottom: 8 }}>
              <label>Exclude dirs (comma):&nbsp;</label>
              <input type="text" value={config.scan.exclude_dirs.join(',')} onChange={e => updateConfig(['scan', 'exclude_dirs'], e.target.value.split(',').map((v:string)=>v.trim()))} style={{ width: 360 }} />
            </div>
            <div style={{ marginBottom: 8 }}>
              <label>Include extensions (comma):&nbsp;</label>
              <input type="text" value={config.scan.include_extensions.join(',')} onChange={e => updateConfig(['scan', 'include_extensions'], e.target.value.split(',').map((v:string)=>v.trim()))} style={{ width: 360 }} />
            </div>
          </div>
        )}

        {activeTab === 'Output' && (
          <div style={sectionStyle}>
            <h3>Output</h3>
            <div style={{ marginBottom: 8 }}>
              <label>Export path:&nbsp;</label>
              <input value={config.output.export_path} onChange={e => updateConfig(['output', 'export_path'], e.target.value)} style={{ width: 400 }} />
            </div>
            <div>
              <label><input type="checkbox" checked={config.output.save_json} onChange={e => updateConfig(['output', 'save_json'], e.target.checked)} /> JSON 저장</label>
            </div>
            <div>
              <label><input type="checkbox" checked={config.output.save_markdown} onChange={e => updateConfig(['output', 'save_markdown'], e.target.checked)} /> Markdown 저장</label>
            </div>
            <div>
              <label><input type="checkbox" checked={config.output.save_diagnostics} onChange={e => updateConfig(['output', 'save_diagnostics'], e.target.checked)} /> Diagnostics 저장</label>
            </div>
            <div>
              <label><input type="checkbox" checked={config.output.auto_open_report_after_scan} onChange={e => updateConfig(['output', 'auto_open_report_after_scan'], e.target.checked)} /> 자동 리포트 열기</label>
            </div>
          </div>
        )}

        {activeTab === 'System' && (
          <div style={sectionStyle}>
            <h3>System</h3>
            <div>API Server: {status.api_server || 'unknown'}</div>
            <div>Python Core: {status.python_core || 'unknown'}</div>
            <div>LLM: {status.llm?.provider || 'unknown'} ({status.llm?.connected ? 'connected' : 'disconnected'})</div>
            <div>Syft: {status.syft?.installed ? 'installed' : 'not found'} ({status.syft?.path || 'N/A'})</div>
            <div>Config Path: {status.config_path || 'N/A'}</div>
          </div>
        )}
      </div>

      <div style={{ position: 'absolute', bottom: 20, left: 220 }}>
        <button onClick={onBack} style={{ padding: '8px 12px' }}>◀ Back to Scanner</button>
      </div>
    </div>
  );
}

export default SettingsPage;
