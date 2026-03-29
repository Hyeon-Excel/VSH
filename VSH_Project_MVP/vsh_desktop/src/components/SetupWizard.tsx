import React, { useState } from 'react';
import SettingsPage from './SettingsPage';

interface SetupWizardProps {
  apiBase: string;
  onComplete: (config: any) => void;
}

function SetupWizard({ apiBase, onComplete }: SetupWizardProps) {
  const [step, setStep] = useState(1);
  const [config, setConfig] = useState<any>({
    llm: {
      provider: 'mock',
      gemini_api_key: '',
      openai_api_key: ''
    },
    tools: {
      syft_enabled: true,
      syft_path: ''
    },
    scan: {
      watch_on_save: true,
      auto_scan_on_select: false,
      enable_sbom: true
    },
    output: {
      export_path: './exports',
      save_json: true,
      save_markdown: true
    }
  });

  const next = () => setStep(prev => Math.min(prev + 1, 6));
  const prev = () => setStep(prev => Math.max(prev - 1, 1));

  const renderContent = () => {
    switch (step) {
      case 1:
        return (
          <div>
            <h2>Welcome to VSH</h2>
            <p>VSH 설정을 완료하면 바로 분석을 시작할 수 있습니다.</p>
            <button onClick={next}>다음</button>
          </div>
        );
      case 2:
        return (
          <div>
            <h2>LLM Provider 선택</h2>
            <select value={config.llm.provider} onChange={e => setConfig((c:any) => ({ ...c, llm: { ...c.llm, provider: e.target.value } }))}>
              <option value="mock">Mock</option>
              <option value="gemini">Gemini</option>
              <option value="openai">OpenAI</option>
            </select>
            <div style={{ marginTop: 10 }}><button onClick={prev}>이전</button> <button onClick={next}>다음</button></div>
          </div>
        );
      case 3:
        return (
          <div>
            <h2>API Key 입력</h2>
            <p>다음 입력 후 연결 테스트를 해주세요.</p>
            <div>Gemini Key: <input value={config.llm.gemini_api_key} onChange={e => setConfig((c:any) => ({ ...c, llm: { ...c.llm, gemini_api_key: e.target.value } }))} /></div>
            <div>OpenAI Key: <input value={config.llm.openai_api_key} onChange={e => setConfig((c:any) => ({ ...c, llm: { ...c.llm, openai_api_key: e.target.value } }))} /></div>
            <div style={{ marginTop: 10 }}><button onClick={prev}>이전</button> <button onClick={next}>다음</button></div>
          </div>
        );
      case 4:
        return (
          <div>
            <h2>Syft 확인</h2>
            <p>Syft 설치 여부를 확인합니다.</p>
            <button onClick={next}>다음</button>
            <button onClick={prev}>이전</button>
          </div>
        );
      case 5:
        return (
          <div>
            <h2>기본 설정</h2>
            <label>Watch on Save: <input type="checkbox" checked={config.scan.watch_on_save} onChange={e => setConfig((c:any) => ({ ...c, scan: { ...c.scan, watch_on_save: e.target.checked } }))} /></label><br/>
            <label>Auto Scan on Select: <input type="checkbox" checked={config.scan.auto_scan_on_select} onChange={e => setConfig((c:any) => ({ ...c, scan: { ...c.scan, auto_scan_on_select: e.target.checked } }))} /></label><br/>
            <label>Enable SBOM: <input type="checkbox" checked={config.scan.enable_sbom} onChange={e => setConfig((c:any) => ({ ...c, scan: { ...c.scan, enable_sbom: e.target.checked } }))} /></label><br/>
            <button onClick={prev}>이전</button> <button onClick={() => { onComplete(config); }}>완료</button>
          </div>
        );
      default:
        return null;
    }
  };

  return (
    <div style={{ padding: 20, fontFamily: 'Arial, sans-serif' }}>
      <h1>Setup Wizard</h1>
      <p>Step {step} / 5</p>
      {renderContent()}
    </div>
  );
}

export default SetupWizard;
