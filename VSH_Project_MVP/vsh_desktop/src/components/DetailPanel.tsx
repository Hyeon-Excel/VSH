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

interface DetailPanelProps {
  finding: Finding;
}

function DetailPanel({ finding }: DetailPanelProps) {
  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'CRITICAL': return '#dc3545'; // 더 진한 빨강
      case 'HIGH': return '#fd7e14'; // 주황
      case 'MEDIUM': return '#ffc107'; // 노랑
      default: return '#6c757d'; // 회색
    }
  };

  const getConfidenceColor = (confidence: number) => {
    if (confidence >= 0.8) return '#44ff44';
    if (confidence >= 0.6) return '#ffff44';
    return '#ff4444';
  };

  return (
    <div style={{ marginTop: 20, fontFamily: 'Arial, sans-serif' }}>
      <h2 style={{ color: getSeverityColor(finding.severity) }}>
        🔍 Finding Details - {finding.severity}
      </h2>
      
      <div style={{ backgroundColor: '#f9f9f9', padding: 15, borderRadius: 8, marginBottom: 15 }}>
        <h3>📁 Basic Information</h3>
        <p><strong>File:</strong> {finding.file}</p>
        <p><strong>Line:</strong> {finding.line} - {finding.end_line}</p>
        <p><strong>Rule ID:</strong> {finding.rule_id}</p>
        <p><strong>Message:</strong> {finding.message}</p>
        <p><strong>Evidence:</strong> {finding.evidence}</p>
        <p><strong>Reachability:</strong> {finding.reachability_status} 
          <span style={{ color: getConfidenceColor(finding.reachability_confidence) }}>
            ({Math.round(finding.reachability_confidence * 100)}%)
          </span>
        </p>
      </div>

      <div style={{ backgroundColor: '#e8f4fd', padding: 15, borderRadius: 8, marginBottom: 15, border: '2px solid #2196F3' }}>
        <h3>🧠 L2 Reasoning (AI Analysis)</h3>
        <p><strong>Vulnerable:</strong> 
          <span style={{ color: finding.l2_reasoning.is_vulnerable ? '#ff4444' : '#44ff44', fontWeight: 'bold' }}>
            {finding.l2_reasoning.is_vulnerable ? 'YES' : 'NO'}
          </span>
        </p>
        <p><strong>Confidence:</strong> 
          <span style={{ color: getConfidenceColor(finding.l2_reasoning.confidence) }}>
            {Math.round(finding.l2_reasoning.confidence * 100)}%
          </span>
        </p>
        <p><strong>Reasoning:</strong></p>
        <div style={{ backgroundColor: 'white', padding: 10, borderRadius: 5, margin: '10px 0' }}>
          {finding.l2_reasoning.reasoning}
        </div>
        <p><strong>Attack Scenario:</strong></p>
        <div style={{ backgroundColor: '#ffebee', padding: 10, borderRadius: 5, margin: '10px 0', border: '1px solid #ff4444' }}>
          ⚠️ {finding.l2_reasoning.attack_scenario}
        </div>
        <p><strong>Fix Suggestion:</strong></p>
        <div style={{ backgroundColor: '#e8f5e8', padding: 10, borderRadius: 5, margin: '10px 0', border: '1px solid #44ff44' }}>
          💡 {finding.l2_reasoning.fix_suggestion}
        </div>
      </div>

      <div style={{ backgroundColor: '#fff3e0', padding: 15, borderRadius: 8, marginBottom: 15, border: '2px solid #ff9800' }}>
        <h3>🔬 L3 Validation (Deep Analysis)</h3>
        <p><strong>Validated:</strong> 
          <span style={{ color: finding.l3_validation.validated ? '#44ff44' : '#ff4444', fontWeight: 'bold' }}>
            {finding.l3_validation.validated ? 'YES' : 'NO'}
          </span>
        </p>
        <p><strong>Exploit Possible:</strong> 
          <span style={{ color: finding.l3_validation.exploit_possible ? '#ff4444' : '#44ff44', fontWeight: 'bold' }}>
            {finding.l3_validation.exploit_possible ? 'YES - EXPLOITABLE!' : 'NO'}
          </span>
        </p>
        {finding.l3_validation.exploit_possible && (
          <div style={{ backgroundColor: '#ffebee', padding: 10, borderRadius: 5, margin: '10px 0', border: '1px solid #ff4444' }}>
            🚨 <strong>Exploit Details:</strong> This vulnerability can be exploited. 
            An attacker could potentially execute arbitrary code or access sensitive data through this weakness. 
            Immediate remediation is required.
          </div>
        )}
        <p><strong>Confidence:</strong> 
          <span style={{ color: getConfidenceColor(finding.l3_validation.confidence) }}>
            {Math.round(finding.l3_validation.confidence * 100)}%
          </span>
        </p>
        <p><strong>Evidence:</strong></p>
        <div style={{ backgroundColor: 'white', padding: 10, borderRadius: 5, margin: '10px 0' }}>
          {finding.l3_validation.evidence}
        </div>
        <p><strong>Recommended Fix:</strong></p>
        <div style={{ backgroundColor: '#e8f5e8', padding: 10, borderRadius: 5, margin: '10px 0', border: '1px solid #44ff44' }}>
          🔧 {finding.l3_validation.recommended_fix}
        </div>
      </div>
    </div>
  );
}

export default DetailPanel;