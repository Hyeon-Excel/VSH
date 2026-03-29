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
  return (
    <div style={{ marginTop: 20 }}>
      <h2>Detail</h2>
      <p><strong>File:</strong> {finding.file}</p>
      <p><strong>Line:</strong> {finding.line}</p>
      <p><strong>Severity:</strong> {finding.severity}</p>
      <p><strong>Rule ID:</strong> {finding.rule_id}</p>
      <p><strong>Message:</strong> {finding.message}</p>
      <p><strong>Evidence:</strong> {finding.evidence}</p>
      <p><strong>Reachability:</strong> {finding.reachability_status} ({finding.reachability_confidence})</p>
      <h3>L2 Reasoning</h3>
      <p><strong>Vulnerable:</strong> {finding.l2_reasoning.is_vulnerable ? 'Yes' : 'No'}</p>
      <p><strong>Confidence:</strong> {finding.l2_reasoning.confidence}</p>
      <p><strong>Reasoning:</strong> {finding.l2_reasoning.reasoning}</p>
      <p><strong>Attack Scenario:</strong> {finding.l2_reasoning.attack_scenario}</p>
      <p><strong>Fix Suggestion:</strong> {finding.l2_reasoning.fix_suggestion}</p>
      <h3>L3 Validation</h3>
      <p><strong>Validated:</strong> {finding.l3_validation.validated ? 'Yes' : 'No'}</p>
      <p><strong>Exploit Possible:</strong> {finding.l3_validation.exploit_possible ? 'Yes' : 'No'}</p>
      <p><strong>Confidence:</strong> {finding.l3_validation.confidence}</p>
      <p><strong>Evidence:</strong> {finding.l3_validation.evidence}</p>
      <p><strong>Recommended Fix:</strong> {finding.l3_validation.recommended_fix}</p>
    </div>
  );
}

export default DetailPanel;