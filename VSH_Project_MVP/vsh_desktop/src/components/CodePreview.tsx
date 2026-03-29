import React, { useEffect, useState } from 'react';
import axios from 'axios';

interface Finding {
  file: string;
  line: number;
  end_line: number;
}

interface CodePreviewProps {
  finding: Finding;
}

function CodePreview({ finding }: CodePreviewProps) {
  const [code, setCode] = useState<string>('');

  useEffect(() => {
    // 간단히 파일 읽기 (실제로는 API로)
    // 여기서는 mock
    setCode(`# Example code\nprint("hello")\n# Line ${finding.line}: ${finding.file}`);
  }, [finding]);

  return (
    <div style={{ marginTop: 20 }}>
      <h2>Code Preview</h2>
      <pre style={{
        backgroundColor: '#f4f4f4',
        padding: 10,
        borderRadius: 5,
        overflow: 'auto',
        maxHeight: 300
      }}>
        {code.split('\n').map((line, idx) => (
          <div key={idx} style={{
            backgroundColor: idx + 1 === finding.line ? 'yellow' : 'transparent'
          }}>
            {line}
          </div>
        ))}
      </pre>
    </div>
  );
}

export default CodePreview;