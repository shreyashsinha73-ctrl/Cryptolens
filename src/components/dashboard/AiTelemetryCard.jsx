import React from 'react';
import Card from '../common/Card.jsx';
import ConfidenceBar from '../ConfidenceBar.jsx';
import AgreementFlag from '../AgreementFlag.jsx';
import Badge from '../common/Badge.jsx';

const AiTelemetryCard = ({ ai_metrics = {} }) => {
  return (
    <Card
      title="AI Inference & Telemetry"
      subtitle="Neural flow classifiers & heuristic validation"
      padding="p-6"
      className="h-full flex flex-col justify-between"
    >
      <div className="space-y-6 pt-2">
        <ConfidenceBar confidenceScore={ai_metrics.confidence_score} />

        <div className="space-y-3 pt-2 border-t border-gray-100 dark:border-[#323D4E]">
          <AgreementFlag heuristicAgreement={ai_metrics.heuristic_agreement} />

          <div className="flex items-center justify-between py-2 px-1">
            <div>
              <div className="text-xs font-bold text-[#202224] dark:text-white uppercase tracking-wider">
                Active Replay Protection
              </div>
              <div className="text-[11px] text-gray-400">
                Anti-replay window sequence tracking
              </div>
            </div>
            <Badge variant="completed" label="VERIFIED" size="sm" />
          </div>
        </div>
      </div>
    </Card>
  );
};

export default AiTelemetryCard;
