import React, { useState } from 'react';
import { selectDimensions } from '../../lib/dimensions.js';
import {
  Radar,
  RadarChart,
  PolarGrid,
  PolarAngleAxis,
  PolarRadiusAxis,
  ResponsiveContainer,
  Tooltip,
} from 'recharts';

const ComplianceRadar = ({
  score_breakdown = null,
  compliance = null,
  control_plane = null,
}) => {
  const [activeProfile, setActiveProfile] = useState('NIST_SP_800_77');

  // Same shared selector as the Analysis Dimensions bars.
  const dims = selectDimensions(score_breakdown, control_plane);
  const dimensions = dims.map((d) => ({
    subject: d.value === null ? `${d.label}\n(not observable)` : d.label,
    score: d.value === null ? null : Math.round(d.value * 100),
    unobs: d.value === null ? 0 : null,
    actualScore: d.value === null ? null : Math.round(d.value * 100),
    isUnobserved: d.value === null,
    evidence: d.evidence,
    obs: d.obs,
  }));

  // Standards from backend compliance data
  const nistStandard = compliance?.standards?.NIST_SP_800_77_R1;
  const cnsaStandard = compliance?.standards?.CNSA_2_0;

  const renderCustomTick = ({ payload, x, y, textAnchor }) => {
    const isUnobs = payload.value.includes('(not observable)');
    const lines = payload.value.split('\n');
    return (
      <g>
        <text
          x={x}
          y={y}
          textAnchor={textAnchor}
          fill={isUnobs ? '#9CA3AF' : '#E5E7EB'}
          fontSize={10}
          fontWeight={isUnobs ? 400 : 700}
        >
          <tspan x={x} dy="0em">{lines[0]}</tspan>
          {lines[1] && (
            <tspan x={x} dy="1.2em" fill="#F59E0B" fontStyle="italic" fontSize={9}>
              {lines[1]}
            </tspan>
          )}
        </text>
      </g>
    );
  };

  const currentStandard = activeProfile === 'NIST_SP_800_77' ? nistStandard : cnsaStandard;
  const standardStatus = currentStandard?.overall_status || 'NOT_ASSESSED';

  return (
    <div className="w-full flex flex-col items-center">
      {/* Header with profile tabs */}
      <div className="w-full flex flex-col sm:flex-row justify-between items-start sm:items-center gap-2 mb-2 pb-2 border-b border-gray-100 dark:border-[#2A2C34]">
        <div>
          <h3 className="text-sm font-bold text-gray-900 dark:text-white tracking-tight">Compliance Radar</h3>
          <p className="text-[11px] font-medium text-gray-500 dark:text-gray-400 mt-0.5">
            Cryptographic sub-score breakdown (0–100%)
          </p>
        </div>

        {/* Profile Selector */}
        <div className="flex items-center gap-1 bg-gray-100 dark:bg-[#1E2530] p-0.5 rounded-lg text-[10px] font-bold">
          <button
            type="button"
            onClick={() => setActiveProfile('NIST_SP_800_77')}
            className={`px-2 py-1 rounded cursor-pointer transition ${
              activeProfile === 'NIST_SP_800_77'
                ? 'bg-blue-600 text-white shadow-xs'
                : 'text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white'
            }`}
          >
            NIST SP 800-77
          </button>
          <button
            type="button"
            onClick={() => setActiveProfile('CNSA_2_0')}
            className={`px-2 py-1 rounded cursor-pointer transition ${
              activeProfile === 'CNSA_2_0'
                ? 'bg-blue-600 text-white shadow-xs'
                : 'text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white'
            }`}
          >
            NSA CNSA 2.0
          </button>
        </div>
      </div>

      {/* Profile Alignment Badge */}
      <div className="w-full flex items-center justify-between text-[11px] mb-1 px-1">
        <span className="text-gray-500 dark:text-gray-400 font-medium">
          Profile Assessment:
        </span>
        <span className={`font-black px-2 py-0.5 rounded text-[10px] uppercase tracking-wider ${
          standardStatus === 'ALIGNED' || standardStatus === 'COMPLIANT'
            ? 'bg-emerald-500/15 text-emerald-600 dark:text-emerald-400 border border-emerald-500/30'
            : standardStatus === 'FAIL' || standardStatus === 'CRITICAL'
            ? 'bg-rose-500/15 text-rose-600 dark:text-rose-400 border border-rose-500/30'
            : 'bg-amber-500/15 text-amber-600 dark:text-amber-400 border border-amber-500/30'
        }`}>
          {standardStatus}
        </span>
      </div>

      <div className="w-full h-72 mt-1">
        <ResponsiveContainer width="100%" height="100%">
          <RadarChart cx="50%" cy="50%" outerRadius="62%" data={dimensions}>
            <PolarGrid stroke="#2A2C34" />
            <PolarAngleAxis dataKey="subject" tick={renderCustomTick} />
            <PolarRadiusAxis angle={30} domain={[0, 100]} tick={false} axisLine={false} />

            <Tooltip
              contentStyle={{
                backgroundColor: '#18191D',
                borderColor: '#2A2C34',
                color: '#fff',
                borderRadius: '8px',
                fontSize: '11px',
              }}
              formatter={(value, name, props) => {
                if (props.payload.isUnobserved) {
                  return [
                    `Not Observable on Wire (${props.payload.obs} / ${props.payload.evidence})`,
                    props.payload.subject.split('\n')[0],
                  ];
                }
                return [
                  `${props.payload.actualScore}% (evidence: ${props.payload.evidence})`,
                  props.payload.subject,
                ];
              }}
            />

            <Radar
              name="Not observable"
              dataKey="unobs"
              stroke="#9CA3AF"
              fill="none"
              strokeDasharray="4 3"
              strokeWidth={1}
              dot={{ r: 4, fill: '#6B7280', stroke: '#9CA3AF', strokeDasharray: '2 2' }}
              isAnimationActive={false}
            />
            <Radar
              name="Evaluated Posture"
              dataKey="score"
              stroke="#6226EF"
              fill="#6226EF"
              fillOpacity={0.35}
              strokeWidth={2}
            />
          </RadarChart>
        </ResponsiveContainer>
      </div>

      {/* Legend footnote */}
      <div className="w-full text-center mt-1">
        <span className="text-[10px] text-gray-400 dark:text-gray-500">
          Unobserved axes marked in amber; never assumed secure or failing.
        </span>
      </div>
    </div>
  );
};

export default ComplianceRadar;