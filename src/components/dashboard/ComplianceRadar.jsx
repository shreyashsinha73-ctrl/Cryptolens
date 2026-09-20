import React from 'react';
import { Radar, RadarChart, PolarGrid, PolarAngleAxis, PolarRadiusAxis, ResponsiveContainer, Tooltip } from 'recharts';

const ComplianceRadar = ({ sub_scores }) => {
  const formatScore = (val) => ((val || 0) * 10).toFixed(1);

  const data = [
    { subject: `Cipher Strength (${formatScore(sub_scores?.cipher_strength)})`, score: (sub_scores?.cipher_strength || 0) * 100 },
    { subject: `Key Exchange (${formatScore(sub_scores?.key_exchange)})`, score: (sub_scores?.key_exchange || 0) * 100 },
    { subject: `Mode & PFS (${formatScore(sub_scores?.mode_pfs)})`, score: (sub_scores?.mode_pfs || 0) * 100 },
    { subject: `Metadata (${formatScore(sub_scores?.metadata_exposure)})`, score: (sub_scores?.metadata_exposure || 0) * 100 },
    { subject: `PQC Readiness (${formatScore(sub_scores?.pqc_readiness)})`, score: (sub_scores?.pqc_readiness || 0) * 100 },
  ];

  return (
    <div className="w-full flex flex-col items-center">
      <div className="w-full flex justify-between items-start mb-2">
         <div>
            <h3 className="text-sm font-bold text-gray-900 dark:text-white tracking-tight">Compliance Radar</h3>
            <p className="text-[11px] font-medium text-gray-500 dark:text-gray-400 mt-0.5">
              Cryptographic sub-score breakdown
            </p>
         </div>
      </div>
      
      {/* Increased container height to h-80 */}
      <div className="w-full h-80 mt-2">
        <ResponsiveContainer width="100%" height="100%">
          {/* Increased outerRadius to 75% */}
          <RadarChart cx="50%" cy="50%" outerRadius="75%" data={data}>
            <PolarGrid stroke="#2A2C34" />
            <PolarAngleAxis dataKey="subject" tick={{ fill: '#9CA3AF', fontSize: 11, fontWeight: 600 }} />
            <PolarRadiusAxis angle={30} domain={[0, 100]} tick={false} axisLine={false} />
            
            <Tooltip 
              contentStyle={{ backgroundColor: '#18191D', borderColor: '#2A2C34', color: '#fff', borderRadius: '8px', fontSize: '12px' }}
              itemStyle={{ color: '#6226EF', fontWeight: 'bold' }}
              formatter={(value) => [`${(value / 10).toFixed(1)} / 10`, 'Score']}
            />
            
            <Radar 
              name="Posture" 
              dataKey="score" 
              stroke="#6226EF" 
              fill="#6226EF" 
              fillOpacity={0.4} 
            />
          </RadarChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
};

export default ComplianceRadar;