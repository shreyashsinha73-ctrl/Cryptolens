import React from 'react';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from 'recharts';

const TrafficDistribution = ({ traffic = [] }) => {
  const data = traffic.map((item) => ({
    name: item.traffic_type || 'Unknown',
    percentage: Number(item.percentage) || 0,
    packet_count: Number(item.packet_count) || 0,
    avg_packet_size_bytes: Number(item.avg_packet_size_bytes) || 0,
  }));

  return (
    <div className="w-full rounded-2xl bg-white dark:bg-[#18191D] border border-gray-100 dark:border-[#2A2C34] p-6">
      <div className="mb-5">
        <h3 className="text-sm font-bold text-gray-900 dark:text-white tracking-tight">
          Traffic Distribution
        </h3>

        <p className="text-[11px] font-medium text-gray-500 dark:text-gray-400 mt-1">
          Detected traffic types across analyzed packets
        </p>
      </div>

      {data.length === 0 ? (
        <div className="h-64 flex items-center justify-center text-sm text-gray-400">
          No traffic classification data available
        </div>
      ) : (
        <div className="w-full h-72">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart
              data={data}
              margin={{
                top: 10,
                right: 20,
                left: 0,
                bottom: 10,
              }}
            >
              <CartesianGrid
                strokeDasharray="3 3"
                stroke="#2A2C34"
                vertical={false}
              />

              <XAxis
                dataKey="name"
                tick={{
                  fill: '#9CA3AF',
                  fontSize: 11,
                  fontWeight: 600,
                }}
                axisLine={false}
                tickLine={false}
              />

              <YAxis
                domain={[0, 100]}
                tickFormatter={(value) => `${value}%`}
                tick={{
                  fill: '#9CA3AF',
                  fontSize: 10,
                }}
                axisLine={false}
                tickLine={false}
              />

              <Tooltip
                cursor={{ fill: 'rgba(98, 38, 239, 0.08)' }}
                contentStyle={{
                  backgroundColor: '#18191D',
                  borderColor: '#2A2C34',
                  color: '#fff',
                  borderRadius: '8px',
                  fontSize: '12px',
                }}
                formatter={(value) => [
                  `${Number(value).toFixed(1)}%`,
                  'Traffic Share',
                ]}
              />

              <Bar
                dataKey="percentage"
                name="Traffic Share"
                fill="#6226EF"
                radius={[6, 6, 0, 0]}
                barSize={45}
              />
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}
    </div>
  );
};

export default TrafficDistribution;