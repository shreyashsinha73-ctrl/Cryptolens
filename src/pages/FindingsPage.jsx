import React, { useState, useMemo } from 'react';
import { Search, ChevronDown, ChevronUp, AlertTriangle, ShieldCheck, Info } from 'lucide-react';
import { useApp } from '../context/AppContext';
import AnalysisDimensions from '../components/dashboard/AnalysisDimensions';
import ComplianceRadar from '../components/dashboard/ComplianceRadar';
import { Card, CardHeader, CardTitle, CardContent } from '../components/ui/card';
import { Badge } from '../components/ui/badge';
import { Input } from '../components/ui/input';
import { Button } from '../components/ui/button';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '../components/ui/select';
import { mergeThreatsAndAnomalies } from '../lib/threatMatrixHelper';

const SEVERITY_COLORS = {
  CRITICAL: 'bg-red-500/10 text-red-400 border-red-500/20',
  HIGH: 'bg-orange-500/10 text-orange-400 border-orange-500/20',
  MEDIUM: 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20',
  LOW: 'bg-blue-500/10 text-blue-400 border-blue-500/20',
  INFO: 'bg-gray-500/10 text-gray-400 border-gray-500/20',
};

const SEVERITY_ORDER = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };

export default function FindingsPage() {
  const { analysisResult: activeResult, activeJobId } = useApp();
  const [searchTerm, setSearchTerm] = useState('');
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [expandedRows, setExpandedRows] = useState(new Set());
  const [page, setPage] = useState(1);
  const itemsPerPage = 10;

  if (!activeJobId || !activeResult) {
    return (
      <div className="flex-1 flex flex-col items-center justify-center text-zinc-500 min-h-[600px]">
        <AlertTriangle className="h-12 w-12 mb-4 opacity-50" />
        <h2 className="text-xl font-semibold text-zinc-300">No active analysis</h2>
        <p className="mt-2 text-sm text-center max-w-md">
          Upload a PCAP or run a testbed capture to view findings and compliance data.
        </p>
      </div>
    );
  }

  const { score_breakdown, control_plane, compliance, threat_matrix } = activeResult;

  const allFindings = useMemo(() => {
    return Array.from(mergeThreatsAndAnomalies(threat_matrix || []));
  }, [threat_matrix]);

  const filteredFindings = useMemo(() => {
    return allFindings
      .filter((f) => {
        const matchesSearch = (f.title || '').toLowerCase().includes(searchTerm.toLowerCase()) ||
                              (f.description || '').toLowerCase().includes(searchTerm.toLowerCase());
        const matchesSeverity = severityFilter === 'ALL' || f.severity === severityFilter;
        return matchesSearch && matchesSeverity;
      })
      .sort((a, b) => (SEVERITY_ORDER[b.severity] || 0) - (SEVERITY_ORDER[a.severity] || 0));
  }, [allFindings, searchTerm, severityFilter]);

  const totalPages = Math.ceil(filteredFindings.length / itemsPerPage);
  const paginatedFindings = filteredFindings.slice((page - 1) * itemsPerPage, page * itemsPerPage);

  const toggleRow = (id) => {
    const newSet = new Set(expandedRows);
    if (newSet.has(id)) newSet.delete(id);
    else newSet.add(id);
    setExpandedRows(newSet);
  };

  return (
    <div className="flex-1 space-y-6 p-8 overflow-y-auto bg-[#090A0F]">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-zinc-100 tracking-tight">Findings & Compliance</h1>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <AnalysisDimensions score_breakdown={score_breakdown} control_plane={control_plane} />
        <ComplianceRadar score_breakdown={score_breakdown} compliance={compliance} control_plane={control_plane} />
      </div>

      <Card className="bg-[#0F121C] border-[#1F2639]">
        <CardHeader className="flex flex-col sm:flex-row items-center justify-between space-y-2 sm:space-y-0 pb-4">
          <CardTitle className="text-lg font-medium text-zinc-100">Evidence Log</CardTitle>
          <div className="flex items-center gap-4 w-full sm:w-auto">
            <Input
              placeholder="Search findings..."
              value={searchTerm}
              onChange={(e) => { setSearchTerm(e.target.value); setPage(1); }}
              className="max-w-[200px] h-9 bg-[#1A1F2E] border-[#2A3143] text-sm text-zinc-300"
            />
            <Select value={severityFilter} onValueChange={(v) => { setSeverityFilter(v); setPage(1); }}>
              <SelectTrigger className="w-[140px] h-9 bg-[#1A1F2E] border-[#2A3143]">
                <SelectValue placeholder="Severity" />
              </SelectTrigger>
              <SelectContent className="bg-[#1A1F2E] border-[#2A3143] text-zinc-300">
                <SelectItem value="ALL">All Severities</SelectItem>
                <SelectItem value="CRITICAL">Critical</SelectItem>
                <SelectItem value="HIGH">High</SelectItem>
                <SelectItem value="MEDIUM">Medium</SelectItem>
                <SelectItem value="LOW">Low</SelectItem>
                <SelectItem value="INFO">Info</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </CardHeader>
        <CardContent>
          <div className="rounded-md border border-[#1F2639]">
            <table className="w-full text-sm">
              <thead className="border-b border-[#1F2639] bg-[#141824]/50 text-left text-zinc-400">
                <tr>
                  <th className="h-10 px-4 font-medium w-10"></th>
                  <th className="h-10 px-4 font-medium">Severity</th>
                  <th className="h-10 px-4 font-medium">Finding</th>
                  <th className="h-10 px-4 font-medium hidden md:table-cell">Category</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1F2639]">
                {paginatedFindings.length === 0 ? (
                  <tr>
                    <td colSpan={4} className="h-24 text-center text-zinc-500">
                      No findings match your criteria.
                    </td>
                  </tr>
                ) : (
                  paginatedFindings.map((f) => {
                    const isExpanded = expandedRows.has(f.finding_id);
                    const isUnobserved = f.observability === 'unobserved' || f.observability === 'not_observable';
                    return (
                      <React.Fragment key={f.finding_id}>
                        <tr
                          className={`hover:bg-[#141824] transition-colors cursor-pointer ${isUnobserved ? 'opacity-60 border-dashed' : ''}`}
                          onClick={() => toggleRow(f.finding_id)}
                        >
                          <td className="p-4 w-10">
                            {isExpanded ? <ChevronUp className="h-4 w-4 text-zinc-500" /> : <ChevronDown className="h-4 w-4 text-zinc-500" />}
                          </td>
                          <td className="p-4">
                            <Badge variant="outline" className={SEVERITY_COLORS[f.severity] || SEVERITY_COLORS.INFO}>
                              {f.severity}
                            </Badge>
                          </td>
                          <td className="p-4 font-medium text-zinc-200">
                            {f.title || f.finding_id}
                          </td>
                          <td className="p-4 text-zinc-400 hidden md:table-cell capitalize">
                            {f.category?.replace(/_/g, ' ') || 'General'}
                          </td>
                        </tr>
                        {isExpanded && (
                          <tr className="bg-[#141824]/30">
                            <td colSpan={4} className="p-4 px-12 border-b border-[#1F2639]/50 text-zinc-400 text-sm space-y-3">
                              <p>{f.description || 'No detailed description provided.'}</p>
                              <div className="flex flex-wrap gap-4 text-xs">
                                <div className="flex flex-col">
                                  <span className="font-medium text-zinc-500 mb-1">Observability</span>
                                  <span className="text-zinc-300 bg-zinc-800 px-2 py-0.5 rounded capitalize">
                                    {isUnobserved ? 'Not Observable' : f.observability || 'Wire Observed'}
                                  </span>
                                </div>
                                <div className="flex flex-col">
                                  <span className="font-medium text-zinc-500 mb-1">Evidence Source</span>
                                  <span className="text-zinc-300 bg-zinc-800 px-2 py-0.5 rounded font-mono">
                                    {f.evidence_source || 'static_analysis'}
                                  </span>
                                </div>
                                {f.observed_value !== undefined && f.observed_value !== null && (
                                  <div className="flex flex-col">
                                    <span className="font-medium text-zinc-500 mb-1">Observed Value</span>
                                    <span className="text-zinc-300 bg-zinc-800 px-2 py-0.5 rounded font-mono">
                                      {String(f.observed_value)}
                                    </span>
                                  </div>
                                )}
                              </div>
                            </td>
                          </tr>
                        )}
                      </React.Fragment>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
          {totalPages > 1 && (
            <div className="flex items-center justify-between mt-4 text-sm text-zinc-400">
              <div>Page {page} of {totalPages}</div>
              <div className="flex gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setPage(p => Math.max(1, p - 1))}
                  disabled={page === 1}
                  className="bg-[#1A1F2E] border-[#2A3143] text-zinc-300 hover:bg-[#2A3143] hover:text-white"
                >
                  Previous
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setPage(p => Math.min(totalPages, p + 1))}
                  disabled={page === totalPages}
                  className="bg-[#1A1F2E] border-[#2A3143] text-zinc-300 hover:bg-[#2A3143] hover:text-white"
                >
                  Next
                </Button>
              </div>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
