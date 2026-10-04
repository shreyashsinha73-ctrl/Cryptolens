import React, { useState, useEffect } from 'react';
import { ShieldAlert, Info, Sparkles, Activity, FileKey, AlertTriangle, RefreshCw } from 'lucide-react';
import { useApp } from '../context/AppContext';
import { Card, CardHeader, CardTitle, CardContent, CardDescription } from '../components/ui/card';
import { Badge } from '../components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '../components/ui/tabs';
import ThreatHeatmap from '../components/dashboard/ThreatHeatmap';
import { Button } from '../components/ui/button';
import { Skeleton } from '../components/ui/skeleton';

export default function AiInsightsPage() {
  const { analysisResult: activeResult, activeJobId } = useApp();
  const [advice, setAdvice] = useState(null);
  const [adviceLoading, setAdviceLoading] = useState(false);
  const [adviceError, setAdviceError] = useState(null);
  const [aiStatus, setAiStatus] = useState(null);

  useEffect(() => {
    fetch('/api/v1/ai/status')
      .then(r => r.json())
      .then(setAiStatus)
      .catch(console.error);
  }, []);

  const fetchAdvice = async () => {
    if (!activeJobId) return;
    setAdviceLoading(true);
    setAdviceError(null);
    try {
      const res = await fetch(`/api/v1/remediate/${activeJobId}/advice`, { method: 'POST' });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      setAdvice(data);
    } catch (e) {
      setAdviceError(e.message);
    } finally {
      setAdviceLoading(false);
    }
  };

  useEffect(() => {
    if (activeJobId && activeResult?.status === 'completed') {
      fetchAdvice();
    }
  }, [activeJobId, activeResult?.status]);

  if (!activeJobId || !activeResult) {
    return (
      <div className="flex-1 flex flex-col items-center justify-center text-zinc-500 min-h-[600px]">
        <AlertTriangle className="h-12 w-12 mb-4 opacity-50" />
        <h2 className="text-xl font-semibold text-zinc-300">No active analysis</h2>
        <p className="mt-2 text-sm text-center max-w-md">
          Upload a PCAP or run a testbed capture to view AI Insights.
        </p>
      </div>
    );
  }

  const isCooldown = aiStatus?.cooling_down_until && typeof aiStatus.cooling_down_until === 'number' && aiStatus.cooling_down_until > 0;
  
  // Executive briefing
  const briefing = activeResult.remediation?.executive_summary;

  return (
    <div className="flex-1 space-y-6 p-8 overflow-y-auto bg-[#090A0F]">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-zinc-100 tracking-tight flex items-center gap-2">
          <Sparkles className="h-6 w-6 text-purple-400" /> AI Cryptographic Insights
        </h1>
      </div>

      <Tabs defaultValue="insights" className="w-full">
        <TabsList className="bg-[#0F121C] border border-[#1F2639]">
          <TabsTrigger value="insights">Executive Briefing</TabsTrigger>
          <TabsTrigger value="hardening">AI Hardening</TabsTrigger>
          <TabsTrigger value="xai">Traffic Classifier (XAI)</TabsTrigger>
        </TabsList>

        <TabsContent value="insights" className="mt-6 space-y-6">
          <Card className="bg-[#0F121C] border-[#1F2639]">
            <CardHeader>
              <CardTitle className="text-lg text-zinc-100 flex items-center gap-2">
                Executive Security Briefing
                {activeResult.remediation && <Badge variant="outline" className="ml-2 bg-purple-500/10 text-purple-400 border-purple-500/20">AI Generated</Badge>}
              </CardTitle>
            </CardHeader>
            <CardContent>
              {briefing ? (
                <div className="prose prose-invert max-w-none text-zinc-300">
                  <p>{briefing}</p>
                </div>
              ) : (
                <div className="text-zinc-500 italic">No executive briefing available. (AI was unavailable or disabled during upload). Use AI Hardening tab to generate advice manually.</div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="hardening" className="mt-6 space-y-6">
          <Card className="bg-[#0F121C] border-[#1F2639]">
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <CardTitle className="text-lg text-zinc-100">Hardening Advice</CardTitle>
              {advice && (
                <Badge variant="outline" className={advice.source === 'gemini' ? 'bg-purple-500/10 text-purple-400 border-purple-500/20' : 'bg-blue-500/10 text-blue-400 border-blue-500/20'}>
                  Source: {advice.source} ({advice.model})
                </Badge>
              )}
            </CardHeader>
            <CardContent>
              {adviceLoading ? (
                <div className="space-y-4">
                  <Skeleton className="h-4 w-full bg-[#1F2639]" />
                  <Skeleton className="h-24 w-full bg-[#1F2639]" />
                  <Skeleton className="h-24 w-full bg-[#1F2639]" />
                </div>
              ) : adviceError ? (
                <div className="text-red-400 p-4 border border-red-500/20 bg-red-500/10 rounded-md">
                  <AlertTriangle className="h-5 w-5 mb-2 inline-block mr-2" />
                  Error loading advice: {adviceError}
                  <Button onClick={fetchAdvice} disabled={isCooldown} className="ml-4 bg-[#1F2639] hover:bg-[#2A3143] text-zinc-200">
                    <RefreshCw className="mr-2 h-4 w-4" /> Retry
                  </Button>
                  {isCooldown && <span className="ml-4 text-sm text-yellow-400">AI is currently on cooldown due to rate limits.</span>}
                </div>
              ) : advice?.hardening_advice ? (
                <div className="space-y-6">
                  <p className="text-zinc-300 text-sm leading-relaxed">{advice.hardening_advice.summary}</p>
                  <div className="grid gap-4">
                    {advice.hardening_advice.points?.map((pt, i) => (
                      <div key={i} className="p-4 rounded-lg bg-[#141824] border border-[#1F2639] space-y-2">
                        <div className="flex items-center gap-3">
                          <Badge variant="outline" className={pt.priority === 'high' ? 'text-red-400 border-red-500/20' : pt.priority === 'medium' ? 'text-yellow-400 border-yellow-500/20' : 'text-blue-400 border-blue-500/20'}>
                            {pt.priority.toUpperCase()}
                          </Badge>
                          <h4 className="font-semibold text-zinc-200">{pt.title}</h4>
                        </div>
                        <div className="text-sm text-zinc-400"><strong className="text-zinc-300">Problem:</strong> {pt.problem}</div>
                        <div className="text-sm text-zinc-400"><strong className="text-zinc-300">Why it matters:</strong> {pt.why_it_matters}</div>
                        <div className="text-sm text-zinc-400"><strong className="text-zinc-300">How to fix:</strong> {pt.how_to_fix}</div>
                      </div>
                    ))}
                  </div>
                  {advice.hardening_advice.not_observable_note && (
                    <div className="text-xs text-zinc-500 italic mt-4 flex items-center gap-2">
                      <Info className="h-3 w-3" /> {advice.hardening_advice.not_observable_note}
                    </div>
                  )}
                </div>
              ) : (
                <div className="text-zinc-500 text-sm">No advice generated.</div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="xai" className="mt-6 space-y-6">
          <div className="flex items-center gap-2 text-sm text-blue-400 mb-4 bg-blue-500/10 p-3 rounded border border-blue-500/20">
            <Info className="h-4 w-4 shrink-0" />
            <p>Explains the traffic classifier only, not cryptographic weakness.</p>
          </div>
          <ThreatHeatmap jobId={activeJobId} />
        </TabsContent>
      </Tabs>
    </div>
  );
}
