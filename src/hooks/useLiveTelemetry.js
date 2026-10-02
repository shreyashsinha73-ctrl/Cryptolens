import { useState, useEffect, useRef, useCallback } from 'react';

function getWsUrl() {
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const host = window.location.hostname || 'localhost';
  return `${protocol}//${host}:8000/ws/live-telemetry`;
}

export function useLiveTelemetry() {
  const [isConnected, setIsConnected] = useState(false);
  const [wireEvents, setWireEvents] = useState([]);
  const [espEvents, setEspEvents] = useState([]);
  const [ikeEvents, setIkeEvents] = useState([]);
  const [rollingScore, setRollingScore] = useState(null);
  const [anomalyAlerts, setAnomalyAlerts] = useState([]);
  const [isStreaming, setIsStreaming] = useState(false);
  const [streamCompleted, setStreamCompleted] = useState(false);
  const [completionMessage, setCompletionMessage] = useState(null);
  const wsRef = useRef(null);
  const reconnectTimer = useRef(null);

  const connect = useCallback(() => {
    try {
      const ws = new WebSocket(getWsUrl());

      ws.onopen = () => {
        setIsConnected(true);
      };

      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          switch (data.type) {
            case 'connection_ack':
              break;
            case 'esp_event':
              setEspEvents((prev) => [...prev.slice(-999), data]);
              setWireEvents((prev) => [...prev.slice(-1999), data]);
              setIsStreaming(true);
              setStreamCompleted(false);
              break;
            case 'ike_event':
              setIkeEvents((prev) => [...prev.slice(-499), data]);
              setWireEvents((prev) => [...prev.slice(-1999), data]);
              setIsStreaming(true);
              setStreamCompleted(false);
              break;
            case 'icmp_event':
            case 'voip_event':
            case 'dns_event':
            case 'web_event':
            case 'wire_packet':
            case 'inner_event':
              setWireEvents((prev) => [...prev.slice(-1999), data]);
              setIsStreaming(true);
              setStreamCompleted(false);
              break;
            case 'rolling_score':
              setRollingScore(data);
              break;
            case 'anomaly_alert':
              setAnomalyAlerts((prev) => [...prev.slice(-99), data]);
              break;
            case 'stream_completed':
              setIsStreaming(false);
              setStreamCompleted(true);
              setCompletionMessage(data.message || 'Simulation completed: all packets streamed.');
              break;
            case 'stream_stopped':
              setIsStreaming(false);
              break;
            default:
              break;
          }
        } catch (err) {
          console.error('[LiveTelemetry] Parse error:', err);
        }
      };

      ws.onclose = () => {
        setIsConnected(false);
        setIsStreaming(false);
        reconnectTimer.current = setTimeout(connect, 3000);
      };

      ws.onerror = () => ws.close();
      wsRef.current = ws;
    } catch (e) {
      reconnectTimer.current = setTimeout(connect, 3000);
    }
  }, []);

  useEffect(() => {
    connect();
    return () => {
      if (wsRef.current) wsRef.current.close();
      if (reconnectTimer.current) clearTimeout(reconnectTimer.current);
    };
  }, [connect]);

  const clearWire = useCallback(() => {
    setWireEvents([]);
    setEspEvents([]);
    setIkeEvents([]);
    setAnomalyAlerts([]);
    setRollingScore(null);
    setStreamCompleted(false);
    setCompletionMessage(null);
  }, []);

  const startCapture = async (iface = 'any') => {
    try {
      clearWire();
      const res = await fetch(`/api/v1/live/start?interface=${iface}`, { method: 'POST' });
      const data = await res.json();
      if (data.status === 'started') setIsStreaming(true);
      return data;
    } catch (e) {
      return { status: 'error', message: e.message };
    }
  };

  const simulateCapture = async (jobId = null) => {
    try {
      clearWire();
      let url = '/api/v1/live/simulate';
      if (jobId) {
        url += `?job_id=${encodeURIComponent(jobId)}`;
      }
      const res = await fetch(url, { method: 'POST' });
      const data = await res.json();
      if (data.status === 'simulation_started') setIsStreaming(true);
      return data;
    } catch (e) {
      return { status: 'error', message: e.message };
    }
  };

  const injectTraffic = async (profile = 'hardened') => {
    try {
      setStreamCompleted(false);
      setCompletionMessage(null);
      const res = await fetch(`/api/v1/live/inject/${profile}`, { method: 'POST' });
      const data = await res.json();
      if (data.status === 'injection_started') setIsStreaming(true);
      return data;
    } catch (e) {
      return { status: 'error', message: e.message };
    }
  };

  const stopCapture = async () => {
    try {
      const res = await fetch('/api/v1/live/stop', { method: 'POST' });
      const data = await res.json();
      setIsStreaming(false);
      return data;
    } catch (e) {
      return { status: 'error', message: e.message };
    }
  };

  return {
    isConnected,
    isStreaming,
    streamCompleted,
    completionMessage,
    wireEvents,
    espEvents,
    ikeEvents,
    rollingScore,
    anomalyAlerts,
    startCapture,
    simulateCapture,
    injectTraffic,
    stopCapture,
    clearWire,
  };
}
