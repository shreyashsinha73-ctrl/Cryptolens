import { useState, useEffect, useRef, useCallback } from 'react';

function getWsUrl() {
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const host = window.location.hostname || 'localhost';
  return `${protocol}//${host}:8000/ws/live-telemetry`;
}

export function useLiveTelemetry() {
  const [isConnected, setIsConnected] = useState(false);
  const [espEvents, setEspEvents] = useState([]);
  const [ikeEvents, setIkeEvents] = useState([]);
  const [rollingScore, setRollingScore] = useState(null);
  const [anomalyAlerts, setAnomalyAlerts] = useState([]);
  const [isStreaming, setIsStreaming] = useState(false);
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
              setEspEvents((prev) => [...prev.slice(-99), data]);
              setIsStreaming(true);
              break;
            case 'ike_event':
              setIkeEvents((prev) => [...prev.slice(-19), data]);
              break;
            case 'rolling_score':
              setRollingScore(data);
              break;
            case 'anomaly_alert':
              setAnomalyAlerts((prev) => [...prev.slice(-49), data]);
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

  const startCapture = async (iface = 'any') => {
    try {
      const res = await fetch(`/api/v1/live/start?interface=${iface}`, { method: 'POST' });
      const data = await res.json();
      if (data.status === 'started') setIsStreaming(true);
      return data;
    } catch (e) {
      return { status: 'error', message: e.message };
    }
  };

  const simulateCapture = async (configId = 'config_01_tunnel_aes256gcm_dh19_pfson') => {
    try {
      const res = await fetch(`/api/v1/live/simulate?config_id=${configId}`, { method: 'POST' });
      const data = await res.json();
      if (data.status === 'simulation_started') setIsStreaming(true);
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
    espEvents,
    ikeEvents,
    rollingScore,
    anomalyAlerts,
    startCapture,
    simulateCapture,
    stopCapture,
  };
}

