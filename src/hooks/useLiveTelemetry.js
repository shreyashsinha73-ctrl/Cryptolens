import { useState, useEffect, useCallback } from 'react';

function getWsUrl() {
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const host = window.location.hostname || 'localhost';
  return `${protocol}//${host}:8000/ws/live-telemetry`;
}

// Module-level singleton state to prevent duplicate WebSocket connections
let sharedWs = null;
let subscribers = new Set();
let reconnectTimeout = null;

let state = {
  isConnected: false,
  isStreaming: false,
  streamCompleted: false,
  completionMessage: null,
  wireEvents: [],
  espEvents: [],
  ikeEvents: [],
  rollingScore: null,
  anomalyAlerts: [],
};

function notifySubscribers() {
  subscribers.forEach((callback) => callback({ ...state }));
}

function initWebSocket() {
  if (sharedWs && (sharedWs.readyState === WebSocket.OPEN || sharedWs.readyState === WebSocket.CONNECTING)) {
    return;
  }

  try {
    sharedWs = new WebSocket(getWsUrl());

    sharedWs.onopen = () => {
      state.isConnected = true;
      notifySubscribers();
    };

    sharedWs.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        switch (data.type) {
          case 'connection_ack':
            break;

          case 'telemetry_batch':
          case 'batch': {
            const events = data.events || [];
            if (!events.length) break;
            state.isStreaming = true;
            state.streamCompleted = false;
            const newEsp = [];
            const newIke = [];
            const newWire = [];
            for (const item of events) {
              const lastWire = newWire[newWire.length - 1] || state.wireEvents[state.wireEvents.length - 1];
              if (lastWire && item.frame_number !== undefined && lastWire.frame_number === item.frame_number) {
                continue;
              }
              if (item.type === 'esp_event' || item.protocol === 'ESP') {
                newEsp.push(item);
              } else if (item.type === 'ike_event' || item.protocol === 'IKE') {
                newIke.push(item);
              }
              newWire.push(item);
            }
            if (newEsp.length) state.espEvents = [...state.espEvents, ...newEsp];
            if (newIke.length) state.ikeEvents = [...state.ikeEvents, ...newIke];
            if (newWire.length) state.wireEvents = [...state.wireEvents, ...newWire];
            notifySubscribers();
            break;
          }

          case 'esp_event':
          case 'ike_event':
          case 'icmp_event':
          case 'voip_event':
          case 'dns_event':
          case 'web_event':
          case 'wire_packet':
          case 'inner_event': {
            // Deduplicate if identical frame number was just appended
            const lastWire = state.wireEvents[state.wireEvents.length - 1];
            if (lastWire && data.frame_number !== undefined && lastWire.frame_number === data.frame_number) {
              return;
            }

            state.isStreaming = true;
            state.streamCompleted = false;

            if (data.type === 'esp_event' || data.protocol === 'ESP') {
              state.espEvents = [...state.espEvents, data];
            } else if (data.type === 'ike_event' || data.protocol === 'IKE') {
              state.ikeEvents = [...state.ikeEvents, data];
            }

            state.wireEvents = [...state.wireEvents, data];
            notifySubscribers();
            break;
          }

          case 'rolling_score':
            state.rollingScore = data;
            notifySubscribers();
            break;

          case 'anomaly_alert':
            state.anomalyAlerts = [...state.anomalyAlerts.slice(-99), data];
            notifySubscribers();
            break;

          case 'heartbeat':
          case 'pong':
            break;

          case 'stream_completed':
            state.isStreaming = false;
            state.streamCompleted = true;
            state.completionMessage = data.message || 'Simulation completed: all packets streamed.';
            notifySubscribers();
            break;

          case 'stream_stopped':
            state.isStreaming = false;
            notifySubscribers();
            break;

          default:
            break;
        }
      } catch (err) {
        console.error('[LiveTelemetry] Parse error:', err);
      }
    };

    sharedWs.onclose = () => {
      state.isConnected = false;
      state.isStreaming = false;
      sharedWs = null;
      notifySubscribers();
      if (!reconnectTimeout) {
        reconnectTimeout = setTimeout(() => {
          reconnectTimeout = null;
          initWebSocket();
        }, 3000);
      }
    };

    sharedWs.onerror = () => {
      if (sharedWs) sharedWs.close();
    };
  } catch (e) {
    if (!reconnectTimeout) {
      reconnectTimeout = setTimeout(() => {
        reconnectTimeout = null;
        initWebSocket();
      }, 3000);
    }
  }
}

export function useLiveTelemetry() {
  const [localState, setLocalState] = useState({ ...state });

  useEffect(() => {
    subscribers.add(setLocalState);
    initWebSocket();
    setLocalState({ ...state });

    return () => {
      subscribers.delete(setLocalState);
    };
  }, []);

  const clearWire = useCallback(() => {
    state.wireEvents = [];
    state.espEvents = [];
    state.ikeEvents = [];
    state.anomalyAlerts = [];
    state.rollingScore = null;
    state.streamCompleted = false;
    state.completionMessage = null;
    notifySubscribers();
  }, []);

  const startCapture = async (iface = 'any') => {
    try {
      clearWire();
      const res = await fetch(`/api/v1/live/start?interface=${iface}`, { method: 'POST' });
      const data = await res.json();
      if (data.status === 'started') {
        state.isStreaming = true;
        notifySubscribers();
      }
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
      if (data.status === 'simulation_started') {
        state.isStreaming = true;
        notifySubscribers();
      }
      return data;
    } catch (e) {
      return { status: 'error', message: e.message };
    }
  };

  const injectTraffic = async (profile = 'hardened') => {
    try {
      state.streamCompleted = false;
      state.completionMessage = null;
      notifySubscribers();
      const res = await fetch(`/api/v1/live/inject/${profile}`, { method: 'POST' });
      const data = await res.json();
      if (data.status === 'injection_started') {
        state.isStreaming = true;
        notifySubscribers();
      }
      return data;
    } catch (e) {
      return { status: 'error', message: e.message };
    }
  };

  const stopCapture = async () => {
    try {
      const res = await fetch('/api/v1/live/stop', { method: 'POST' });
      const data = await res.json();
      state.isStreaming = false;
      notifySubscribers();
      return data;
    } catch (e) {
      return { status: 'error', message: e.message };
    }
  };

  return {
    isConnected: localState.isConnected,
    isStreaming: localState.isStreaming,
    streamCompleted: localState.streamCompleted,
    completionMessage: localState.completionMessage,
    wireEvents: localState.wireEvents,
    espEvents: localState.espEvents,
    ikeEvents: localState.ikeEvents,
    rollingScore: localState.rollingScore,
    anomalyAlerts: localState.anomalyAlerts,
    startCapture,
    simulateCapture,
    injectTraffic,
    stopCapture,
    clearWire,
  };
}
