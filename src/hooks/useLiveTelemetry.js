import { useState, useEffect, useCallback } from 'react';

function getWsUrl() {
  if (import.meta.env.VITE_WS_URL) return import.meta.env.VITE_WS_URL;
  if (typeof window === 'undefined') return 'ws://127.0.0.1:8000/ws/live-telemetry';
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const host = window.location.host;
  return `${protocol}//${host}/ws/live-telemetry`;
}

// Module-level singleton state to prevent duplicate WebSocket connections
let sharedWs = null;
let subscribers = new Set();
let reconnectTimeout = null;
let reconnectAttempts = 0;
const MAX_RECONNECT_ATTEMPTS = 8;
const INITIAL_RECONNECT_DELAY_MS = 1000;
const MAX_RECONNECT_DELAY_MS = 16000;

let currentStreamId = null;
const seenDedupeKeys = new Set();
const MAX_DEDUPE_SIZE = 15000;

let pendingEvents = [];
let pendingAlerts = [];
let pendingScore = null;
let flushTimer = null;
const MAX_BUFFERED_WIRE_EVENTS = 2500;

let state = {
  isConnected: false,
  isStreaming: false,
  streamCompleted: false,
  completionMessage: null,
  streamId: null,
  streamSource: null,
  wireEvents: [],
  espEvents: [],
  ikeEvents: [],
  rollingScore: null,
  anomalyAlerts: [],
};

function pruneDedupeKeys() {
  if (seenDedupeKeys.size > MAX_DEDUPE_SIZE) {
    const it = seenDedupeKeys.values();
    for (let i = 0; i < 4000; i++) {
      const v = it.next().value;
      if (v !== undefined) seenDedupeKeys.delete(v);
    }
  }
}

function notifySubscribers() {
  subscribers.forEach((callback) => callback({ ...state }));
}

function flushPendingToState() {
  if (!pendingEvents.length && !pendingAlerts.length && !pendingScore) return;

  if (pendingEvents.length) {
    const newEsp = [];
    const newIke = [];
    for (const ev of pendingEvents) {
      if (ev.type === 'esp_event' || ev.protocol === 'ESP') {
        newEsp.push(ev);
      } else if (ev.type === 'ike_event' || ev.protocol === 'IKE') {
        newIke.push(ev);
      }
    }

    state.wireEvents = [...state.wireEvents, ...pendingEvents].slice(-MAX_BUFFERED_WIRE_EVENTS);
    if (newEsp.length) {
      state.espEvents = [...state.espEvents, ...newEsp].slice(-MAX_BUFFERED_WIRE_EVENTS);
    }
    if (newIke.length) {
      state.ikeEvents = [...state.ikeEvents, ...newIke].slice(-MAX_BUFFERED_WIRE_EVENTS);
    }
    pendingEvents = [];
  }

  if (pendingAlerts.length) {
    state.anomalyAlerts = [...state.anomalyAlerts, ...pendingAlerts].slice(-100);
    pendingAlerts = [];
  }

  if (pendingScore) {
    state.rollingScore = pendingScore;
    pendingScore = null;
  }

  notifySubscribers();
}

function scheduleFlush() {
  if (flushTimer) return;
  flushTimer = setTimeout(() => {
    flushTimer = null;
    flushPendingToState();
  }, 66); // ~15 Hz batched update
}

function resetStreamState(newStreamId = null) {
  currentStreamId = newStreamId;
  seenDedupeKeys.clear();
  pendingEvents = [];
  pendingAlerts = [];
  pendingScore = null;
  state.streamId = newStreamId;
  state.isStreaming = Boolean(newStreamId);
  state.streamSource = null;
  state.streamCompleted = false;
  state.completionMessage = null;
  state.wireEvents = [];
  state.espEvents = [];
  state.ikeEvents = [];
  state.anomalyAlerts = [];
  state.rollingScore = null;
}

function processWirePacket(item) {
  const sId = item.stream_id || currentStreamId || 'default';
  if (currentStreamId && item.stream_id && item.stream_id !== currentStreamId) {
    resetStreamState(item.stream_id);
  } else if (!currentStreamId && item.stream_id) {
    currentStreamId = item.stream_id;
    state.streamId = currentStreamId;
  }

  if (item.frame_number !== undefined && item.frame_number !== null) {
    const dedupeKey = `${sId}:${item.frame_number}`;
    if (seenDedupeKeys.has(dedupeKey)) {
      return;
    }
    seenDedupeKeys.add(dedupeKey);
    pruneDedupeKeys();
  }

  pendingEvents.push(item);
  state.isStreaming = true;
  state.streamCompleted = false;
  scheduleFlush();
}

function scheduleReconnect() {
  if (subscribers.size === 0) return; // Stop retrying if component unmounted
  if (reconnectAttempts >= MAX_RECONNECT_ATTEMPTS) {
    console.warn('[LiveTelemetry] Max reconnect attempts reached');
    return;
  }
  const delay = Math.min(
    INITIAL_RECONNECT_DELAY_MS * Math.pow(2, reconnectAttempts),
    MAX_RECONNECT_DELAY_MS
  );
  reconnectAttempts++;
  if (reconnectTimeout) clearTimeout(reconnectTimeout);
  reconnectTimeout = setTimeout(() => {
    reconnectTimeout = null;
    initWebSocket();
  }, delay);
}

function initWebSocket() {
  if (sharedWs && (sharedWs.readyState === WebSocket.OPEN || sharedWs.readyState === WebSocket.CONNECTING)) {
    return;
  }

  try {
    sharedWs = new WebSocket(getWsUrl());

    sharedWs.onopen = () => {
      state.isConnected = true;
      reconnectAttempts = 0;
      notifySubscribers();
    };

    sharedWs.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        switch (data.type) {
          case 'connection_ack':
            break;

          case 'heartbeat':
          case 'ping': {
            if (sharedWs && sharedWs.readyState === WebSocket.OPEN) {
              try {
                sharedWs.send(JSON.stringify({ type: 'pong', timestamp: Date.now() }));
              } catch {
                // Heartbeat send failed, ignore
              }
            }
            break;
          }

          case 'pong':
            break;

          case 'stream_started': {
            const preservedSource = data.mode === 'live' ? 'live_sniff' : data.mode === 'simulation' ? 'simulate' : (state.streamSource || (data.job_id ? 'simulate' : 'live_sniff'));
            resetStreamState(data.stream_id || null);
            state.streamSource = preservedSource;
            state.isStreaming = true;
            notifySubscribers();
            break;
          }

          case 'telemetry_batch':
          case 'batch': {
            const events = data.events || [];
            if (!events.length) break;
            for (const item of events) {
              processWirePacket(item);
            }
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
            processWirePacket(data);
            break;
          }

          case 'rolling_score': {
            pendingScore = data;
            scheduleFlush();
            break;
          }

          case 'anomaly_alert': {
            // Ignore alerts until this client has seen stream_started (no stale/replayed alerts).
            if (!state.isStreaming) break;
            pendingAlerts.push(data);
            scheduleFlush();
            break;
          }

          case 'stream_completed': {
            flushPendingToState();
            state.isStreaming = false;
            state.streamCompleted = true;
            state.completionMessage = data.message || 'Stream completed: all packets processed.';
            notifySubscribers();
            break;
          }

          case 'stream_stopped': {
            flushPendingToState();
            state.isStreaming = false;
            notifySubscribers();
            break;
          }

          default:
            break;
        }
      } catch (err) {
        console.error('[LiveTelemetry] Parse error:', err);
      }
    };

    sharedWs.onclose = () => {
      flushPendingToState();
      state.isConnected = false;
      state.isStreaming = false;
      sharedWs = null;
      notifySubscribers();
      scheduleReconnect();
    };

    sharedWs.onerror = () => {
      if (sharedWs) sharedWs.close();
    };
  } catch (err) {
    console.warn('[LiveTelemetry] WebSocket error:', err);
    scheduleReconnect();
  }
}

export function useLiveTelemetry() {
  const [localState, setLocalState] = useState({ ...state });

  useEffect(() => {
    subscribers.add(setLocalState);
    reconnectAttempts = 0;
    initWebSocket();
    setLocalState({ ...state });

    return () => {
      subscribers.delete(setLocalState);
      if (subscribers.size === 0 && reconnectTimeout) {
        clearTimeout(reconnectTimeout);
        reconnectTimeout = null;
      }
    };
  }, []);

  const clearWire = useCallback(() => {
    if (flushTimer) {
      clearTimeout(flushTimer);
      flushTimer = null;
    }
    resetStreamState(null);
    notifySubscribers();
  }, []);

  const startCapture = async (iface = 'any') => {
    try {
      clearWire();
      state.streamSource = 'live_sniff';
      notifySubscribers();
      const res = await fetch(`/api/v1/live/start?interface=${iface}`, { method: 'POST' });
      const data = await res.json();
      if (data.status === 'started') {
        state.isStreaming = true;
        state.streamSource = 'live_sniff';
        if (data.stream_id) state.streamId = data.stream_id;
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
      state.streamSource = 'simulate';
      notifySubscribers();
      let url = '/api/v1/live/simulate';
      if (jobId) {
        url += `?job_id=${encodeURIComponent(jobId)}`;
      }
      const res = await fetch(url, { method: 'POST' });
      const data = await res.json();
      if (data.status === 'simulation_started') {
        state.isStreaming = true;
        state.streamSource = 'simulate';
        if (data.stream_id) state.streamId = data.stream_id;
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
        if (data.stream_id) state.streamId = data.stream_id;
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

  const analyzeCapture = async () => {
    try {
      const res = await fetch('/api/v1/live/analyze', { method: 'POST' });
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
    streamId: localState.streamId,
    streamSource: localState.streamSource,
    wireEvents: localState.wireEvents,
    espEvents: localState.espEvents,
    ikeEvents: localState.ikeEvents,
    rollingScore: localState.rollingScore,
    anomalyAlerts: localState.anomalyAlerts,
    startCapture,
    simulateCapture,
    injectTraffic,
    stopCapture,
    analyzeCapture,
    clearWire,
  };
}
