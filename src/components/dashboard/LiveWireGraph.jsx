import React, { useRef, useEffect, useState, useMemo, useCallback } from 'react';
import { getPacketSeverity } from '../../lib/wireSeverity';

const SEVERITY_COLORS = {
  critical: {
    primary: '#ef4444',
    secondary: '#f87171',
    glow: 'rgba(239, 68, 68, 0.5)',
    bg: 'rgba(239, 68, 68, 0.15)',
    border: 'rgba(239, 68, 68, 0.4)',
    text: 'text-red-400',
    badge: 'bg-red-500 text-white',
  },
  medium: {
    primary: '#f59e0b',
    secondary: '#fbbf24',
    glow: 'rgba(245, 158, 11, 0.5)',
    bg: 'rgba(245, 158, 11, 0.15)',
    border: 'rgba(245, 158, 11, 0.4)',
    text: 'text-amber-400',
    badge: 'bg-amber-500 text-gray-950 font-bold',
  },
  low: {
    primary: '#10b981',
    secondary: '#34d399',
    glow: 'rgba(16, 185, 129, 0.45)',
    bg: 'rgba(16, 185, 129, 0.15)',
    border: 'rgba(16, 185, 129, 0.35)',
    text: 'text-emerald-400',
    badge: 'bg-emerald-500/25 text-emerald-300 border border-emerald-500/30',
  },
};

const MAX_VISIBLE_PACKETS = 150;
const MAX_HUBS = 12;
const RELEASE_INTERVAL_MS = 85; // 60 - 120 ms stagger requirement
const TRAVEL_DURATION_MS = 700;

export default function LiveWireGraph({
  wireEvents = [],
  anomalyAlerts = [],
  selectedPacket = null,
  onSelectPacket = () => {},
  isStreaming = false,
  isConnected = false,
}) {
  const containerRef = useRef(null);
  const canvasRef = useRef(null);

  // Playback control
  const [isPaused, setIsPaused] = useState(false);
  const isPausedRef = useRef(isPaused);

  useEffect(() => {
    isPausedRef.current = isPaused;
  }, [isPaused]);

  // Tooltip state
  const [hoveredPacket, setHoveredPacket] = useState(null);
  const [tooltipPos, setTooltipPos] = useState({ x: 0, y: 0 });

  // References for animation state across requestAnimationFrame ticks
  const engineRef = useRef({
    hubs: new Map(), // ip -> { x, y, targetX, targetY, ip, worstSeverity, lastActive, pulseAlpha, pulseRadius }
    particles: [], // active travelling & settled particles
    packetQueue: [], // staggered queue of packets waiting to spawn
    processedIndex: 0, // index in wireEvents we have enqueued
    lastReleaseTime: 0,
    animFrameId: null,
    width: 800,
    height: 480,
    dpr: 1,
    recentAlertsCount: 0,
    hubCounter: 0,
  });

  // Severity counts based on all ingested wireEvents
  const severityCounts = useMemo(() => {
    let crit = 0;
    let med = 0;
    let low = 0;
    for (let i = 0; i < wireEvents.length; i++) {
      const s = getPacketSeverity(wireEvents[i]);
      if (s === 'critical') crit++;
      else if (s === 'medium') med++;
      else low++;
    }
    return { critical: crit, medium: med, low };
  }, [wireEvents]);

  // When wireEvents is cleared (new stream started or user clear), reset engine state
  useEffect(() => {
    if (wireEvents.length === 0) {
      const e = engineRef.current;
      e.hubs.clear();
      e.particles = [];
      e.packetQueue = [];
      e.processedIndex = 0;
      e.recentAlertsCount = 0;
      e.hubCounter = 0;
    }
  }, [wireEvents.length]);

  // Enqueue newly arrived packets into the stagger queue
  useEffect(() => {
    const e = engineRef.current;
    if (wireEvents.length > e.processedIndex) {
      const newItems = wireEvents.slice(e.processedIndex);
      e.processedIndex = wireEvents.length;
      for (const pkt of newItems) {
        e.packetQueue.push(pkt);
      }
    }
  }, [wireEvents]);

  // Handle anomaly alerts to trigger visual pulse shockwaves
  useEffect(() => {
    const e = engineRef.current;
    if (anomalyAlerts && anomalyAlerts.length > e.recentAlertsCount) {
      const newAlerts = anomalyAlerts.slice(e.recentAlertsCount);
      e.recentAlertsCount = anomalyAlerts.length;

      for (const alert of newAlerts) {
        const culprit = alert.culprit_packet;
        const targetIp = culprit?.src_ip || culprit?.dst_ip;
        if (targetIp && e.hubs.has(targetIp)) {
          const hub = e.hubs.get(targetIp);
          hub.pulseRadius = 15;
          hub.pulseAlpha = 1.0;
          hub.pulseColor = SEVERITY_COLORS.critical.primary;
        } else {
          // Pulse all hubs briefly if no specific IP resolved
          e.hubs.forEach((hub) => {
            hub.pulseRadius = 15;
            hub.pulseAlpha = 0.9;
            hub.pulseColor = SEVERITY_COLORS.critical.primary;
          });
        }
      }
    }
  }, [anomalyAlerts]);

  // Setup Canvas & Animation Loop
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let destroyed = false;

    const handleResize = () => {
      const container = containerRef.current;
      if (!container || !canvas) return;
      const rect = container.getBoundingClientRect();
      const dpr = window.devicePixelRatio || 1;
      const w = Math.max(320, rect.width);
      const h = Math.max(340, rect.height || 460);

      engineRef.current.width = w;
      engineRef.current.height = h;
      engineRef.current.dpr = dpr;

      canvas.width = Math.floor(w * dpr);
      canvas.height = Math.floor(h * dpr);
      canvas.style.width = `${w}px`;
      canvas.style.height = `${h}px`;

      recalculateHubPositions(engineRef.current, w, h);
    };

    const resizeObserver = new ResizeObserver(() => handleResize());
    if (containerRef.current) {
      resizeObserver.observe(containerRef.current);
    }
    handleResize();

    // Main Canvas Render Loop
    const render = (time) => {
      if (destroyed) return;
      const e = engineRef.current;
      const { width: w, height: h, dpr } = e;

      // 1. Dequeue packet if not paused and stagger interval elapsed
      if (!isPausedRef.current && e.packetQueue.length > 0) {
        if (time - e.lastReleaseTime >= RELEASE_INTERVAL_MS) {
          e.lastReleaseTime = time;
          const nextPkt = e.packetQueue.shift();
          spawnPacketParticle(e, nextPkt, time, w, h);
        }
      }

      // 2. Clear canvas with deep cyber slate background
      ctx.save();
      ctx.scale(dpr, dpr);
      ctx.clearRect(0, 0, w, h);

      // Subtle cyber radar grid background
      drawCyberGrid(ctx, w, h);

      // 3. Smooth hub positions toward targets
      e.hubs.forEach((hub) => {
        hub.x += (hub.targetX - hub.x) * 0.12;
        hub.y += (hub.targetY - hub.y) * 0.12;
      });

      // 4. Draw connection conduits between connected hubs
      drawConduits(ctx, e);

      // 5. Update and render particles (travelling + settled)
      updateAndDrawParticles(ctx, e, time, selectedPacket);

      // 6. Draw glowing host hubs and any anomaly pulses
      drawHubs(ctx, e, time);

      ctx.restore();

      e.animFrameId = requestAnimationFrame(render);
    };

    const engine = engineRef.current;
    engine.animFrameId = requestAnimationFrame(render);

    return () => {
      destroyed = true;
      if (engine.animFrameId) {
        cancelAnimationFrame(engine.animFrameId);
      }
      resizeObserver.disconnect();
    };
  }, [selectedPacket]);

  // Hit test for mouse interactions (hover and selection)
  const findParticleAt = useCallback((clientX, clientY) => {
    const canvas = canvasRef.current;
    if (!canvas) return null;
    const rect = canvas.getBoundingClientRect();
    const x = clientX - rect.left;
    const y = clientY - rect.top;

    const e = engineRef.current;
    // Check particles in reverse order (newest on top)
    for (let i = e.particles.length - 1; i >= 0; i--) {
      const p = e.particles[i];
      if (p.opacity < 0.15) continue;
      const dx = p.x - x;
      const dy = p.y - y;
      const dist = Math.sqrt(dx * dx + dy * dy);
      const hitRadius = p.state === 'travelling' ? 12 : 9;
      if (dist <= hitRadius) {
        return { packet: p.packet, x: p.x, y: p.y };
      }
    }

    // Also check hubs
    for (const [, hub] of e.hubs) {
      const dx = hub.x - x;
      const dy = hub.y - y;
      if (Math.sqrt(dx * dx + dy * dy) <= 26) {
        return { isHub: true, ip: hub.ip, worstSeverity: hub.worstSeverity, x: hub.x, y: hub.y };
      }
    }

    return null;
  }, []);

  const handleMouseMove = (evt) => {
    const hit = findParticleAt(evt.clientX, evt.clientY);
    if (hit) {
      if (hit.packet) {
        setHoveredPacket(hit.packet);
        setTooltipPos({ x: hit.x, y: hit.y });
      } else {
        setHoveredPacket(null);
      }
      if (canvasRef.current) canvasRef.current.style.cursor = 'pointer';
    } else {
      setHoveredPacket(null);
      if (canvasRef.current) canvasRef.current.style.cursor = 'default';
    }
  };

  const handleClick = (evt) => {
    const hit = findParticleAt(evt.clientX, evt.clientY);
    if (hit && hit.packet) {
      onSelectPacket(hit.packet);
    } else {
      // Click empty space closes inspector
      onSelectPacket(null);
    }
  };

  const handleMouseLeave = () => {
    setHoveredPacket(null);
  };

  return (
    <div className="relative w-full rounded-2xl overflow-hidden bg-[#0A0D14] border border-gray-800 shadow-2xl flex flex-col">
      {/* Top SOC Status & Legend Bar */}
      <div className="flex flex-wrap items-center justify-between gap-3 px-4 py-3 bg-[#0E131F]/90 border-b border-gray-800 text-xs font-mono z-10">
        <div className="flex items-center gap-3 flex-wrap">
          <div className="flex items-center gap-2">
            <span className="relative flex h-2.5 w-2.5">
              <span className={`animate-ping absolute inline-flex h-full w-full rounded-full opacity-75 ${
                isStreaming ? 'bg-emerald-400' : isConnected ? 'bg-amber-400' : 'bg-rose-400'
              }`} />
              <span className={`relative inline-flex rounded-full h-2.5 w-2.5 ${
                isStreaming ? 'bg-emerald-500' : isConnected ? 'bg-amber-500' : 'bg-rose-500'
              }`} />
            </span>
            <span className="font-bold text-gray-200 uppercase tracking-wider text-[11px]">
            </span>
          </div>

          {/* Severity Counters */}
          <div className="flex items-center gap-2 text-[10px]">
            <span className="px-2 py-0.5 rounded bg-red-500/15 border border-red-500/30 text-red-400 font-bold flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-red-500" />
              {/* Critical: {severityCounts.critical} */}
            </span>
            <span className="px-2 py-0.5 rounded bg-amber-500/15 border border-amber-500/30 text-amber-400 font-bold flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-amber-500" />
              {/* Medium: {severityCounts.medium} */}
            </span>
            <span className="px-2 py-0.5 rounded bg-emerald-500/15 border border-emerald-500/30 text-emerald-400 font-bold flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
              {/* Low / Secure: {severityCounts.low} */}
            </span>
          </div>
        </div>

        {/* Legend & Playback Controls */}
        <div className="flex items-center gap-3">
          {/* Pause / Resume Button */}
          <button
            onClick={() => setIsPaused((prev) => !prev)}
            className={`px-3 py-1 rounded-lg text-[11px] font-bold transition flex items-center gap-1.5 cursor-pointer ${
              isPaused
                ? 'bg-amber-500 text-gray-950 hover:bg-amber-400 font-black shadow-xs'
                : 'bg-gray-800 hover:bg-gray-700 text-gray-200 border border-gray-700'
            }`}
            title={isPaused ? 'Resume animation & ingestion queue' : 'Pause animation'}
          >
            {isPaused ? (
              <>
                <svg className="w-3 h-3 fill-current" viewBox="0 0 24 24">
                  <path d="M8 5v14l11-7z" />
                </svg>
                Resume
              </>
            ) : (
              <>
                <svg className="w-3 h-3 fill-current" viewBox="0 0 24 24">
                  <path d="M6 19h4V5H6v14zm8-14v14h4V5h-4z" />
                </svg>
                Pause
              </>
            )}
          </button>
        </div>
      </div>

      {/* Main Interactive Canvas Area */}
      <div
        ref={containerRef}
        className="relative w-full h-[440px] sm:h-[480px] select-none"
      >
        <canvas
          ref={canvasRef}
          onMouseMove={handleMouseMove}
          onClick={handleClick}
          onMouseLeave={handleMouseLeave}
          className="absolute inset-0 w-full h-full block"
        />

        {/* Empty / Disconnected / Idle State Placeholder */}
        {wireEvents.length === 0 && (
          <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none p-6 text-center">
            <div className="w-16 h-16 rounded-full bg-blue-500/10 border border-blue-500/30 flex items-center justify-center mb-3">
              <svg className="w-8 h-8 text-blue-400 animate-pulse" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.5" d="M13 10V3L4 14h7v7l9-11h-7z" />
              </svg>
            </div>
            <h4 className="text-sm font-bold text-gray-200 font-mono uppercase tracking-wider">
              {isStreaming ? 'Ingesting Wire Telemetry...' : 'Network Activity Topology Idle'}
            </h4>
            <p className="text-xs text-gray-400 max-w-sm mt-1">
              {isStreaming
                ? 'Parsing incoming IPsec packets into topology nodes...'
                : 'Click "Simulate Stream" or "Live Sniff" above to observe live packet transit & host telemetry.'}
            </p>
          </div>
        )}

        {/* Hover Tooltip (HTML overlay for razor-sharp rendering) */}
        {hoveredPacket && (
          <div
            className="absolute pointer-events-none z-30 transition-transform duration-75 text-xs font-mono max-w-[240px]"
            style={{
              left: `${tooltipPos.x + 14}px`,
              top: `${Math.max(10, tooltipPos.y - 70)}px`,
            }}
          >
            <div className="bg-[#121824]/95 backdrop-blur-md border border-gray-700 text-gray-200 px-3 py-2 rounded-xl shadow-xl space-y-1">
              <div className="flex items-center justify-between gap-2 border-b border-gray-800 pb-1">
                <span className="font-bold text-white text-[11px]">
                  Frame #{hoveredPacket.frame_number ?? '—'}
                </span>
                <span
                  className={`text-[9px] font-black uppercase px-1.5 py-0.5 rounded ${
                    SEVERITY_COLORS[getPacketSeverity(hoveredPacket)].badge
                  }`}
                >
                  {hoveredPacket.severity || (hoveredPacket.is_replay ? 'CRITICAL' : 'SECURE')}
                </span>
              </div>
              <div className="text-[10px] text-gray-400">
                <span className="text-purple-400 font-bold">{hoveredPacket.packet_type || hoveredPacket.protocol}</span>
                {' '}&bull;{' '}
                <span>{hoveredPacket.packet_length} Bytes</span>
              </div>
              <div className="text-[10px] text-gray-300 font-semibold truncate max-w-[200px]">
                {hoveredPacket.src_ip} &rarr; {hoveredPacket.dst_ip}
              </div>
              {hoveredPacket.spi && hoveredPacket.spi !== '—' && (
                <div className="text-[9px] text-amber-400">SPI: {hoveredPacket.spi}</div>
              )}
            </div>
          </div>
        )}
      </div>

      {/* Bottom Hint Banner */}
      {/* <div className="px-4 py-2 bg-[#090C12] border-t border-gray-800/80 flex items-center justify-between text-[11px] font-mono text-gray-400">
        <span className="flex items-center gap-2">
          <span className="w-1.5 h-1.5 rounded-full bg-blue-500" />
          Click any traveling or settled packet node to inspect full wire metadata
        </span>
        <span className="text-gray-500 hidden sm:inline">
          Zero Decryption Boundary Active (RFC 4303)
        </span>
      </div> */}
    </div>
  );
}

/**
 * Recalculate target positions for hubs to keep them balanced in the canvas.
 * For 2 hubs (standard tunnel endpoints): placed symmetrically left & right.
 * For >2 hubs: distributed in an elliptical ring.
 */
function recalculateHubPositions(engine, width, height) {
  const hubArray = Array.from(engine.hubs.values());
  const count = hubArray.length;
  if (count === 0) return;

  const cx = width / 2;
  const cy = height / 2;

  if (count === 1) {
    hubArray[0].targetX = cx;
    hubArray[0].targetY = cy;
  } else if (count === 2) {
    const offsetX = Math.min(width * 0.32, 260);
    hubArray[0].targetX = cx - offsetX;
    hubArray[0].targetY = cy;
    hubArray[1].targetX = cx + offsetX;
    hubArray[1].targetY = cy;
  } else {
    const rx = Math.min(width * 0.36, 320);
    const ry = Math.min(height * 0.35, 160);
    hubArray.forEach((hub, idx) => {
      const angle = (idx / count) * 2 * Math.PI - Math.PI / 2;
      hub.targetX = cx + rx * Math.cos(angle);
      hub.targetY = cy + ry * Math.sin(angle);
    });
  }
}

/**
 * Spawns a new travelling packet particle from src_ip hub to dst_ip hub.
 */
function spawnPacketParticle(engine, packet, spawnTime, width, height) {
  const srcIp = packet.src_ip || '192.168.1.10';
  const dstIp = packet.dst_ip || '192.168.1.20';
  const severity = getPacketSeverity(packet);

  // Register or update source hub
  if (!engine.hubs.has(srcIp)) {
    if (engine.hubs.size >= MAX_HUBS) {
      // Evict oldest hub if capacity exceeded
      const oldestKey = engine.hubs.keys().next().value;
      engine.hubs.delete(oldestKey);
    }
    engine.hubCounter = (engine.hubCounter || 0) + 1;
    engine.hubs.set(srcIp, {
      name: `HOST ${engine.hubCounter}`,
      ip: srcIp,
      x: width * 0.25,
      y: height * 0.5,
      targetX: width * 0.25,
      targetY: height * 0.5,
      worstSeverity: severity,
      pulseRadius: 0,
      pulseAlpha: 0,
      pulseColor: SEVERITY_COLORS[severity].primary,
      lastActive: spawnTime,
    });
    recalculateHubPositions(engine, width, height);
  }

  // Register or update destination hub
  if (!engine.hubs.has(dstIp)) {
    if (engine.hubs.size >= MAX_HUBS) {
      const oldestKey = engine.hubs.keys().next().value;
      engine.hubs.delete(oldestKey);
    }
    engine.hubCounter = (engine.hubCounter || 0) + 1;
    engine.hubs.set(dstIp, {
      name: `HOST ${engine.hubCounter}`,
      ip: dstIp,
      x: width * 0.75,
      y: height * 0.5,
      targetX: width * 0.75,
      targetY: height * 0.5,
      worstSeverity: severity,
      pulseRadius: 0,
      pulseAlpha: 0,
      pulseColor: SEVERITY_COLORS[severity].primary,
      lastActive: spawnTime,
    });
    recalculateHubPositions(engine, width, height);
  }

  // Update hubs severity
  const srcHub = engine.hubs.get(srcIp);
  const dstHub = engine.hubs.get(dstIp);
  srcHub.lastActive = spawnTime;
  dstHub.lastActive = spawnTime;

  if (severityRank(severity) > severityRank(srcHub.worstSeverity)) {
    srcHub.worstSeverity = severity;
  }
  if (severityRank(severity) > severityRank(dstHub.worstSeverity)) {
    dstHub.worstSeverity = severity;
  }

  // Calculate curve control offset for aesthetic SOC transit arc
  const arcDirection = Math.random() > 0.5 ? 1 : -1;
  const arcCurvature = (40 + Math.random() * 50) * arcDirection;

  // Orbit angle when settled around destination hub
  const settledAngle = Math.random() * 2 * Math.PI;
  const settledDistance = 10 + (Math.random() * 20);

  const particle = {
    packet,
    severity,
    srcIp,
    dstIp,
    spawnTime,
    duration: TRAVEL_DURATION_MS,
    state: 'travelling', // 'travelling' | 'settled' | 'fading'
    arcCurvature,
    settledAngle,
    settledDistance,
    x: srcHub.x,
    y: srcHub.y,
    opacity: 1.0,
  };

  engine.particles.push(particle);

  // Enforce MAX_VISIBLE_PACKETS cap with fade-out
  if (engine.particles.length > MAX_VISIBLE_PACKETS) {
    const overflow = engine.particles.length - MAX_VISIBLE_PACKETS;
    for (let i = 0; i < overflow; i++) {
      if (engine.particles[i].state !== 'fading') {
        engine.particles[i].state = 'fading';
      }
    }
  }
}

function severityRank(s) {
  if (s === 'critical') return 3;
  if (s === 'medium') return 2;
  return 1;
}

/**
 * Draws cyber network grid and concentric range circles
 */
function drawCyberGrid(ctx, w, h) {
  ctx.save();
  ctx.strokeStyle = 'rgba(255, 255, 255, 0.025)';
  ctx.lineWidth = 1;

  // Grid lines
  const gridSize = 40;
  for (let x = 0; x < w; x += gridSize) {
    ctx.beginPath();
    ctx.moveTo(x, 0);
    ctx.lineTo(x, h);
    ctx.stroke();
  }
  for (let y = 0; y < h; y += gridSize) {
    ctx.beginPath();
    ctx.moveTo(0, y);
    ctx.lineTo(w, y);
    ctx.stroke();
  }

  // Central faint radar circles
  ctx.strokeStyle = 'rgba(59, 130, 246, 0.04)';
  ctx.beginPath();
  ctx.arc(w / 2, h / 2, Math.min(w, h) * 0.28, 0, Math.PI * 2);
  ctx.stroke();

  ctx.beginPath();
  ctx.arc(w / 2, h / 2, Math.min(w, h) * 0.44, 0, Math.PI * 2);
  ctx.stroke();

  ctx.restore();
}

/**
 * Draws conduits (thin glowing connection lines) between active hubs
 */
function drawConduits(ctx, engine) {
  const hubs = Array.from(engine.hubs.values());
  if (hubs.length < 2) return;

  ctx.save();
  for (let i = 0; i < hubs.length; i++) {
    for (let j = i + 1; j < hubs.length; j++) {
      const h1 = hubs[i];
      const h2 = hubs[j];

      // Base conduit line
      ctx.strokeStyle = 'rgba(56, 189, 248, 0.12)';
      ctx.lineWidth = 1.5;
      ctx.setLineDash([4, 4]);
      ctx.beginPath();
      ctx.moveTo(h1.x, h1.y);
      ctx.lineTo(h2.x, h2.y);
      ctx.stroke();
    }
  }
  ctx.restore();
}

/**
 * Updates coordinates and draws all packet particles
 */
/**
 * Updates coordinates and draws all packet particles
 */
function updateAndDrawParticles(ctx, engine, now, selectedPacket) {
  const surviving = [];
  
  const rw = 100; // Half-width of the rectangle (200/2)
  const rh = 42;  // Half-height of the rectangle (84/2)

  // Helper to get point on the rounded rectangle boundary for the arc
  function getBoundary(cx, cy, tx, ty) {
    const dx = tx - cx;
    const dy = ty - cy;
    if (Math.abs(dx) < 0.1 && Math.abs(dy) < 0.1) return {x: cx, y: cy};
    
    // Normalize and scale by radius. For a rounded rect, it's roughly an ellipse if we want smooth orbit
    // But for start/end, just use ellipse approximation
    const angle = Math.atan2(dy, dx);
    return {
      x: cx + Math.cos(angle) * rw,
      y: cy + Math.sin(angle) * rh
    };
  }

  for (let i = 0; i < engine.particles.length; i++) {
    const p = engine.particles[i];
    const srcHub = engine.hubs.get(p.srcIp);
    const dstHub = engine.hubs.get(p.dstIp);

    // If either hub was evicted, default to screen center
    const cx0 = srcHub ? srcHub.x : engine.width / 2;
    const cy0 = srcHub ? srcHub.y : engine.height / 2;
    const cx1 = dstHub ? dstHub.x : engine.width / 2;
    const cy1 = dstHub ? dstHub.y : engine.height / 2;
    
    const startPoint = getBoundary(cx0, cy0, cx1, cy1);
    // End point is boundary of dst facing src
    const endPoint = getBoundary(cx1, cy1, cx0, cy0);
    
    const x0 = startPoint.x;
    const y0 = startPoint.y;
    const x1 = endPoint.x;
    const y1 = endPoint.y;

    if (p.state === 'travelling') {
      const elapsed = now - p.spawnTime;
      const progress = Math.min(1.0, elapsed / p.duration);

      // Quadratic bezier arc interpolation
      const midX = (x0 + x1) / 2;
      const midY = (y0 + y1) / 2 + p.arcCurvature;

      const t = progress;
      const invT = 1 - t;

      p.x = invT * invT * x0 + 2 * invT * t * midX + t * t * x1;
      p.y = invT * invT * y0 + 2 * invT * t * midY + t * t * y1;

      if (progress >= 1.0) {
        p.state = 'settled';
      }
    } else if (p.state === 'settled' || p.state === 'fading') {
      if (p.state === 'fading') {
        p.opacity -= 0.035;
      }
      
      // Orbit outside the rectangle boundary
      const angle = p.settledAngle + (now * 0.0004);
      // Orbit ellipse radii: rectangle size + padding (settledDistance)
      const orbitRx = rw + p.settledDistance;
      const orbitRy = rh + p.settledDistance;
      
      p.x = cx1 + Math.cos(angle) * orbitRx;
      p.y = cy1 + Math.sin(angle) * orbitRy;
    }

    if (p.opacity > 0.01) {
      surviving.push(p);
      drawSingleParticle(ctx, p, selectedPacket);
    }
  }

  engine.particles = surviving;
}

/**
 * Draws an individual packet particle with circular geometry and glow
 */
function drawSingleParticle(ctx, p, selectedPacket) {
  const colors = SEVERITY_COLORS[p.severity] || SEVERITY_COLORS.low;
  const isSelected = selectedPacket?.frame_number === p.packet.frame_number;

  ctx.save();
  ctx.globalAlpha = p.opacity;

  const size = p.state === 'travelling' ? 7.5 : 5.5;

  // Selected highlight ring
  if (isSelected) {
    ctx.strokeStyle = '#38bdf8';
    ctx.lineWidth = 2.5;
    ctx.shadowColor = '#38bdf8';
    ctx.shadowBlur = 12;
    ctx.beginPath();
    ctx.arc(p.x, p.y, size + 4, 0, Math.PI * 2);
    ctx.stroke();
  }

  // Soft outer glow
  ctx.shadowColor = colors.primary;
  ctx.shadowBlur = p.severity === 'critical' ? 14 : 8;

  // Draw circular node
  ctx.fillStyle = colors.primary;
  ctx.beginPath();
  ctx.arc(p.x, p.y, size, 0, Math.PI * 2);
  ctx.fill();

  // Core highlight
  ctx.fillStyle = '#ffffff';
  ctx.shadowBlur = 0;
  ctx.beginPath();
  ctx.arc(p.x, p.y, size * 0.4, 0, Math.PI * 2);
  ctx.fill();

  ctx.restore();
}

function drawHubs(ctx, engine) {
  engine.hubs.forEach((hub) => {
    const colors = SEVERITY_COLORS[hub.worstSeverity] || SEVERITY_COLORS.low;
    const w = 200;
    const h = 84;
    const rx = 8;
    const x = hub.x - w / 2;
    const y = hub.y - h / 2;

    ctx.save();

    // 1. Anomaly shockwave pulse if active
    if (hub.pulseAlpha > 0.02) {
      ctx.strokeStyle = hub.pulseColor || SEVERITY_COLORS.critical.primary;
      ctx.lineWidth = 2;
      ctx.globalAlpha = hub.pulseAlpha;
      ctx.beginPath();
      ctx.roundRect(hub.x - hub.pulseRadius * (w/40), hub.y - hub.pulseRadius * (h/40), hub.pulseRadius * (w/20), hub.pulseRadius * (h/20), rx + 4);
      ctx.stroke();

      hub.pulseRadius += 1.2;
      hub.pulseAlpha -= 0.025;
    }

    ctx.globalAlpha = 1.0;

    // 2. Hub Background & Border
    ctx.fillStyle = '#22232B'; // Dark zinc/slate
    ctx.strokeStyle = colors.border || colors.primary;
    ctx.lineWidth = 1;
    ctx.shadowColor = 'rgba(0,0,0,0.5)';
    ctx.shadowBlur = 10;
    ctx.shadowOffsetY = 4;
    
    ctx.beginPath();
    ctx.roundRect(x, y, w, h, rx);
    ctx.fill();
    ctx.shadowBlur = 0;
    ctx.shadowOffsetY = 0;
    ctx.stroke();

    // Subtle glow based on severity
    if (hub.worstSeverity !== 'low') {
      ctx.strokeStyle = colors.primary;
      ctx.lineWidth = 1.5;
      ctx.globalAlpha = 0.4;
      ctx.stroke();
      ctx.globalAlpha = 1.0;
    }

    // 3. Icon Box (top-left)
    const iconBoxSize = 28;
    ctx.fillStyle = 'rgba(255, 255, 255, 0.06)';
    ctx.beginPath();
    ctx.roundRect(x + 14, y + 14, iconBoxSize, iconBoxSize, 4);
    ctx.fill();

    // Draw a simple computer/server icon inside the box
    ctx.strokeStyle = '#D1D5DB'; // gray-300
    ctx.lineWidth = 1.5;
    ctx.beginPath();
    // Monitor screen
    ctx.strokeRect(x + 14 + 6, y + 14 + 7, 16, 10);
    // Stand
    ctx.moveTo(x + 14 + 14, y + 14 + 17);
    ctx.lineTo(x + 14 + 14, y + 14 + 20);
    // Base
    ctx.moveTo(x + 14 + 10, y + 14 + 20);
    ctx.lineTo(x + 14 + 18, y + 14 + 20);
    ctx.stroke();

    // 4. Title (Host Name)
    ctx.font = '600 15px Inter, sans-serif';
    ctx.fillStyle = '#F3F4F6';
    ctx.textAlign = 'left';
    ctx.textBaseline = 'top';
    const nameStr = hub.name || 'HOST';
    ctx.fillText(nameStr, x + 14, y + 50);

    // 5. IP Address
    ctx.font = '12px Inter, sans-serif';
    ctx.fillStyle = '#9CA3AF';
    ctx.fillText(hub.ip, x + 14, y + 68);

    // 6. Severity Badge (top-right)
    const sevText = hub.worstSeverity ? hub.worstSeverity.charAt(0).toUpperCase() + hub.worstSeverity.slice(1) : 'Secure';
    const isSecure = hub.worstSeverity === 'low';
    ctx.font = '500 11px Inter, sans-serif';
    const badgeTextWidth = ctx.measureText(sevText).width;
    const badgeWidth = badgeTextWidth + 24; // text + dot + padding
    const badgeHeight = 22;
    const badgeX = x + w - 14 - badgeWidth;
    const badgeY = y + 14;

    ctx.fillStyle = isSecure ? 'rgba(16, 185, 129, 0.15)' : (hub.worstSeverity === 'critical' ? 'rgba(239, 68, 68, 0.15)' : 'rgba(245, 158, 11, 0.15)');
    ctx.beginPath();
    ctx.roundRect(badgeX, badgeY, badgeWidth, badgeHeight, 11);
    ctx.fill();

    // Badge Dot
    ctx.fillStyle = isSecure ? '#10b981' : (hub.worstSeverity === 'critical' ? '#ef4444' : '#f59e0b');
    ctx.beginPath();
    ctx.arc(badgeX + 10, badgeY + badgeHeight / 2, 3, 0, Math.PI * 2);
    ctx.fill();

    // Badge Text
    ctx.fillStyle = isSecure ? '#34d399' : (hub.worstSeverity === 'critical' ? '#f87171' : '#fbbf24');
    ctx.fillText(sevText, badgeX + 18, badgeY + 5.5);

    ctx.restore();
  });
}
