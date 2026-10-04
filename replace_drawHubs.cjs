const fs = require('fs');

const newDrawHubs = `
/**
 * Draws all distinct host hubs as rounded rectangles (Stitch design)
 */
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
`;

let code = fs.readFileSync('src/components/dashboard/LiveWireGraph.jsx', 'utf8');
const drawHubsStart = code.indexOf('function drawHubs(ctx, engine)');
let drawHubsEnd = code.indexOf('}', drawHubsStart);

// Find the end of the drawHubs function properly (since it has nested braces)
let braces = 0;
for (let i = drawHubsStart; i < code.length; i++) {
  if (code[i] === '{') braces++;
  else if (code[i] === '}') {
    braces--;
    if (braces === 0) {
      drawHubsEnd = i + 1;
      break;
    }
  }
}

code = code.substring(0, drawHubsStart) + newDrawHubs.trim() + code.substring(drawHubsEnd);
fs.writeFileSync('src/components/dashboard/LiveWireGraph.jsx', code);
