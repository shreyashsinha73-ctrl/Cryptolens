const fs = require('fs');
let code = fs.readFileSync('src/components/dashboard/LiveWireGraph.jsx', 'utf8');

// 1. Add hubCounter initialization
code = code.replace(
  'recentAlertsCount: 0,',
  'recentAlertsCount: 0,\n    hubCounter: 0,'
);

// 2. Add hubCounter reset
code = code.replace(
  'e.recentAlertsCount = 0;',
  'e.recentAlertsCount = 0;\n      e.hubCounter = 0;'
);

// 3. Assign name to srcHub
code = code.replace(
  /engine\.hubs\.set\(srcIp, \{\n\s*ip: srcIp,/g,
  "engine.hubCounter = (engine.hubCounter || 0) + 1;\n    engine.hubs.set(srcIp, {\n      name: `HOST ${engine.hubCounter}`,\n      ip: srcIp,"
);

// 4. Assign name to dstHub
code = code.replace(
  /engine\.hubs\.set\(dstIp, \{\n\s*ip: dstIp,/g,
  "engine.hubCounter = (engine.hubCounter || 0) + 1;\n    engine.hubs.set(dstIp, {\n      name: `HOST ${engine.hubCounter}`,\n      ip: dstIp,"
);

fs.writeFileSync('src/components/dashboard/LiveWireGraph.jsx', code);
