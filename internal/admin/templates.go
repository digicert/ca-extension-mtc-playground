// Copyright (C) 2026 DigiCert, Inc.
//
// Licensed under the dual-license model:
//   1. GNU Affero General Public License v3.0 (AGPL v3) — see LICENSE.txt
//   2. DigiCert Commercial License — see LICENSE_COMMERCIAL.txt
//
// For commercial licensing, contact sales@digicert.com.

package admin

const dashboardHTML = `<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>MTC Bridge — Admin Dashboard</title>
	<script src="https://cdn.tailwindcss.com"></script>
	<script src="https://unpkg.com/htmx.org@2.0.4"></script>
	<script src="https://unpkg.com/htmx-ext-sse@2.2.2/sse.js"></script>
</head>
<body class="bg-gray-50 min-h-screen">
	<nav class="bg-indigo-700 text-white px-6 py-4 shadow">
		<div class="flex items-center justify-between max-w-7xl mx-auto">
			<h1 class="text-xl font-bold">MTC Bridge Dashboard</h1>
			<div class="flex gap-4 text-sm">
				<a href="/admin" class="font-semibold underline">Dashboard</a>
				<a href="/admin/certs" class="opacity-75 hover:opacity-100">Certificates</a>
				<a href="/admin/viz" class="opacity-75 hover:opacity-100">Visualization</a>
			</div>
		</div>
	</nav>

	<main class="max-w-7xl mx-auto px-6 py-8">
		<!-- Stats Panel -->
		<section class="bg-white rounded-lg shadow p-6 mb-8"
			hx-get="/admin/stats" hx-trigger="every 5s" hx-swap="innerHTML">
			<h2 class="text-lg font-semibold mb-4">Log Statistics</h2>
			<div class="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-6">
				<div>
					<p class="text-gray-500 text-sm">Tree Size</p>
					<p class="text-2xl font-bold">{{ .Stats.TreeSize }}</p>
				</div>
				<div>
					<p class="text-gray-500 text-sm">Revocations</p>
					<p class="text-2xl font-bold">{{ .Stats.RevocationCount }}</p>
				</div>
				<div>
					<p class="text-gray-500 text-sm">Checkpoints</p>
					<p class="text-2xl font-bold">{{ .Stats.CheckpointCount }}</p>
				</div>
				<div>
					<p class="text-gray-500 text-sm">Watcher</p>
					<p class="text-2xl font-bold">{{ if .WatcherStats.Running }}
						<span class="text-green-600">Running</span>
					{{ else }}
						<span class="text-red-600">Stopped</span>
					{{ end }}</p>
				</div>
				<div>
					<p class="text-gray-500 text-sm">Certs Processed</p>
					<p class="text-2xl font-bold">{{ .WatcherStats.CertsProcessed }}</p>
				</div>
				<div>
					<p class="text-gray-500 text-sm">Latest Checkpoint</p>
					<p class="text-sm font-medium mt-1">{{ formatTime .Stats.LatestCheckpoint }}</p>
				</div>
			</div>
			<h2 class="text-lg font-semibold mb-4 mt-6">Assertion Issuer</h2>
			<div class="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-6">
				<div>
					<p class="text-gray-500 text-sm">Total Bundles</p>
					<p class="text-2xl font-bold">{{ .AssertionStats.TotalBundles }}</p>
				</div>
				<div>
					<p class="text-gray-500 text-sm">Fresh</p>
					<p class="text-2xl font-bold text-green-600">{{ .AssertionStats.FreshBundles }}</p>
				</div>
				<div>
					<p class="text-gray-500 text-sm">Stale</p>
					<p class="text-2xl font-bold text-amber-600">{{ .AssertionStats.StaleBundles }}</p>
				</div>
				<div>
					<p class="text-gray-500 text-sm">Pending</p>
					<p class="text-2xl font-bold text-blue-600">{{ .AssertionStats.PendingEntries }}</p>
				</div>
				<div>
					<p class="text-gray-500 text-sm">Last Generated</p>
					<p class="text-sm font-medium mt-1">{{ formatTime .AssertionStats.LastGenerated }}</p>
				</div>
				<div>
					<p class="text-gray-500 text-sm">Last Run</p>
					<p class="text-sm font-medium mt-1">{{ .IssuerStats.LastRunDuration }}</p>
				</div>
			</div>
			<h2 class="text-lg font-semibold mb-4 mt-6">Log Integrity</h2>
			<div class="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-6">
				<div>
					<p class="text-gray-500 text-sm">Proof Depth</p>
					<p class="text-2xl font-bold">{{ .ProofDepth }}</p>
				</div>
				<div>
					<p class="text-gray-500 text-sm">Landmarks</p>
					<p class="text-2xl font-bold">{{ .LandmarkCount }}</p>
				</div>
				<div>
					<p class="text-gray-500 text-sm">Consistency</p>
					<p class="text-2xl font-bold"><a href="/admin/viz?tab=consistency&old={{ .VerifyLinkOld }}&new={{ .VerifyLinkNew }}" class="{{ .VerifyClass }} hover:underline">{{ .VerifyStatus }}</a></p>
				</div>
				<div>
					<p class="text-gray-500 text-sm">Proof Range</p>
					<p class="text-sm font-medium mt-1">1 → {{ .Stats.TreeSize }}</p>
				</div>
				<div class="col-span-2">
					<p class="text-gray-500 text-sm">Last Verified</p>
					<p class="text-sm font-medium mt-1">{{ .VerifyDetail }}</p>
				</div>
			</div>
		</section>

		<div class="grid md:grid-cols-2 gap-8">
			<!-- Recent Checkpoints -->
			<section class="bg-white rounded-lg shadow p-6">
				<h2 class="text-lg font-semibold mb-4">Recent Checkpoints</h2>
				<table class="w-full">
					<thead>
						<tr class="border-b text-left text-gray-500 text-sm">
							<th class="px-2 py-1">ID</th>
							<th class="px-2 py-1">Tree Size</th>
							<th class="px-2 py-1">Root Hash</th>
							<th class="px-2 py-1">Time</th>
						</tr>
					</thead>
					<tbody hx-get="/admin/checkpoints" hx-trigger="every 10s" hx-swap="innerHTML">
						{{ range .Checkpoints }}
						<tr class="border-b">
							<td class="px-2 py-1 text-sm">{{ .ID }}</td>
							<td class="px-2 py-1 font-mono text-sm">{{ .TreeSize }}</td>
							<td class="px-2 py-1 font-mono text-xs">{{ truncHash .RootHash }}</td>
							<td class="px-2 py-1 text-xs text-gray-500">{{ formatTime .CreatedAt }}</td>
						</tr>
						{{ end }}
					</tbody>
				</table>
			</section>

			<!-- Recent Events -->
			<section class="bg-white rounded-lg shadow p-6">
				<h2 class="text-lg font-semibold mb-4">Recent Events</h2>
				<div hx-ext="sse" sse-connect="/admin/sse" sse-swap="message">
				<table class="w-full">
					<thead>
						<tr class="border-b text-left text-gray-500 text-sm">
							<th class="px-2 py-1">ID</th>
							<th class="px-2 py-1">Type</th>
							<th class="px-2 py-1">Time</th>
						</tr>
					</thead>
					<tbody hx-get="/admin/events" hx-trigger="every 10s" hx-swap="innerHTML">
						{{ range .Events }}
						<tr class="border-b">
							<td class="px-2 py-1 text-sm">{{ .ID }}</td>
							<td class="px-2 py-1"><span class="px-2 py-0.5 rounded bg-blue-100 text-blue-800 text-xs">{{ .EventType }}</span></td>
							<td class="px-2 py-1 text-xs text-gray-500">{{ formatTime .CreatedAt }}</td>
						</tr>
						{{ end }}
					</tbody>
				</table>
				</div>
			</section>
		</div>

		<!-- Recent Consistency Proofs -->
		<section class="bg-white rounded-lg shadow p-6 mt-8">
			<h2 class="text-lg font-semibold mb-4">Recent Consistency Proofs</h2>
			<table class="w-full">
				<thead>
					<tr class="border-b text-left text-gray-500 text-sm">
						<th class="px-2 py-1">Old Size</th>
						<th class="px-2 py-1">New Size</th>
						<th class="px-2 py-1">Hashes</th>
						<th class="px-2 py-1">Time</th>
					</tr>
				</thead>
				<tbody hx-get="/admin/consistency-proofs" hx-trigger="load, every 10s" hx-swap="innerHTML">
				</tbody>
			</table>
		</section>
	</main>

	<footer class="text-center text-gray-400 text-sm py-8">
		mtc-bridge — Experimental MTC support for DigiCert Private CA
	</footer>
</body>
</html>`

const certBrowserHTML = `<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>MTC Bridge — Certificate Browser</title>
	<script src="https://cdn.tailwindcss.com"></script>
	<script src="https://unpkg.com/htmx.org@2.0.4"></script>
</head>
<body class="bg-gray-50 min-h-screen">
	<nav class="bg-indigo-700 text-white px-6 py-4 shadow">
		<div class="flex items-center justify-between max-w-7xl mx-auto">
			<h1 class="text-xl font-bold">MTC Bridge Dashboard</h1>
			<div class="flex gap-4 text-sm">
				<a href="/admin" class="opacity-75 hover:opacity-100">Dashboard</a>
				<a href="/admin/certs" class="font-semibold underline">Certificates</a>
				<a href="/admin/viz" class="opacity-75 hover:opacity-100">Visualization</a>
			</div>
		</div>
	</nav>

	<main class="max-w-7xl mx-auto px-6 py-8">
		<div class="bg-white rounded-lg shadow p-6">
			<div class="flex items-center justify-between mb-6">
				<h2 class="text-lg font-semibold">Certificate Browser</h2>
				<div class="flex items-center gap-3">
					<div class="flex rounded-lg border overflow-hidden text-sm" id="status-filter">
						<button type="button"
							class="px-3 py-2 bg-indigo-600 text-white font-medium"
							hx-get="/admin/certs/search"
							hx-target="#cert-results"
							hx-include="#cert-search"
							onclick="setFilter(this, '')">
							All
						</button>
						<button type="button"
							class="px-3 py-2 text-gray-600 hover:bg-gray-100"
							hx-get="/admin/certs/search?status=revoked"
							hx-target="#cert-results"
							hx-include="#cert-search"
							onclick="setFilter(this, 'revoked')">
							Revoked
						</button>
					</div>
					<input type="text" name="q" id="cert-search"
						placeholder="Search by serial number..."
						class="px-4 py-2 border rounded-lg text-sm w-80"
						hx-get="/admin/certs/search"
						hx-trigger="keyup changed delay:300ms"
						hx-target="#cert-results"
						hx-vals="js:{status: window._certStatusFilter || ''}">
				</div>
			</div>
			<script>
				window._certStatusFilter = '';
				function setFilter(btn, value) {
					window._certStatusFilter = value;
					document.querySelectorAll('#status-filter button').forEach(function(b) {
						b.className = 'px-3 py-2 text-gray-600 hover:bg-gray-100';
					});
					btn.className = 'px-3 py-2 bg-indigo-600 text-white font-medium';
				}
			</script>
			<table class="w-full">
				<thead>
					<tr class="border-b text-left text-gray-500 text-sm">
						<th class="px-3 py-2">Index</th>
						<th class="px-3 py-2">Serial Number</th>
						<th class="px-3 py-2">Created</th>
						<th class="px-3 py-2">Status</th>
					</tr>
				</thead>
				<tbody id="cert-results"
					hx-get="/admin/certs/search"
					hx-trigger="load"
					hx-swap="innerHTML">
				</tbody>
			</table>
		</div>
	</main>

	<footer class="text-center text-gray-400 text-sm py-8">
		mtc-bridge — Experimental MTC support for DigiCert Private CA
	</footer>
`

const certDetailStartHTML = `<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>MTC Bridge — Certificate #%d</title>
	<script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-50 min-h-screen">
	<nav class="bg-indigo-700 text-white px-6 py-4 shadow">
		<div class="flex items-center justify-between max-w-7xl mx-auto">
			<h1 class="text-xl font-bold">MTC Bridge Dashboard</h1>
			<div class="flex gap-4 text-sm">
				<a href="/admin" class="opacity-75 hover:opacity-100">Dashboard</a>
				<a href="/admin/certs" class="opacity-75 hover:opacity-100">Certificates</a>
				<a href="/admin/viz" class="opacity-75 hover:opacity-100">Visualization</a>
			</div>
		</div>
	</nav>
	<main class="max-w-7xl mx-auto px-6 py-8">
		<div class="mb-4"><a href="/admin/certs" class="text-indigo-600 hover:underline text-sm">← Back to certificates</a></div>
`

const certDetailEndHTML = `
	</main>
	<footer class="text-center text-gray-400 text-sm py-8">
		mtc-bridge — Experimental MTC support for DigiCert Private CA
	</footer>
</body>
</html>`

const vizExplorerHTML = `<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>MTC Bridge — Visualization</title>
	<script src="https://cdn.tailwindcss.com"></script>
	<style>
		*{margin:0;padding:0;box-sizing:border-box}
		.viz-body{background:#0a0e1a;color:#e2e8f0;min-height:calc(100vh - 56px);overflow-x:hidden}
		.tabs{display:flex;justify-content:center;gap:4px;padding:10px 16px}
		.tab{padding:8px 20px;border-radius:8px;border:1px solid #334155;background:#1e293b;color:#94a3b8;cursor:pointer;font-size:.85rem;transition:all .2s}
		.tab:hover{background:#334155}
		.tab.active{background:linear-gradient(135deg,#38bdf8,#818cf8);color:#0a0e1a;border-color:transparent;font-weight:600}
		.controls{display:flex;justify-content:center;gap:8px;padding:6px 16px 10px;flex-wrap:wrap}
		.controls button,.controls select{padding:6px 14px;border-radius:8px;border:1px solid #334155;background:#1e293b;color:#e2e8f0;font-size:.8rem;cursor:pointer;transition:all .2s}
		.controls button:hover{background:#334155}
		.btn-g{background:linear-gradient(135deg,#34d399,#22d3ee)!important;color:#0a0e1a!important;border:none!important;font-weight:600}
		.stats{display:flex;gap:10px;justify-content:center;padding:0 16px 8px;flex-wrap:wrap}
		.st{background:#1e293b;border-radius:8px;padding:5px 14px;font-size:.75rem;color:#94a3b8;text-align:center}
		.st .v{font-size:1rem;font-weight:700;color:#e2e8f0}
		.st .v.g{color:#34d399}.st .v.r{color:#f87171}.st .v.b{color:#38bdf8}.st .v.p{color:#a78bfa}
		.main-viz{display:flex;height:calc(100vh - 280px);min-height:480px}
		.viz{flex:1;position:relative;overflow:hidden}
		.viz canvas{display:block}
		.side{width:300px;background:#111827;border-left:1px solid #1e293b;overflow-y:auto;padding:14px;flex-shrink:0}
		.side h3{font-size:.9rem;color:#38bdf8;margin-bottom:8px;display:flex;align-items:center;gap:6px}
		.breadcrumb{display:flex;gap:4px;padding:0 16px 6px;flex-wrap:wrap;align-items:center}
		.crumb{padding:3px 10px;border-radius:6px;font-size:.75rem;background:#1e293b;color:#94a3b8;cursor:pointer;transition:all .2s}
		.crumb:hover{background:#334155}
		.crumb.current{color:#38bdf8;border:1px solid #38bdf8}
		.crumb-sep{color:#475569;font-size:.7rem}
		.detail-card{background:#1e293b;border-radius:10px;padding:12px;margin-bottom:8px;border-left:4px solid #38bdf8;font-size:.78rem;line-height:1.6}
		.detail-card.rev{border-left-color:#f87171;background:#1c1520}
		.detail-card .domain{font-weight:600;color:#e2e8f0;font-size:.88rem}
		.detail-card .meta{color:#64748b;margin-top:3px}
		.tag{display:inline-block;padding:2px 8px;border-radius:99px;font-size:.7rem;font-weight:600;margin-top:4px}
		.tag.valid{background:#064e3b;color:#34d399}
		.tag.revoked{background:#450a0a;color:#f87171}
		.tag.pq{background:#1e1b4b;color:#a78bfa}
		.tag.classical{background:#172554;color:#60a5fa}
		.tip{position:fixed;background:#1e293b;border:1px solid #475569;border-radius:10px;padding:12px 16px;font-size:.8rem;color:#e2e8f0;pointer-events:none;z-index:200;display:none;max-width:360px;box-shadow:0 8px 32px rgba(0,0,0,.5);line-height:1.6}
		.legend-row{display:flex;gap:12px;justify-content:center;padding:6px 16px;flex-wrap:wrap}
		.leg{display:flex;align-items:center;gap:5px;font-size:.73rem;color:#94a3b8}
		.leg-c{width:12px;height:12px;border-radius:3px}
		.loading-msg{text-align:center;color:#94a3b8;padding:60px 20px;font-size:1rem}
		.merkle-node-group{cursor:pointer}
		.merkle-node-rect{rx:10;ry:10;transition:all .3s}
		.merkle-node-group:hover .merkle-node-rect{filter:brightness(1.3)}
		.merkle-node-label{font-family:system-ui,sans-serif;font-size:11px;fill:#e2e8f0;text-anchor:middle;pointer-events:none}
		.merkle-node-hash{font-family:'Courier New',monospace;font-size:9.5px;fill:#94a3b8;text-anchor:middle;pointer-events:none}
		.merkle-edge{stroke:#475569;stroke-width:2;fill:none}
		.merkle-edge.highlighted{stroke:#fbbf24;stroke-width:3;filter:drop-shadow(0 0 4px rgba(251,191,36,.5))}
		.merkle-node-rect.highlighted{filter:drop-shadow(0 0 8px rgba(251,191,36,.6))}
		#merkleSvgContainer{scrollbar-width:thin;scrollbar-color:#334155 #0a0e1a}
		#merkleSvgContainer::-webkit-scrollbar{width:8px;height:8px}
		#merkleSvgContainer::-webkit-scrollbar-track{background:#0a0e1a}
		#merkleSvgContainer::-webkit-scrollbar-thumb{background:#334155;border-radius:4px}
		@media(max-width:768px){.main-viz{flex-direction:column;height:auto}.side{width:100%;border-left:none;border-top:1px solid #1e293b;max-height:300px}.viz{min-height:400px}}
	</style>
</head>
<body class="bg-gray-50 min-h-screen">
	<nav class="bg-indigo-700 text-white px-6 py-4 shadow">
		<div class="flex items-center justify-between max-w-7xl mx-auto">
			<h1 class="text-xl font-bold">MTC Bridge Dashboard</h1>
			<div class="flex gap-4 text-sm">
				<a href="/admin" class="opacity-75 hover:opacity-100">Dashboard</a>
				<a href="/admin/certs" class="opacity-75 hover:opacity-100">Certificates</a>
				<a href="/admin/viz" class="font-semibold underline">Visualization</a>
			</div>
		</div>
	</nav>

	<div class="viz-body">
		<div class="tabs" style="padding-top:14px">
			<div class="tab active" id="tabSunburst" onclick="switchView('sunburst')">Sunburst</div>
			<div class="tab" id="tabTreemap" onclick="switchView('treemap')">Treemap</div>
			<div class="tab" id="tabProof" onclick="switchView('proof')">Proof Explorer</div>
			<div class="tab" id="tabMerkle" onclick="switchView('merkle')">Merkle Tree</div>
			<div class="tab" id="tabConsistency" onclick="switchView('consistency')">Consistency</div>
		</div>
		<div class="controls" id="vizControls">
			<button class="btn-g" onclick="drillUp()">Drill Up</button>
			<button onclick="resetView()">Reset</button>
			<select id="colorMode" onchange="redraw()">
				<option value="status">Color: Trust Status</option>
				<option value="algorithm">Color: Key Algorithm</option>
				<option value="age">Color: Certificate Age</option>
				<option value="assertion">Color: Assertion Coverage</option>
			</select>
			<button id="btnRevoked" onclick="toggleRevokedHighlight()" style="border:1px solid #f87171;color:#f87171">Highlight Revoked</button>
			<button onclick="loadData()">Refresh</button>
		</div>
		<div class="controls" id="proofControls" style="display:none">
			<input type="number" id="proofIndex" placeholder="Enter leaf index..." min="0" style="padding:6px 14px;border-radius:8px;border:1px solid #334155;background:#1e293b;color:#e2e8f0;font-size:.85rem;width:200px" onkeydown="if(event.key==='Enter')loadProof()">
			<button class="btn-g" onclick="loadProof()">Show Proof</button>
			<span id="proofStatus" style="color:#64748b;font-size:.8rem;align-self:center"></span>
		</div>
		<div class="controls" id="merkleControls" style="display:none">
			<button onclick="merklePrev()">← Prev</button>
			<button onclick="merkleNext()">Next →</button>
			<input type="number" id="merkleStartInput" placeholder="Jump to index..." min="0" style="padding:6px 14px;border-radius:8px;border:1px solid #334155;background:#1e293b;color:#e2e8f0;font-size:.85rem;width:160px" onkeydown="if(event.key==='Enter')merkleJump()">
			<button class="btn-g" onclick="merkleJump()">Go</button>
			<select id="merkleSize" onchange="merkleSizeChanged()" style="padding:6px 14px;border-radius:8px;border:1px solid #334155;background:#1e293b;color:#e2e8f0;font-size:.8rem">
				<option value="4">4 Leaves</option>
				<option value="8" selected>8 Leaves</option>
				<option value="16">16 Leaves</option>
			</select>
			<button onclick="verifyMerkleRandom()" style="background:linear-gradient(135deg,#34d399,#22d3ee);color:#0a0e1a;border:none;font-weight:600">Verify Proof</button>
			<span id="merkleStatus" style="color:#64748b;font-size:.8rem;align-self:center"></span>
		</div>
		<div class="controls" id="consistencyControls" style="display:none">
			<select id="oldSizeSelect" style="padding:6px 14px;border-radius:8px;border:1px solid #334155;background:#1e293b;color:#e2e8f0;font-size:.85rem;width:220px">
				<option value="">Old tree size...</option>
			</select>
			<span style="color:#64748b;font-size:1rem;align-self:center">→</span>
			<select id="newSizeSelect" style="padding:6px 14px;border-radius:8px;border:1px solid #334155;background:#1e293b;color:#e2e8f0;font-size:.85rem;width:220px">
				<option value="">New tree size...</option>
			</select>
			<button class="btn-g" onclick="loadConsistencyProof()">Verify Consistency</button>
			<span id="consistencyStatus" style="color:#64748b;font-size:.8rem;align-self:center"></span>
		</div>
		<div class="stats" id="statsBar"></div>
		<div class="breadcrumb" id="breadcrumb"></div>
		<div class="legend-row" id="legendRow"></div>
		<div class="main-viz">
			<div class="viz" id="vizPanel">
				<canvas id="canvas"></canvas>
				<div id="merkleSvgContainer" style="display:none;width:100%;height:100%;overflow:auto;padding:20px 10px"></div>
				<div class="loading-msg" id="loadingMsg">Loading visualization data...</div>
			</div>
			<div class="side">
				<h3 id="sideTitle">Details</h3>
				<div id="sideContent"></div>
			</div>
		</div>
	</div>
	<div class="tip" id="tip"></div>

	<script>
	// ─── STATE ───
	let hierarchy = null;
	let revokedSet = new Set();
	let vizStats = null;
	let drillPath = [];
	let currentNode = null;
	let viewMode = 'sunburst';
	let hoveredSegment = null;
	let segments = [];
	let leafCertsCache = {};
	let highlightRevoked = false;
	let proofData = null;
	let proofSegments = [];
	let consistencyData = null;
	let consistencySegments = [];
	let checkpointsList = null;

	// ─── MERKLE TREE STATE ───
	let merkleSubtreeData = null;
	let merkleHighlightedNodes = new Set();
	let merkleHighlightedEdges = new Set();
	let merkleSubtreeStart = 0;
	let merkleSubtreeSize = 8;

	const canvas = document.getElementById('canvas');
	const ctx = canvas.getContext('2d');

	// ─── DATA LOADING ───
	async function loadData() {
		document.getElementById('loadingMsg').style.display = 'block';
		try {
			const [summaryRes, revokedRes, statsRes] = await Promise.all([
				fetch('/admin/viz/summary'),
				fetch('/admin/viz/revocations'),
				fetch('/admin/viz/stats'),
			]);
			const summaryData = await summaryRes.json();
			const revokedData = await revokedRes.json();
			vizStats = await statsRes.json();

			revokedSet = new Set(revokedData.revokedIndices || []);
			hierarchy = transformNode(summaryData);
			currentNode = hierarchy;
			drillPath = [hierarchy];

			renderStats();
			renderBreadcrumb();
			document.getElementById('loadingMsg').style.display = 'none';
			redraw();
			renderSidePanel(null);
		} catch (err) {
			console.error('Failed to load visualization data:', err);
			document.getElementById('loadingMsg').textContent = 'Failed to load data. Retrying in 3s...';
			setTimeout(loadData, 3000);
		}
	}

	function transformNode(node) {
		if (!node) return null;
		const result = {
			name: node.name || 'Unknown',
			level: node.level === 'root' ? 0 : node.level === 'ca' ? 1 : node.level === 'batch' ? 2 : 3,
			levelName: node.level || 'root',
			certCount: node.certCount || 0,
			revokedCount: node.revokedCount || 0,
			pqCount: node.pqCount || 0,
			classicalCount: node.classicalCount || 0,
			freshCount: node.freshCount || 0,
			staleCount: node.staleCount || 0,
			missingCount: node.missingCount || 0,
			color: node.color || '#475569',
			children: (node.children || []).map(ch => transformNode(ch)),
			path: [],
		};
		return result;
	}

	// ─── COLORS ───
	function nodeRevRatio(node) {
		return node.certCount > 0 ? node.revokedCount / node.certCount : 0;
	}
	function nodePQRatio(node) {
		return node.certCount > 0 ? node.pqCount / node.certCount : 0;
	}
	function groupColor(node) {
		const mode = document.getElementById('colorMode').value;
		if (mode === 'assertion') {
			const total = node.certCount || 1;
			const freshRatio = (node.freshCount || 0) / total;
			const staleRatio = (node.staleCount || 0) / total;
			const missingRatio = (node.missingCount || 0) / total;
			if (freshRatio > 0.8) return '#22c55e';
			if (missingRatio > 0.5) return '#ef4444';
			if (staleRatio > 0.3) return '#f59e0b';
			return '#3b82f6';
		}
		return node.color || '#475569';
	}

	function certDotColor(cert) {
		const mode = document.getElementById('colorMode').value;
		const rev = cert.revoked;
		if (mode === 'status') {
			if (rev) return {fill:'#991b1b',stroke:'#f87171'};
			return {fill:'#065f46',stroke:'#34d399'};
		}
		if (mode === 'algorithm') {
			if (cert.isPQ) return {fill:rev?'#4a1942':'#312e81',stroke:rev?'#f87171':'#a78bfa'};
			return {fill:rev?'#4a1942':'#172554',stroke:rev?'#f87171':'#60a5fa'};
		}
		if (mode === 'assertion') {
			// For individual certs, we don't have per-cert assertion status in the leaf view,
			// so color based on the parent node's assertion coverage
			return {fill: rev ? '#991b1b' : '#1e3a5f', stroke: rev ? '#f87171' : '#3b82f6'};
		}
		// age — use issuedAt
		const age = cert.issuedAt ? (Date.now() - new Date(cert.issuedAt).getTime()) / 86400000 : 7;
		const t = Math.min(age / 14, 1);
		const r = Math.round(52 + t * 200), g = Math.round(211 - t * 160), b = Math.round(153 - t * 100);
		return {fill:rev?'#991b1b':'rgb('+Math.round(r*.25)+','+Math.round(g*.25)+','+Math.round(b*.25)+')',stroke:rev?'#f87171':'rgb('+r+','+g+','+b+')'};
	}

	// ─── SUNBURST ───
	function drawSunburst() {
		const W = canvas.width / devicePixelRatio, H = canvas.height / devicePixelRatio;
		const cx = W / 2, cy = H / 2;
		const maxR = Math.min(W, H) / 2 - 30;
		const node = currentNode;
		const children = node.children || [];
		if (!children.length) { drawLeafGrid(); return; }

		segments = [];
		const total = children.reduce((s, ch) => s + ch.certCount, 0);
		if (!total) {
			ctx.fillStyle = '#475569'; ctx.textAlign = 'center'; ctx.font = '14px system-ui';
			ctx.fillText('No certificates in tree', cx, cy);
			return;
		}

		// Center circle
		const innerR = maxR * 0.18;
		ctx.beginPath(); ctx.arc(cx, cy, innerR, 0, Math.PI * 2);
		ctx.fillStyle = '#1e293b'; ctx.fill();
		ctx.strokeStyle = '#334155'; ctx.lineWidth = 2; ctx.stroke();
		ctx.fillStyle = '#e2e8f0'; ctx.font = 'bold 13px system-ui'; ctx.textAlign = 'center';
		ctx.fillText(node.name, cx, cy - 6);
		ctx.fillStyle = '#94a3b8'; ctx.font = '11px system-ui';
		ctx.fillText(total.toLocaleString() + ' certs', cx, cy + 12);

		// Ring 1: children
		let angle = -Math.PI / 2;
		const gap = 0.008;
		children.forEach((ch) => {
			const sweep = (ch.certCount / total) * Math.PI * 2 - gap;
			if (sweep <= 0) return;
			const r1 = innerR + 6, r2 = maxR * 0.48;
			const rr = nodeRevRatio(ch);
			const baseColor = groupColor(ch);

			ctx.beginPath(); ctx.arc(cx, cy, r2, angle, angle + sweep); ctx.arc(cx, cy, r1, angle + sweep, angle, true); ctx.closePath();
			const dimmed = highlightRevoked && rr === 0;
			const grad = ctx.createRadialGradient(cx, cy, r1, cx, cy, r2);
			grad.addColorStop(0, baseColor + (dimmed ? '10' : '40')); grad.addColorStop(1, baseColor + (dimmed ? '20' : '90'));
			ctx.fillStyle = grad; ctx.fill();
			ctx.strokeStyle = dimmed ? baseColor + '30' : baseColor; ctx.lineWidth = 1; ctx.stroke();

			if (rr > 0) {
				const revAlpha = highlightRevoked ? '90' : '50';
				ctx.beginPath(); ctx.arc(cx, cy, r2, angle, angle + sweep * rr); ctx.arc(cx, cy, r1, angle + sweep * rr, angle, true); ctx.closePath();
				ctx.fillStyle = '#f87171' + revAlpha; ctx.fill();
				ctx.strokeStyle = '#f87171'; ctx.lineWidth = highlightRevoked ? 2.5 : 1.5; ctx.stroke();
			}

			const midA = angle + sweep / 2;
			const labelR = (r1 + r2) / 2;
			const lx = cx + Math.cos(midA) * labelR, ly = cy + Math.sin(midA) * labelR;
			if (sweep > 0.15) {
				ctx.save(); ctx.translate(lx, ly);
				let rot = midA; if (rot > Math.PI / 2 || rot < -Math.PI / 2) rot += Math.PI;
				ctx.rotate(rot);
				ctx.fillStyle = '#e2e8f0'; ctx.font = Math.min(11, Math.max(7, sweep * 30)) + 'px system-ui'; ctx.textAlign = 'center';
				const label = ch.name.length > 18 ? ch.name.slice(0, 16) + '\u2026' : ch.name;
				ctx.fillText(label, 0, 0);
				ctx.fillStyle = '#94a3b8'; ctx.font = Math.min(9, Math.max(6, sweep * 22)) + 'px system-ui';
				ctx.fillText(ch.certCount.toLocaleString(), 0, 12);
				ctx.restore();
			}

			segments.push({type:'arc',cx,cy,r1,r2,startAngle:angle,endAngle:angle+sweep,node:ch});

			// Ring 2: sub-children
			if (ch.children && ch.children.length) {
				const r3 = maxR * 0.48 + 4, r4 = maxR * 0.72;
				let subAngle = angle;
				const subTotal = ch.certCount;
				ch.children.forEach(sub => {
					const subSweep = (sub.certCount / subTotal) * sweep - gap * 0.5;
					if (subSweep <= 0.005) { subAngle += subSweep + gap * 0.5; return; }
					const subRR = nodeRevRatio(sub);
					ctx.beginPath(); ctx.arc(cx, cy, r4, subAngle, subAngle + subSweep); ctx.arc(cx, cy, r3, subAngle + subSweep, subAngle, true); ctx.closePath();
					const sg = ctx.createRadialGradient(cx, cy, r3, cx, cy, r4);
					sg.addColorStop(0, baseColor + '25'); sg.addColorStop(1, baseColor + '55');
					ctx.fillStyle = sg; ctx.fill();
					ctx.strokeStyle = baseColor + '80'; ctx.lineWidth = 0.5; ctx.stroke();
					if (subRR > 0) {
						ctx.beginPath(); ctx.arc(cx, cy, r4, subAngle, subAngle + subSweep * subRR); ctx.arc(cx, cy, r3, subAngle + subSweep * subRR, subAngle, true); ctx.closePath();
						ctx.fillStyle = '#f8717140'; ctx.fill();
					}
					if (subSweep > 0.08) {
						const smA = subAngle + subSweep / 2;
						const slr = (r3 + r4) / 2;
						const sx = cx + Math.cos(smA) * slr, sy = cy + Math.sin(smA) * slr;
						ctx.save(); ctx.translate(sx, sy);
						let sr = smA; if (sr > Math.PI / 2 || sr < -Math.PI / 2) sr += Math.PI;
						ctx.rotate(sr);
						ctx.fillStyle = '#cbd5e1'; ctx.font = Math.min(9, Math.max(6, subSweep * 25)) + 'px system-ui'; ctx.textAlign = 'center';
						ctx.fillText(sub.name.length > 14 ? sub.name.slice(0, 12) + '\u2026' : sub.name, 0, 0);
						ctx.restore();
					}
					segments.push({type:'arc',cx,cy,r1:r3,r2:r4,startAngle:subAngle,endAngle:subAngle+subSweep,node:sub});
					subAngle += subSweep + gap * 0.5;
				});
			}

			// Ring 3: PQ glow
			const r5 = maxR * 0.74, r6 = maxR * 0.82;
			const pqRatio = nodePQRatio(ch);
			if (pqRatio > 0) {
				ctx.beginPath(); ctx.arc(cx, cy, r6, angle, angle + sweep * pqRatio); ctx.arc(cx, cy, r5, angle + sweep * pqRatio, angle, true); ctx.closePath();
				ctx.fillStyle = '#a78bfa30'; ctx.fill();
				ctx.strokeStyle = '#a78bfa60'; ctx.lineWidth = 0.5; ctx.stroke();
			}

			angle += sweep + gap;
		});

		ctx.fillStyle = '#475569'; ctx.font = '9px system-ui'; ctx.textAlign = 'center';
		ctx.fillText('Outer glow = Post-Quantum algorithm ratio', cx, cy + maxR * 0.9);
	}

	// ─── TREEMAP ───
	function drawTreemap() {
		const W = canvas.width / devicePixelRatio, H = canvas.height / devicePixelRatio;
		const node = currentNode;
		const children = node.children || [];
		if (!children.length) { drawLeafGrid(); return; }

		segments = [];
		const items = children.map(ch => ({node:ch, value:ch.certCount})).filter(x => x.value > 0);
		if (!items.length) {
			ctx.fillStyle = '#475569'; ctx.textAlign = 'center'; ctx.font = '14px system-ui';
			ctx.fillText('No certificates in tree', W / 2, H / 2);
			return;
		}

		const rects = squarify(items.map(x => x.value), {x:8,y:8,w:W-16,h:H-16});

		items.forEach((item, i) => {
			const r = rects[i]; if (!r) return;
			const rr = nodeRevRatio(item.node);
			const baseColor = groupColor(item.node);
			const pad = 2;

			const dimmed = highlightRevoked && rr === 0;
			ctx.fillStyle = baseColor + (dimmed ? '08' : '20');
			ctx.strokeStyle = baseColor + (dimmed ? '30' : '80');
			ctx.lineWidth = 1.5;
			roundRect(ctx, r.x + pad, r.y + pad, r.w - pad * 2, r.h - pad * 2, 6);
			ctx.fill(); ctx.stroke();

			if (rr > 0) {
				const stripH = highlightRevoked ? Math.max(6, (r.h - pad * 2) * Math.max(rr, 0.15)) : Math.max(3, (r.h - pad * 2) * rr);
				ctx.fillStyle = highlightRevoked ? '#f8717160' : '#f8717130';
				roundRect(ctx, r.x + pad, r.y + r.h - pad - stripH, r.w - pad * 2, stripH, 0);
				ctx.fill();
				ctx.strokeStyle = '#f87171'; ctx.lineWidth = highlightRevoked ? 2 : 1;
				ctx.beginPath(); ctx.moveTo(r.x + pad, r.y + r.h - pad - stripH); ctx.lineTo(r.x + r.w - pad, r.y + r.h - pad - stripH); ctx.stroke();
				if (highlightRevoked) {
					ctx.strokeStyle = '#f87171'; ctx.lineWidth = 2;
					roundRect(ctx, r.x + pad, r.y + pad, r.w - pad * 2, r.h - pad * 2, 6); ctx.stroke();
				}
			}

			const pqR = nodePQRatio(item.node);
			if (pqR > 0 && r.w > 30) {
				const barW = (r.w - pad * 2 - 8) * pqR;
				ctx.fillStyle = '#a78bfa50';
				roundRect(ctx, r.x + pad + 4, r.y + pad + 4, barW, 4, 2); ctx.fill();
			}

			if (r.w > 50 && r.h > 30) {
				ctx.fillStyle = '#e2e8f0'; ctx.font = 'bold ' + Math.min(14, Math.max(9, r.w / 12)) + 'px system-ui'; ctx.textAlign = 'left';
				const name = item.node.name.length > Math.floor(r.w / 8) ? item.node.name.slice(0, Math.floor(r.w / 8) - 1) + '\u2026' : item.node.name;
				ctx.fillText(name, r.x + pad + 6, r.y + pad + 22);
				ctx.fillStyle = '#94a3b8'; ctx.font = Math.min(11, Math.max(7, r.w / 14)) + 'px system-ui';
				ctx.fillText(item.node.certCount.toLocaleString() + ' certs', r.x + pad + 6, r.y + pad + 36);
				if (rr > 0.001 && r.h > 50) {
					ctx.fillStyle = '#f87171';
					ctx.fillText((rr * 100).toFixed(1) + '% revoked', r.x + pad + 6, r.y + pad + 49);
				}
			}

			segments.push({type:'rect',x:r.x+pad,y:r.y+pad,w:r.w-pad*2,h:r.h-pad*2,node:item.node});
		});
	}

	// ─── LEAF GRID ───
	function drawLeafGrid() {
		const W = canvas.width / devicePixelRatio, H = canvas.height / devicePixelRatio;
		segments = [];

		if (!currentNode._certs || !currentNode._certs.length) {
			ctx.fillStyle = '#94a3b8'; ctx.textAlign = 'center'; ctx.font = '13px system-ui';
			ctx.fillText(currentNode.certCount > 0 ? 'Loading certificates...' : 'No certificates at this level', W / 2, H / 2);

			if (currentNode.certCount > 0 && !currentNode._loading) {
				currentNode._loading = true;
				loadLeafCerts();
			}
			return;
		}

		const certs = currentNode._certs;
		const pad = 12;
		const area = (W - pad * 2) * (H - pad * 2);
		const dotSize = Math.max(3, Math.min(16, Math.sqrt(area / certs.length) * 0.75));
		const cols = Math.floor((W - pad * 2) / (dotSize + 2));

		certs.forEach((cert, i) => {
			const col = i % cols, row = Math.floor(i / cols);
			const x = pad + col * (dotSize + 2);
			const y = pad + row * (dotSize + 2);
			if (y + dotSize > H) return;
			const cc = certDotColor(cert);
			const rev = cert.revoked;

			ctx.fillStyle = cc.fill; ctx.strokeStyle = cc.stroke; ctx.lineWidth = rev ? 2 : 0.5;
			ctx.beginPath(); ctx.roundRect(x, y, dotSize, dotSize, 2); ctx.fill(); ctx.stroke();

			if (rev && dotSize > 5) {
				ctx.strokeStyle = '#f87171'; ctx.lineWidth = 1.5;
				ctx.beginPath(); ctx.moveTo(x + 2, y + 2); ctx.lineTo(x + dotSize - 2, y + dotSize - 2);
				ctx.moveTo(x + dotSize - 2, y + 2); ctx.lineTo(x + 2, y + dotSize - 2); ctx.stroke();
			}

			segments.push({type:'rect',x,y,w:dotSize,h:dotSize,node:null,cert});
		});
	}

	async function loadLeafCerts() {
		const path = drillPath.map(n => n.name);
		const ca = path[1] || '';
		const batchNode = drillPath[2];
		const batch = (batchNode && batchNode.batch_key) || '';
		const algo = path[3] || '';
		const params = new URLSearchParams({ca, batch, algo, page: '1'});
		try {
			const res = await fetch('/admin/viz/certificates?' + params);
			const data = await res.json();
			currentNode._certs = data.certificates || [];
			currentNode._loading = false;
			redraw();
			renderSidePanel(currentNode);
		} catch (err) {
			console.error('Failed to load leaf certs:', err);
			currentNode._loading = false;
		}
	}

	// ─── SQUARIFY ───
	function squarify(values, rect) {
		const total = values.reduce((s, v) => s + v, 0);
		const rects = [];
		let remaining = [...values.map((v, i) => ({v, i}))];
		let {x, y, w, h} = rect;

		while (remaining.length) {
			const isWide = w >= h;
			const side = isWide ? h : w;
			let row = [], rowSum = 0;
			const areaLeft = remaining.reduce((s, r) => s + r.v, 0);

			for (let i = 0; i < remaining.length; i++) {
				const test = [...row, remaining[i]];
				const testSum = rowSum + remaining[i].v;
				const testArea = (testSum / total) * (rect.w * rect.h);
				const rowLen = testArea / side;
				const worst = Math.max(...test.map(t => {
					const s = (t.v / testSum) * side;
					return Math.max(rowLen / s, s / rowLen);
				}));
				if (row.length && worst > Math.max(...row.map(t => {
					const s = (t.v / rowSum) * side;
					const rl = (rowSum / total) * (rect.w * rect.h) / side;
					return Math.max(rl / s, s / rl);
				}))) { break; }
				row.push(remaining[i]); rowSum += remaining[i].v;
			}

			const rowArea = (rowSum / areaLeft) * (w * h);
			const rowLen = isWide ? rowArea / h : rowArea / w;
			let offset = 0;
			row.forEach(item => {
				const frac = item.v / rowSum;
				const s = frac * side;
				if (isWide) { rects[item.i] = {x, y: y + offset, w: rowLen, h: s}; }
				else { rects[item.i] = {x: x + offset, y, w: s, h: rowLen}; }
				offset += s;
			});

			remaining = remaining.slice(row.length);
			if (isWide) { x += rowLen; w -= rowLen; }
			else { y += rowLen; h -= rowLen; }
		}
		return rects;
	}

	function roundRect(c, x, y, w, h, r) {
		c.beginPath(); c.roundRect(x, y, w, h, r);
	}

	// ─── RENDER ───
	function resizeCanvas() {
		const panel = document.getElementById('vizPanel');
		canvas.width = panel.clientWidth * devicePixelRatio;
		canvas.height = panel.clientHeight * devicePixelRatio;
		canvas.style.width = panel.clientWidth + 'px';
		canvas.style.height = panel.clientHeight + 'px';
		ctx.setTransform(devicePixelRatio, 0, 0, devicePixelRatio, 0, 0);
	}

	function redraw() {
		if (viewMode === 'merkle') {
			renderMerkleTree();
			renderMerkleLegend();
			return;
		}
		resizeCanvas();
		ctx.clearRect(0, 0, canvas.width, canvas.height);
		if (viewMode === 'proof') {
			drawProofTree();
			renderProofLegend();
			return;
		}
		if (viewMode === 'consistency') {
			drawConsistencyProof();
			renderConsistencyLegend();
			return;
		}
		if (!hierarchy) return;
		if (viewMode === 'sunburst') drawSunburst();
		else drawTreemap();
		renderLegend();
	}

	function renderStats() {
		if (!vizStats) return;
		const s = vizStats;
		document.getElementById('statsBar').innerHTML =
			'<div class="st"><div class="v b">' + s.total.toLocaleString() + '</div>Total Certs</div>' +
			'<div class="st"><div class="v g">' + s.valid.toLocaleString() + '</div>Valid</div>' +
			'<div class="st"><div class="v r">' + s.revoked.toLocaleString() + '</div>Revoked</div>' +
			'<div class="st"><div class="v p">' + s.pqCount.toLocaleString() + '</div>Post-Quantum</div>' +
			'<div class="st"><div class="v">' + s.caCount + '</div>CAs</div>' +
			'<div class="st"><div class="v">' + (s.revocationRate * 100).toFixed(2) + '%</div>Revocation Rate</div>' +
			'<div class="st"><div class="v g">' + ((s.coverageRate || 0) * 100).toFixed(1) + '%</div>Assertion Coverage</div>';
	}

	function renderBreadcrumb() {
		document.getElementById('breadcrumb').innerHTML = drillPath.map((n, i) => {
			const isCurrent = i === drillPath.length - 1;
			return (i > 0 ? '<span class="crumb-sep">\u203a</span>' : '') +
				'<span class="crumb ' + (isCurrent ? 'current' : '') + '" onclick="drillTo(' + i + ')">' + n.name + '</span>';
		}).join('');
	}

	function renderLegend() {
		const mode = document.getElementById('colorMode').value;
		let items = [];
		if (mode === 'status') {
			items = [{c:'#34d399',l:'Valid'},{c:'#f87171',l:'Revoked'}];
		} else if (mode === 'algorithm') {
			items = [{c:'#a78bfa',l:'Post-Quantum (ML-DSA)'},{c:'#60a5fa',l:'Classical (ECDSA/Ed25519/RSA)'}];
		} else if (mode === 'assertion') {
			items = [{c:'#22c55e',l:'Fresh (>80%)'},{c:'#f59e0b',l:'Stale (>30%)'},{c:'#ef4444',l:'Missing (>50%)'},{c:'#3b82f6',l:'Mixed'}];
		} else {
			items = [{c:'#34d399',l:'Fresh (0 days)'},{c:'#f59e0b',l:'Mid-life (~7 days)'},{c:'#f87171',l:'Expiring (~14 days)'}];
		}
		if (mode !== 'assertion') items.push({c:'#a78bfa40',l:'PQ Ratio (outer ring / top bar)'});
		document.getElementById('legendRow').innerHTML = items.map(i =>
			'<div class="leg"><div class="leg-c" style="background:' + i.c + '"></div>' + i.l + '</div>'
		).join('');
	}

	function renderSidePanel(node, cert) {
		const title = document.getElementById('sideTitle');
		const content = document.getElementById('sideContent');

		if (cert) {
			title.textContent = 'Certificate Detail';
			const rev = cert.revoked;
			content.innerHTML = '<div class="detail-card ' + (rev ? 'rev' : '') + '">' +
				'<div class="domain">' + (cert.commonName || cert.serialHex || 'Certificate #' + cert.index) + '</div>' +
				'<div class="meta">' +
				'CA: ' + (cert.ca || 'Unknown') + '<br>' +
				'Algorithm: ' + (cert.algorithm || 'Unknown') + ' ' + (cert.isPQ ? '(Post-Quantum)' : '(Classical)') + '<br>' +
				'Issued: ' + (cert.issuedAt || 'Unknown') + '<br>' +
				'Batch: ' + (cert.batchWindow || 'Unknown') + '<br>' +
				'Index: #' + cert.index +
				'</div>' +
				'<span class="tag ' + (rev ? 'revoked' : 'valid') + '">' + (rev ? 'REVOKED' : 'VALID') + '</span> ' +
				'<span class="tag ' + (cert.isPQ ? 'pq' : 'classical') + '">' + (cert.isPQ ? 'Post-Quantum' : 'Classical') + '</span>' +
				'<div style="margin-top:8px"><a href="/admin/certs/' + cert.index + '" style="color:#38bdf8;font-size:.8rem">View full details \u2192</a></div>' +
				'</div>';
			return;
		}

		if (!node || node === hierarchy) {
			title.textContent = 'Overview';
			if (!hierarchy || !hierarchy.children || !hierarchy.children.length) {
				content.innerHTML = '<div style="color:#64748b;padding:20px;text-align:center">No certificate data available yet.<br>Certificates will appear here as they are processed.</div>';
				return;
			}
			// Revocation summary card at the top
			const totalRev = hierarchy.revokedCount;
			const totalCerts = hierarchy.certCount;
			const revPct = totalCerts ? ((totalRev / totalCerts) * 100).toFixed(2) : '0.00';
			let html = '<div style="background:#1c1017;border:1px solid #991b1b;border-radius:10px;padding:14px;margin-bottom:12px">' +
				'<div style="display:flex;justify-content:space-between;align-items:center">' +
				'<div><div style="color:#f87171;font-size:.75rem;font-weight:600;text-transform:uppercase;letter-spacing:.05em">Revocations</div>' +
				'<div style="font-size:1.5rem;font-weight:700;color:#f87171">' + totalRev.toLocaleString() + '</div></div>' +
				'<div style="text-align:right"><div style="color:#64748b;font-size:.72rem">' + revPct + '% of ' + totalCerts.toLocaleString() + '</div>' +
				'<div style="width:80px;height:6px;background:#1e293b;border-radius:3px;margin-top:4px;overflow:hidden">' +
				'<div style="width:' + Math.max(1, Math.min(100, parseFloat(revPct))) + '%;height:100%;background:#f87171;border-radius:3px"></div></div></div></div>';
			// Per-CA revocation breakdown
			const casSorted = [...hierarchy.children].filter(g => g.revokedCount > 0).sort((a, b) => b.revokedCount - a.revokedCount);
			if (casSorted.length) {
				html += '<div style="margin-top:10px">';
				casSorted.forEach(g => {
					const pct = g.certCount ? ((g.revokedCount / g.certCount) * 100).toFixed(1) : 0;
					html += '<div style="display:flex;justify-content:space-between;align-items:center;padding:4px 0;font-size:.75rem">' +
						'<span style="color:#e2e8f0">' + g.name + '</span>' +
						'<span style="color:#f87171;font-weight:600">' + g.revokedCount + ' (' + pct + '%)</span></div>';
				});
				html += '</div>';
			}
			html += '</div>';
			// Assertion coverage summary
			const freshC = hierarchy.freshCount || 0;
			const staleC = hierarchy.staleCount || 0;
			const missingC = hierarchy.missingCount || 0;
			const covPct = totalCerts ? ((freshC / totalCerts) * 100).toFixed(1) : '0.0';
			html += '<div style="background:#0c1a10;border:1px solid #166534;border-radius:10px;padding:14px;margin-bottom:12px">' +
				'<div style="display:flex;justify-content:space-between;align-items:center">' +
				'<div><div style="color:#22c55e;font-size:.75rem;font-weight:600;text-transform:uppercase;letter-spacing:.05em">Assertion Coverage</div>' +
				'<div style="font-size:1.5rem;font-weight:700;color:#22c55e">' + covPct + '%</div></div>' +
				'<div style="text-align:right;font-size:.72rem;color:#64748b">' +
				'<div style="color:#22c55e">' + freshC.toLocaleString() + ' fresh</div>' +
				'<div style="color:#f59e0b">' + staleC.toLocaleString() + ' stale</div>' +
				'<div style="color:#ef4444">' + missingC.toLocaleString() + ' missing</div>' +
				'</div></div></div>';

			// CA overview cards
			html += '<h3 style="color:#94a3b8;margin:8px 0 6px;font-size:.78rem">Certificate Authorities</h3>';
			html += hierarchy.children.sort((a, b) => b.certCount - a.certCount).map(g => {
				const rr = g.certCount ? ((g.revokedCount / g.certCount) * 100).toFixed(1) : 0;
				return '<div class="detail-card" style="border-left-color:' + g.color + '">' +
					'<div class="domain">' + g.name + '</div>' +
					'<div class="meta">' + g.certCount.toLocaleString() + ' certs \u00b7 ' + g.pqCount + ' PQ \u00b7 ' + rr + '% revoked</div>' +
					(g.revokedCount ? '<span class="tag revoked">' + g.revokedCount + ' revoked</span> ' : '<span class="tag valid">Clean</span> ') +
					(g.pqCount ? '<span class="tag pq">' + ((g.pqCount / g.certCount) * 100).toFixed(0) + '% PQ</span>' : '') +
					'</div>';
			}).join('');
			content.innerHTML = html;
			return;
		}

		title.textContent = node.name;
		let html = '<div class="detail-card">' +
			'<div class="domain">' + node.name + '</div>' +
			'<div class="meta">' + node.certCount.toLocaleString() + ' certificates<br>' +
			node.revokedCount + ' revoked (' + (node.certCount ? ((node.revokedCount / node.certCount) * 100).toFixed(1) : 0) + '%)<br>' +
			node.pqCount + ' post-quantum (' + (node.certCount ? ((node.pqCount / node.certCount) * 100).toFixed(0) : 0) + '%)</div>' +
			'</div>';

		if (node.children && node.children.length) {
			html += '<h3 style="color:#94a3b8;margin:10px 0 6px;font-size:.8rem">Children (' + node.children.length + ')</h3>';
			node.children.sort((a, b) => b.certCount - a.certCount).slice(0, 20).forEach(ch => {
				html += '<div class="detail-card" style="border-left-color:' + ch.color + ';cursor:pointer" onclick="drillIntoByName(\'' + ch.name.replace(/'/g, "\\'") + '\')">' +
					'<div class="domain">' + ch.name + '</div>' +
					'<div class="meta">' + ch.certCount.toLocaleString() + ' certs \u00b7 ' + ch.revokedCount + ' revoked</div></div>';
			});
		}
		content.innerHTML = html;
	}

	// ─── INTERACTION ───
	canvas.addEventListener('click', e => {
		const rect = canvas.getBoundingClientRect();
		const mx = e.clientX - rect.left, my = e.clientY - rect.top;
		for (const seg of segments) {
			if (seg.type === 'rect') {
				if (mx >= seg.x && mx <= seg.x + seg.w && my >= seg.y && my <= seg.y + seg.h) {
					if (seg.cert) { renderSidePanel(null, seg.cert); return; }
					if (seg.node && seg.node.children && seg.node.children.length) {
						currentNode = seg.node; drillPath.push(seg.node);
						renderBreadcrumb(); redraw(); renderSidePanel(seg.node);
						return;
					}
					if (seg.node) { renderSidePanel(seg.node); return; }
				}
			} else if (seg.type === 'arc') {
				const dx = mx - seg.cx, dy = my - seg.cy;
				const dist = Math.sqrt(dx * dx + dy * dy);
				let a = Math.atan2(dy, dx);
				if (dist >= seg.r1 && dist <= seg.r2) {
					let sa = seg.startAngle;
					while (a < sa) a += Math.PI * 2;
					if (a <= seg.endAngle) {
						if (seg.node.children && seg.node.children.length) {
							currentNode = seg.node; drillPath.push(seg.node);
							renderBreadcrumb(); redraw(); renderSidePanel(seg.node);
						} else { renderSidePanel(seg.node); }
						return;
					}
				}
			}
		}
	});

	canvas.addEventListener('mousemove', e => {
		const rect = canvas.getBoundingClientRect();
		const mx = e.clientX - rect.left, my = e.clientY - rect.top;
		const tip = document.getElementById('tip');
		let found = false;

		// Handle proof explorer tooltips
		if (viewMode === 'proof' && proofData) {
			for (const seg of proofSegments) {
				if (mx >= seg.x && mx <= seg.x + seg.w && my >= seg.y && my <= seg.y + seg.h) {
					found = true;
					canvas.style.cursor = 'pointer';
					tip.innerHTML = '<strong>' + seg.label + '</strong>' +
						(seg.hash ? '<br><span style="font-family:monospace;font-size:.75rem;color:#60a5fa">' + seg.hash + '</span>' : '<br><em style="color:#64748b">Intermediate computed hash</em>');
					tip.style.display = 'block';
					tip.style.left = Math.min(e.clientX + 14, window.innerWidth - 380) + 'px';
					tip.style.top = (e.clientY - 10) + 'px';
					break;
				}
			}
			if (!found) { canvas.style.cursor = 'default'; tip.style.display = 'none'; }
			return;
		}

		// Handle consistency proof tooltips
		if (viewMode === 'consistency' && consistencyData) {
			for (const seg of consistencySegments) {
				if (mx >= seg.x && mx <= seg.x + seg.w && my >= seg.y && my <= seg.y + seg.h) {
					found = true;
					canvas.style.cursor = 'pointer';
					tip.innerHTML = '<strong>' + seg.label + '</strong>' +
						(seg.hash ? '<br><span style="font-family:monospace;font-size:.75rem;color:#60a5fa">' + seg.hash + '</span>' : '');
					tip.style.display = 'block';
					tip.style.left = Math.min(e.clientX + 14, window.innerWidth - 380) + 'px';
					tip.style.top = (e.clientY - 10) + 'px';
					break;
				}
			}
			if (!found) { canvas.style.cursor = 'default'; tip.style.display = 'none'; }
			return;
		}

		for (const seg of segments) {
			let hit = false;
			if (seg.type === 'rect') {
				hit = mx >= seg.x && mx <= seg.x + seg.w && my >= seg.y && my <= seg.y + seg.h;
			} else if (seg.type === 'arc') {
				const dx = mx - seg.cx, dy = my - seg.cy;
				const dist = Math.sqrt(dx * dx + dy * dy);
				let a = Math.atan2(dy, dx);
				if (dist >= seg.r1 && dist <= seg.r2) {
					while (a < seg.startAngle) a += Math.PI * 2;
					hit = a <= seg.endAngle;
				}
			}
			if (hit) {
				found = true;
				canvas.style.cursor = 'pointer';
				let html = '';
				if (seg.cert) {
					const c = seg.cert;
					html = '<strong>' + (c.commonName || 'Cert #' + c.index) + '</strong><br>' + (c.ca || '') + ' \u00b7 ' + (c.algorithm || '') +
						'<br>' + (c.revoked ? '<span style="color:#f87171">REVOKED</span>' : '<span style="color:#34d399">Valid</span>');
				} else if (seg.node) {
					const n = seg.node;
					html = '<strong>' + n.name + '</strong><br>' + n.certCount.toLocaleString() + ' certs \u00b7 ' + n.revokedCount + ' revoked (' + (n.certCount ? ((n.revokedCount / n.certCount) * 100).toFixed(1) : 0) + '%)' +
						'<br>' + n.pqCount + ' post-quantum' +
						(n.children && n.children.length ? '<br><em style="color:#64748b">Click to drill down</em>' : '');
				}
				tip.innerHTML = html;
				tip.style.display = 'block';
				tip.style.left = Math.min(e.clientX + 14, window.innerWidth - 380) + 'px';
				tip.style.top = (e.clientY - 10) + 'px';
				break;
			}
		}
		if (!found) { canvas.style.cursor = 'default'; tip.style.display = 'none'; }
	});
	canvas.addEventListener('mouseleave', () => { document.getElementById('tip').style.display = 'none'; });

	// ─── MERKLE TREE ───
	async function loadMerkleSubtree() {
		document.getElementById('merkleStatus').textContent = 'Loading...';
		try {
			const res = await fetch('/admin/viz/subtree?start=' + merkleSubtreeStart + '&size=' + merkleSubtreeSize);
			if (!res.ok) { document.getElementById('merkleStatus').textContent = 'Failed to load subtree'; return; }
			merkleSubtreeData = await res.json();
			merkleSubtreeStart = merkleSubtreeData.subtreeStart;
			merkleHighlightedNodes.clear();
			merkleHighlightedEdges.clear();
			renderMerkleTree();
			renderMerkleSidePanel();
			updateMerkleStatus();
		} catch (err) {
			document.getElementById('merkleStatus').textContent = 'Error: ' + err.message;
		}
	}

	function updateMerkleStatus() {
		if (!merkleSubtreeData) return;
		const d = merkleSubtreeData;
		const end = Math.min(d.subtreeStart + d.subtreeSize, d.treeSize);
		document.getElementById('merkleStatus').style.color = '#94a3b8';
		document.getElementById('merkleStatus').textContent = 'Entries ' + d.subtreeStart + '\u2013' + (end - 1) + ' of ' + d.treeSize.toLocaleString();
	}

	function renderMerkleTree() {
		const container = document.getElementById('merkleSvgContainer');
		if (!merkleSubtreeData || merkleSubtreeData.levels.length === 0) {
			container.innerHTML = '<p style="text-align:center;color:#64748b;padding:60px 20px">No entries in the log. Loading...</p>';
			return;
		}
		// levels[0] = leaves, levels[last] = subtree root; reverse for top-down rendering
		const dataLevels = merkleSubtreeData.levels;
		const levels = [...dataLevels].reverse();
		const nodeW = 130, nodeH = 52;
		const hGap = 16, vGap = 60;
		const maxLeaves = levels[levels.length - 1].nodes.length;
		const svgW = Math.max(maxLeaves * (nodeW + hGap), 400);
		const svgH = levels.length * (nodeH + vGap) + 40;

		// Position leaves at bottom
		let positions = [];
		for (let l = 0; l < levels.length; l++) positions.push([]);

		const bottomIdx = levels.length - 1;
		const leafNodes = levels[bottomIdx].nodes;
		const totalLeafW = leafNodes.length * nodeW + (leafNodes.length - 1) * hGap;
		const leafStartX = (svgW - totalLeafW) / 2;
		leafNodes.forEach((node, i) => {
			positions[bottomIdx][i] = { x: leafStartX + i * (nodeW + hGap) + nodeW / 2, y: bottomIdx * (nodeH + vGap) + 20 };
		});

		// Position interior nodes by centering over children
		for (let l = levels.length - 2; l >= 0; l--) {
			const childPositions = positions[l + 1];
			levels[l].nodes.forEach((node, i) => {
				const leftIdx = i * 2;
				const rightIdx = i * 2 + 1;
				const leftPos = childPositions[leftIdx];
				const rightPos = childPositions[rightIdx] || leftPos;
				positions[l][i] = { x: (leftPos.x + rightPos.x) / 2, y: l * (nodeH + vGap) + 20 };
			});
		}

		let edgesHTML = '';
		let nodesHTML = '';

		// Edges: parent to children
		for (let l = 0; l < levels.length - 1; l++) {
			const childLevel = levels[l + 1];
			levels[l].nodes.forEach((node, i) => {
				const pPos = positions[l][i];
				const leftIdx = i * 2;
				const rightIdx = i * 2 + 1;
				[leftIdx, rightIdx].forEach(ci => {
					if (ci < childLevel.nodes.length) {
						const cPos = positions[l + 1][ci];
						const edgeId = node.hash.slice(0, 8) + '-' + childLevel.nodes[ci].hash.slice(0, 8);
						const hl = merkleHighlightedEdges.has(edgeId) ? ' highlighted' : '';
						edgesHTML += '<path class="merkle-edge' + hl + '" d="M' + pPos.x + ',' + (pPos.y + nodeH) + ' C' + pPos.x + ',' + (pPos.y + nodeH + vGap / 2) + ' ' + cPos.x + ',' + (cPos.y - vGap / 2) + ' ' + cPos.x + ',' + cPos.y + '"/>';
					}
				});
			});
		}

		// Nodes
		levels.forEach((lvl, l) => {
			const isLeafLevel = l === levels.length - 1;
			const isRootLevel = l === 0 && lvl.nodes.length === 1;
			lvl.nodes.forEach((node, i) => {
				const pos = positions[l][i];
				let fill;
				if (isRootLevel) fill = 'url(#merkleRootGrad)';
				else if (isLeafLevel) fill = 'url(#merkleLeafGrad)';
				else fill = 'url(#merkleIntGrad)';
				const hl = merkleHighlightedNodes.has(node.hash) ? ' highlighted' : '';
				const shortHash = node.hash.slice(0, 10) + '...';
				let label;
				if (isRootLevel) label = 'Subtree Root';
				else if (isLeafLevel) {
					const cn = node.commonName || '';
					label = cn.length > 14 ? cn.slice(0, 13) + '...' : (cn || '#' + node.index);
				} else {
					label = 'L' + lvl.level + ' #' + node.index;
				}
				const extra = node.commonName ? ' data-cn="' + node.commonName + '" data-ca="' + (node.ca || '') + '" data-algo="' + (node.algorithm || '') + '" data-revoked="' + (node.revoked || false) + '"' : '';
				nodesHTML += '<g class="merkle-node-group" data-hash="' + node.hash + '" data-label="' + label + '" data-index="' + node.index + '" data-level="' + lvl.level + '"' + extra + ' onmouseenter="showMerkleTooltip(event,this)" onmouseleave="hideMerkleTooltip()">' +
					'<rect class="merkle-node-rect' + hl + '" x="' + (pos.x - nodeW / 2) + '" y="' + pos.y + '" width="' + nodeW + '" height="' + nodeH + '" fill="' + fill + '" stroke="' + (merkleHighlightedNodes.has(node.hash) ? '#fbbf24' : (node.revoked ? '#f87171' : '#475569')) + '" stroke-width="' + (merkleHighlightedNodes.has(node.hash) ? 2 : 1) + '"/>' +
					'<text class="merkle-node-label" x="' + pos.x + '" y="' + (pos.y + 20) + '">' + label + '</text>' +
					'<text class="merkle-node-hash" x="' + pos.x + '" y="' + (pos.y + 36) + '">' + shortHash + '</text></g>';
			});
		});

		container.innerHTML = '<svg width="' + svgW + '" height="' + svgH + '" viewBox="0 0 ' + svgW + ' ' + svgH + '">' +
			'<defs>' +
			'<linearGradient id="merkleRootGrad" x1="0%" y1="0%" x2="100%" y2="100%"><stop offset="0%" style="stop-color:#f59e0b"/><stop offset="100%" style="stop-color:#f97316"/></linearGradient>' +
			'<linearGradient id="merkleIntGrad" x1="0%" y1="0%" x2="100%" y2="100%"><stop offset="0%" style="stop-color:#6366f1"/><stop offset="100%" style="stop-color:#818cf8"/></linearGradient>' +
			'<linearGradient id="merkleLeafGrad" x1="0%" y1="0%" x2="100%" y2="100%"><stop offset="0%" style="stop-color:#0ea5e9"/><stop offset="100%" style="stop-color:#38bdf8"/></linearGradient>' +
			'</defs>' + edgesHTML + nodesHTML + '</svg>';
	}

	function showMerkleTooltip(e, el) {
		const tip = document.getElementById('tip');
		const hash = el.getAttribute('data-hash');
		const label = el.getAttribute('data-label');
		const idx = el.getAttribute('data-index');
		const level = el.getAttribute('data-level');
		const cn = el.getAttribute('data-cn');
		const ca = el.getAttribute('data-ca');
		const algo = el.getAttribute('data-algo');
		const revoked = el.getAttribute('data-revoked') === 'true';
		let html = '<strong>' + label + '</strong>';
		if (cn) {
			html += '<br>CN: ' + cn;
			if (ca) html += '<br>CA: ' + ca;
			if (algo) html += '<br>Algorithm: ' + algo;
			if (revoked) html += '<br><span style="color:#f87171;font-weight:600">REVOKED</span>';
		}
		html += '<br><span style="color:#64748b;font-size:.72rem">Level ' + level + ', Index ' + idx + '</span>';
		html += '<div style="font-family:monospace;font-size:.75rem;color:#38bdf8;word-break:break-all;margin-top:4px">' + hash + '</div>';
		tip.innerHTML = html;
		tip.style.display = 'block';
		tip.style.left = Math.min(e.clientX + 14, window.innerWidth - 380) + 'px';
		tip.style.top = (e.clientY - 10) + 'px';
	}
	function hideMerkleTooltip() { document.getElementById('tip').style.display = 'none'; }

	function merklePrev() {
		if (merkleSubtreeStart <= 0) return;
		merkleSubtreeStart = Math.max(0, merkleSubtreeStart - merkleSubtreeSize);
		loadMerkleSubtree();
	}
	function merkleNext() {
		if (!merkleSubtreeData) return;
		if (merkleSubtreeStart + merkleSubtreeSize < merkleSubtreeData.treeSize) {
			merkleSubtreeStart += merkleSubtreeSize;
			loadMerkleSubtree();
		}
	}
	function merkleJump() {
		const idx = parseInt(document.getElementById('merkleStartInput').value, 10);
		if (!isNaN(idx) && idx >= 0) {
			merkleSubtreeStart = idx;
			loadMerkleSubtree();
		}
	}
	function merkleSizeChanged() {
		merkleSubtreeSize = parseInt(document.getElementById('merkleSize').value, 10);
		loadMerkleSubtree();
	}

	function verifyMerkleRandom() {
		if (!merkleSubtreeData || merkleSubtreeData.levels.length === 0) return;
		const leaves = merkleSubtreeData.levels[0].nodes;
		if (leaves.length < 2) return;
		merkleHighlightedNodes.clear();
		merkleHighlightedEdges.clear();
		const leafIdx = Math.floor(Math.random() * leaves.length);
		const leaf = leaves[leafIdx];
		merkleHighlightedNodes.add(leaf.hash);
		// Walk up levels highlighting proof path
		let curIdx = leafIdx;
		for (let l = 0; l < merkleSubtreeData.levels.length - 1; l++) {
			const sibIdx = curIdx ^ 1;
			const parentIdx = curIdx >> 1;
			const curLevel = merkleSubtreeData.levels[l];
			const parentLevel = merkleSubtreeData.levels[l + 1];
			if (sibIdx < curLevel.nodes.length) {
				merkleHighlightedNodes.add(curLevel.nodes[sibIdx].hash);
				if (parentIdx < parentLevel.nodes.length) {
					merkleHighlightedEdges.add(parentLevel.nodes[parentIdx].hash.slice(0, 8) + '-' + curLevel.nodes[sibIdx].hash.slice(0, 8));
				}
			}
			if (parentIdx < parentLevel.nodes.length) {
				merkleHighlightedNodes.add(parentLevel.nodes[parentIdx].hash);
				merkleHighlightedEdges.add(parentLevel.nodes[parentIdx].hash.slice(0, 8) + '-' + curLevel.nodes[curIdx].hash.slice(0, 8));
			}
			curIdx = parentIdx;
		}
		renderMerkleTree();
		const label = leaf.commonName || ('Entry #' + leaf.index);
		const status = document.getElementById('merkleStatus');
		status.style.color = '#34d399';
		status.textContent = 'Proof path for "' + label + '" (index ' + leaf.index + ') highlighted in gold';
	}

	function renderMerkleLegend() {
		const items = [
			{c:'linear-gradient(135deg,#f59e0b,#f97316)',l:'Subtree Root'},
			{c:'linear-gradient(135deg,#6366f1,#818cf8)',l:'Internal Node'},
			{c:'linear-gradient(135deg,#0ea5e9,#38bdf8)',l:'Leaf Node'},
			{c:'linear-gradient(135deg,#fbbf24,#f59e0b)',l:'Verification Path'},
		];
		document.getElementById('legendRow').innerHTML = items.map(i =>
			'<div class="leg"><div class="leg-c" style="background:' + i.c + '"></div>' + i.l + '</div>'
		).join('');
	}

	function renderMerkleSidePanel() {
		const title = document.getElementById('sideTitle');
		const content = document.getElementById('sideContent');
		title.textContent = 'Merkle Tree';
		if (!merkleSubtreeData || merkleSubtreeData.levels.length === 0) {
			content.innerHTML = '<div style="color:#64748b;padding:20px;text-align:center">Loading tree data...</div>';
			return;
		}
		const d = merkleSubtreeData;
		const leaves = d.levels[0].nodes;
		const subtreeRoot = d.levels[d.levels.length - 1].nodes[0];
		const totalNodes = d.levels.reduce((s, l) => s + l.nodes.length, 0);
		const end = Math.min(d.subtreeStart + d.subtreeSize, d.treeSize);

		let html = '<div class="detail-card" style="border-left-color:#f59e0b">' +
			'<div class="domain">Tree Overview</div>' +
			'<div class="meta">Total Entries: ' + d.treeSize.toLocaleString() + '<br>Viewing: ' + d.subtreeStart + ' \u2013 ' + (end - 1) +
			'<br>Subtree Nodes: ' + totalNodes + '<br>Depth: ' + d.levels.length + '</div></div>';

		html += '<div class="detail-card" style="border-left-color:#f97316">' +
			'<div style="font-size:.72rem;color:#64748b;text-transform:uppercase;letter-spacing:.05em;margin-bottom:4px">Global Root Hash</div>' +
			'<div style="font-family:monospace;font-size:.72rem;color:#f59e0b;word-break:break-all">' + d.globalRootHash + '</div></div>';

		if (subtreeRoot) {
			html += '<div class="detail-card" style="border-left-color:#818cf8">' +
				'<div style="font-size:.72rem;color:#64748b;text-transform:uppercase;letter-spacing:.05em;margin-bottom:4px">Subtree Root Hash</div>' +
				'<div style="font-family:monospace;font-size:.72rem;color:#818cf8;word-break:break-all">' + subtreeRoot.hash + '</div></div>';
		}

		html += '<div style="margin:10px 0 6px;font-size:.78rem;color:#94a3b8;font-weight:600">Leaf Entries (' + leaves.length + ')</div>';
		leaves.forEach(leaf => {
			const label = leaf.commonName || ('Entry #' + leaf.index);
			const revTag = leaf.revoked ? '<span class="tag revoked">Revoked</span>' : '<span class="tag valid">Valid</span>';
			const pqTag = leaf.isPQ ? ' <span class="tag pq">PQ</span>' : '';
			html += '<div class="detail-card' + (leaf.revoked ? ' rev' : '') + '" style="padding:8px 12px">' +
				'<div style="display:flex;justify-content:space-between;align-items:center">' +
				'<span class="domain" style="font-size:.82rem">' + label + '</span>' +
				'<span style="color:#64748b;font-size:.7rem">#' + leaf.index + '</span></div>' +
				(leaf.ca ? '<div class="meta">' + leaf.ca + (leaf.algorithm ? ' \u00b7 ' + leaf.algorithm : '') + '</div>' : '') +
				'<div style="margin-top:3px">' + revTag + pqTag + '</div>' +
				'<div style="font-family:monospace;font-size:.68rem;color:#38bdf8;word-break:break-all;margin-top:2px">' + leaf.hash + '</div></div>';
		});

		html += '<div class="detail-card" style="border-left-color:#818cf8;margin-top:12px">' +
			'<div class="domain">How It Works</div>' +
			'<div class="meta">Each leaf hashes a log entry with SHA-256. Parent nodes hash the concatenation of their children. ' +
			'This subtree shows ' + d.subtreeSize + ' consecutive entries from the transparency log. ' +
			'Use Prev/Next to navigate, or click "Verify Proof" to see an inclusion proof path.</div></div>';
		content.innerHTML = html;
	}

	// ─── CONSISTENCY PROOF ───
	async function loadCheckpoints() {
		if (checkpointsList) return;
		try {
			const res = await fetch('/admin/checkpoints/list');
			checkpointsList = await res.json();
			const oldSel = document.getElementById('oldSizeSelect');
			const newSel = document.getElementById('newSizeSelect');
			checkpointsList.forEach(cp => {
				const label = 'Size ' + cp.treeSize.toLocaleString() + ' (' + cp.time + ')';
				oldSel.add(new Option(label, cp.treeSize));
				newSel.add(new Option(label, cp.treeSize));
			});
			if (checkpointsList.length >= 2) {
				oldSel.value = checkpointsList[1].treeSize;
				newSel.value = checkpointsList[0].treeSize;
			}
		} catch (err) {
			console.error('Failed to load checkpoints:', err);
		}
	}

	async function loadConsistencyProof() {
		const oldSize = document.getElementById('oldSizeSelect').value;
		const newSize = document.getElementById('newSizeSelect').value;
		if (!oldSize || !newSize) {
			document.getElementById('consistencyStatus').textContent = 'Select both tree sizes';
			return;
		}
		document.getElementById('consistencyStatus').textContent = 'Computing proof...';
		try {
			const res = await fetch('/admin/viz/consistency?old=' + oldSize + '&new=' + newSize);
			if (!res.ok) {
				document.getElementById('consistencyStatus').textContent = await res.text();
				consistencyData = null;
				redraw();
				return;
			}
			consistencyData = await res.json();
			document.getElementById('consistencyStatus').textContent = '';
			redraw();
			renderConsistencySidePanel();
		} catch (err) {
			document.getElementById('consistencyStatus').textContent = 'Error: ' + err.message;
			consistencyData = null;
			redraw();
		}
	}

	function drawConsistencyProof() {
		const W = canvas.width / devicePixelRatio, H = canvas.height / devicePixelRatio;
		consistencySegments = [];

		if (!consistencyData) {
			ctx.fillStyle = '#94a3b8'; ctx.textAlign = 'center'; ctx.font = '14px system-ui';
			ctx.fillText('Select two checkpoints and click "Verify Consistency"', W / 2, H / 2 - 10);
			ctx.fillStyle = '#64748b'; ctx.font = '12px system-ui';
			ctx.fillText('Proves the old tree is a prefix of the new tree (RFC 9162 \u00a72.1.4)', W / 2, H / 2 + 14);
			return;
		}

		const d = consistencyData;
		const proofLen = d.proof.length;
		const nodeR = 24;

		// Two root nodes at the top
		const oldRootX = W * 0.25, newRootX = W * 0.75, rootY = 70;

		// Draw dashed arrow between roots
		ctx.strokeStyle = d.verified ? '#22c55e50' : '#f8717150';
		ctx.lineWidth = 2;
		ctx.setLineDash([6, 4]);
		ctx.beginPath();
		ctx.moveTo(oldRootX + nodeR + 15, rootY);
		ctx.lineTo(newRootX - nodeR - 15, rootY);
		ctx.stroke();
		ctx.setLineDash([]);

		// Arrow label
		ctx.fillStyle = d.verified ? '#22c55e' : '#f87171';
		ctx.font = 'bold 13px system-ui'; ctx.textAlign = 'center';
		ctx.fillText(d.verified ? 'CONSISTENT' : 'INCONSISTENT', W / 2, rootY - 12);
		ctx.fillStyle = '#64748b'; ctx.font = '10px system-ui';
		ctx.fillText(proofLen + ' proof hash' + (proofLen !== 1 ? 'es' : ''), W / 2, rootY + 6);

		// Draw old root
		drawConsistencyNode(oldRootX, rootY, nodeR, '#f59e0b', d.oldRoot,
			'Old Root (size ' + d.oldSize.toLocaleString() + ')', true);
		consistencySegments.push({
			x: oldRootX - nodeR, y: rootY - nodeR, w: nodeR * 2, h: nodeR * 2,
			hash: d.oldRoot, label: 'Old Root (size ' + d.oldSize + ')'
		});

		// Draw new root
		drawConsistencyNode(newRootX, rootY, nodeR, '#22c55e', d.newRoot,
			'New Root (size ' + d.newSize.toLocaleString() + ')', true);
		consistencySegments.push({
			x: newRootX - nodeR, y: rootY - nodeR, w: nodeR * 2, h: nodeR * 2,
			hash: d.newRoot, label: 'New Root (size ' + d.newSize + ')'
		});

		// Proof hashes as a vertical chain
		if (proofLen > 0) {
			const chainTop = rootY + 70;
			const chainHeight = H - chainTop - 50;
			const stepH = Math.min(55, chainHeight / proofLen);
			const nodeRSmall = 18;

			for (let i = 0; i < proofLen; i++) {
				const y = chainTop + i * stepH;
				const x = W / 2;

				// Connect to previous node
				if (i > 0) {
					ctx.strokeStyle = '#334155'; ctx.lineWidth = 1.5;
					ctx.beginPath();
					ctx.moveTo(x, y - nodeRSmall);
					ctx.lineTo(x, y - stepH + nodeRSmall);
					ctx.stroke();
				} else {
					// Connect first proof hash to both roots
					ctx.strokeStyle = '#f59e0b30'; ctx.lineWidth = 1.5;
					ctx.beginPath(); ctx.moveTo(oldRootX, rootY + nodeR); ctx.lineTo(x, y - nodeRSmall); ctx.stroke();
					ctx.strokeStyle = '#22c55e30';
					ctx.beginPath(); ctx.moveTo(newRootX, rootY + nodeR); ctx.lineTo(x, y - nodeRSmall); ctx.stroke();
				}

				drawConsistencyNode(x, y, nodeRSmall, '#3b82f6', d.proof[i],
					'Proof[' + i + ']', false);
				consistencySegments.push({
					x: x - nodeRSmall, y: y - nodeRSmall, w: nodeRSmall * 2, h: nodeRSmall * 2,
					hash: d.proof[i], label: 'Proof Hash [' + i + ']'
				});
			}
		}

		// Verification badge at bottom
		const badgeY = H - 28;
		ctx.fillStyle = d.verified ? '#22c55e' : '#f87171';
		ctx.font = 'bold 12px system-ui'; ctx.textAlign = 'center';
		ctx.fillText(
			d.verified ? '\u2713 Consistency Verified \u2014 old tree is a prefix of the new tree'
				: '\u2717 Verification Failed \u2014 trees are inconsistent',
			W / 2, badgeY
		);

		// Footer info
		ctx.fillStyle = '#475569'; ctx.font = '10px system-ui';
		ctx.fillText('Old Size: ' + d.oldSize.toLocaleString() + '  |  New Size: ' + d.newSize.toLocaleString() +
			'  |  Proof Depth: ' + proofLen + '  |  Tree Depth: ' + d.treeDepth, W / 2, H - 10);
	}

	function drawConsistencyNode(x, y, r, color, hash, label, highlight) {
		if (highlight) {
			ctx.beginPath(); ctx.arc(x, y, r + 5, 0, Math.PI * 2);
			ctx.fillStyle = color + '15'; ctx.fill();
		}
		ctx.beginPath(); ctx.arc(x, y, r, 0, Math.PI * 2);
		ctx.fillStyle = color + '25'; ctx.fill();
		ctx.strokeStyle = color; ctx.lineWidth = 2; ctx.stroke();
		if (hash) {
			ctx.fillStyle = '#e2e8f0'; ctx.font = 'bold 9px monospace'; ctx.textAlign = 'center';
			ctx.fillText(hash.substring(0, 8) + '...', x, y + 3);
		}
		ctx.fillStyle = '#94a3b8'; ctx.font = '9px system-ui'; ctx.textAlign = 'center';
		ctx.fillText(label, x, y + r + 14);
	}

	function renderConsistencyLegend() {
		const items = [
			{c:'#f59e0b', l:'Old Root Hash'},
			{c:'#22c55e', l:'New Root Hash'},
			{c:'#3b82f6', l:'Consistency Proof Hashes'},
		];
		document.getElementById('legendRow').innerHTML = items.map(i =>
			'<div class="leg"><div class="leg-c" style="background:' + i.c + '"></div>' + i.l + '</div>'
		).join('');
	}

	function renderConsistencySidePanel() {
		const title = document.getElementById('sideTitle');
		const content = document.getElementById('sideContent');
		if (!consistencyData) {
			title.textContent = 'Consistency Proof';
			content.innerHTML = '<div style="color:#64748b;padding:20px;text-align:center">Select two tree sizes to verify consistency.</div>';
			return;
		}
		const d = consistencyData;
		title.textContent = 'Consistency Proof';

		let html = '<div class="detail-card" style="border-left-color:' + (d.verified ? '#22c55e' : '#f87171') + '">' +
			'<div class="domain">' + (d.verified ? '\u2713 Verified' : '\u2717 FAILED') + '</div>' +
			'<div class="meta">' +
			'Old Size: ' + d.oldSize.toLocaleString() + '<br>' +
			'New Size: ' + d.newSize.toLocaleString() + '<br>' +
			'Proof Hashes: ' + d.proofLen + '<br>' +
			'Tree Growth: +' + (d.newSize - d.oldSize).toLocaleString() + ' entries</div></div>';

		html += '<div class="detail-card" style="border-left-color:#f59e0b">' +
			'<div style="font-size:.72rem;color:#64748b;text-transform:uppercase;letter-spacing:.05em;margin-bottom:4px">Old Root (size ' + d.oldSize.toLocaleString() + ')</div>' +
			'<div style="font-family:monospace;font-size:.68rem;color:#f59e0b;word-break:break-all">' + d.oldRoot + '</div></div>';

		html += '<div class="detail-card" style="border-left-color:#22c55e">' +
			'<div style="font-size:.72rem;color:#64748b;text-transform:uppercase;letter-spacing:.05em;margin-bottom:4px">New Root (size ' + d.newSize.toLocaleString() + ')</div>' +
			'<div style="font-family:monospace;font-size:.68rem;color:#22c55e;word-break:break-all">' + d.newRoot + '</div></div>';

		if (d.proof.length) {
			html += '<div style="margin:10px 0 6px;font-size:.78rem;color:#94a3b8;font-weight:600">Proof Hashes (' + d.proof.length + ')</div>';
			d.proof.forEach((h, i) => {
				html += '<div class="detail-card" style="border-left-color:#3b82f6;padding:8px 12px">' +
					'<span style="color:#94a3b8;font-size:.7rem">Hash ' + i + '</span>' +
					'<div style="font-family:monospace;font-size:.68rem;color:#60a5fa;word-break:break-all;margin-top:2px">' + h + '</div></div>';
			});
		}

		html += '<div class="detail-card" style="border-left-color:#818cf8;margin-top:12px">' +
			'<div class="domain">How It Works</div>' +
			'<div class="meta">A consistency proof (RFC 9162 \u00a72.1.4) proves that the old tree ' +
			'is a prefix of the new tree. The proof provides O(log n) intermediate hashes that allow ' +
			'reconstructing both the old and new root hashes, proving no entries were modified or removed. ' +
			'This is the append-only guarantee that makes transparency logs trustworthy.</div></div>';

		content.innerHTML = html;
	}

	// ─── ACTIONS ───
	function switchView(v) {
		viewMode = v;
		document.getElementById('tabSunburst').classList.toggle('active', v === 'sunburst');
		document.getElementById('tabTreemap').classList.toggle('active', v === 'treemap');
		document.getElementById('tabProof').classList.toggle('active', v === 'proof');
		document.getElementById('tabMerkle').classList.toggle('active', v === 'merkle');
		document.getElementById('tabConsistency').classList.toggle('active', v === 'consistency');
		// Show/hide controls per view
		document.getElementById('proofControls').style.display = v === 'proof' ? 'flex' : 'none';
		document.getElementById('merkleControls').style.display = v === 'merkle' ? 'flex' : 'none';
		document.getElementById('consistencyControls').style.display = v === 'consistency' ? 'flex' : 'none';
		document.getElementById('vizControls').style.display = (v === 'sunburst' || v === 'treemap') ? '' : 'none';
		// Toggle canvas vs SVG container
		canvas.style.display = v === 'merkle' ? 'none' : 'block';
		document.getElementById('merkleSvgContainer').style.display = v === 'merkle' ? 'block' : 'none';
		// Hide stats/breadcrumb for merkle/consistency view
		document.getElementById('statsBar').style.display = (v === 'merkle' || v === 'consistency') ? 'none' : '';
		document.getElementById('breadcrumb').style.display = (v === 'merkle' || v === 'consistency') ? 'none' : '';
		if (v === 'merkle') {
			renderMerkleLegend();
			if (!merkleSubtreeData) { loadMerkleSubtree(); }
			else { renderMerkleTree(); renderMerkleSidePanel(); updateMerkleStatus(); }
		} else if (v === 'consistency') {
			renderConsistencyLegend();
			loadCheckpoints();
			redraw();
			renderConsistencySidePanel();
		} else {
			redraw();
		}
	}
	function drillUp() {
		if (drillPath.length > 1) {
			drillPath.pop(); currentNode = drillPath[drillPath.length - 1];
			renderBreadcrumb(); redraw(); renderSidePanel(currentNode);
		}
	}
	function drillTo(idx) {
		drillPath = drillPath.slice(0, idx + 1); currentNode = drillPath[drillPath.length - 1];
		renderBreadcrumb(); redraw(); renderSidePanel(currentNode);
	}
	function drillIntoByName(name) {
		const child = (currentNode.children || []).find(ch => ch.name === name);
		if (child) {
			currentNode = child; drillPath.push(child);
			renderBreadcrumb(); redraw(); renderSidePanel(child);
		}
	}
	function resetView() {
		currentNode = hierarchy; drillPath = [hierarchy];
		renderBreadcrumb(); redraw(); renderSidePanel(null);
	}
	function toggleRevokedHighlight() {
		highlightRevoked = !highlightRevoked;
		const btn = document.getElementById('btnRevoked');
		if (highlightRevoked) {
			btn.style.background = '#991b1b';
			btn.style.color = '#f87171';
			btn.style.borderColor = '#f87171';
			btn.style.fontWeight = '600';
		} else {
			btn.style.background = '';
			btn.style.color = '#f87171';
			btn.style.borderColor = '#f87171';
			btn.style.fontWeight = '';
		}
		redraw();
	}

	// ─── PROOF EXPLORER ───
	async function loadProof() {
		const input = document.getElementById('proofIndex');
		const idx = parseInt(input.value, 10);
		if (isNaN(idx) || idx < 0) {
			document.getElementById('proofStatus').textContent = 'Please enter a valid leaf index';
			return;
		}
		document.getElementById('proofStatus').textContent = 'Loading proof...';
		try {
			const res = await fetch('/admin/viz/proof/' + idx);
			if (!res.ok) {
				const text = await res.text();
				document.getElementById('proofStatus').textContent = text || 'Failed to load proof';
				proofData = null;
				redraw();
				return;
			}
			proofData = await res.json();
			document.getElementById('proofStatus').textContent = '';
			redraw();
			renderProofSidePanel();
		} catch (err) {
			document.getElementById('proofStatus').textContent = 'Error: ' + err.message;
			proofData = null;
			redraw();
		}
	}

	function drawProofTree() {
		const W = canvas.width / devicePixelRatio, H = canvas.height / devicePixelRatio;
		proofSegments = [];

		if (!proofData) {
			ctx.fillStyle = '#94a3b8'; ctx.textAlign = 'center'; ctx.font = '14px system-ui';
			ctx.fillText('Enter a leaf index above and click "Show Proof" to explore the Merkle inclusion proof', W / 2, H / 2 - 10);
			ctx.fillStyle = '#64748b'; ctx.font = '12px system-ui';
			ctx.fillText('The proof path from leaf to root will be rendered as an interactive binary tree', W / 2, H / 2 + 14);
			return;
		}

		const depth = proofData.proofPath.length;
		if (depth === 0) {
			ctx.fillStyle = '#94a3b8'; ctx.textAlign = 'center'; ctx.font = '14px system-ui';
			ctx.fillText('Tree has only one entry — no proof path needed', W / 2, H / 2);
			return;
		}

		const topPad = 40, bottomPad = 40;
		const levelHeight = (H - topPad - bottomPad) / depth;
		const nodeRadius = Math.min(22, Math.max(14, W / (depth * 4)));

		// Draw from root (top) to leaf (bottom)
		// Proof path: proofPath[0] is the sibling at the leaf level,
		// proofPath[depth-1] is the sibling at the level just below root.
		// proofSides[i] tells whether the proof hash is "left" or "right" of the path node.

		// At each level (from leaf to root), we draw two nodes:
		// 1. The path node (the node in the inclusion path)
		// 2. The proof sibling node
		// Then connect them to their parent at the level above.

		const levels = depth + 1; // including root at top and leaf at bottom
		const nodePositions = []; // [{pathX, pathY, sibX, sibY}] indexed by level (0 = root, depth = leaf)

		for (let i = 0; i < levels; i++) {
			const y = topPad + i * levelHeight;
			// Horizontal spread narrows as we go up (root is centered)
			const spread = Math.min(W * 0.4, 60 + (i / depth) * (W * 0.35));
			const cx = W / 2;

			if (i === 0) {
				// Root level — only the path node (root hash)
				nodePositions.push({pathX: cx, pathY: y, sibX: null, sibY: null});
			} else {
				// At proof level i-1 (0-indexed from leaf), we have the sibling
				const proofIdx = depth - i; // map tree level to proof array index
				const side = proofData.proofSides[proofIdx]; // "left" or "right"
				// Path node and sibling positions
				const leftX = cx - spread;
				const rightX = cx + spread;
				if (side === 'left') {
					// Proof hash is the left sibling, path node is on the right
					nodePositions.push({pathX: rightX, pathY: y, sibX: leftX, sibY: y});
				} else {
					// Proof hash is the right sibling, path node is on the left
					nodePositions.push({pathX: leftX, pathY: y, sibX: rightX, sibY: y});
				}
			}
		}

		// Draw connecting lines first (behind nodes)
		ctx.lineWidth = 2;
		for (let i = 1; i < levels; i++) {
			const parent = nodePositions[i - 1];
			const current = nodePositions[i];

			// Line from parent path node to current path node
			ctx.strokeStyle = '#22c55e60';
			ctx.beginPath();
			ctx.moveTo(parent.pathX, parent.pathY + nodeRadius);
			ctx.lineTo(current.pathX, current.pathY - nodeRadius);
			ctx.stroke();

			// Line from parent path node to sibling node
			if (current.sibX !== null) {
				ctx.strokeStyle = '#334155';
				ctx.beginPath();
				ctx.moveTo(parent.pathX, parent.pathY + nodeRadius);
				ctx.lineTo(current.sibX, current.sibY - nodeRadius);
				ctx.stroke();
			}
		}

		// Draw nodes
		for (let i = 0; i < levels; i++) {
			const pos = nodePositions[i];
			const isRoot = i === 0;
			const isLeaf = i === levels - 1;

			// Path node (green)
			let pathHash;
			if (isRoot) {
				pathHash = proofData.rootHash;
			} else if (isLeaf) {
				pathHash = proofData.leafHash;
			} else {
				pathHash = null; // intermediate — computed hash, not directly available
			}

			drawProofNode(pos.pathX, pos.pathY, nodeRadius, '#22c55e', pathHash,
				isRoot ? 'Root' : isLeaf ? 'Leaf #' + proofData.leafIndex : 'Path',
				isRoot || isLeaf);

			// Sibling node (blue = proof hash)
			if (pos.sibX !== null) {
				const proofIdx = depth - i;
				const sibHash = proofData.proofPath[proofIdx];
				drawProofNode(pos.sibX, pos.sibY, nodeRadius, '#3b82f6', sibHash, 'Proof[' + proofIdx + ']', false);

				proofSegments.push({x: pos.sibX - nodeRadius, y: pos.sibY - nodeRadius,
					w: nodeRadius * 2, h: nodeRadius * 2, hash: sibHash, label: 'Proof Hash [Level ' + proofIdx + ']'});
			}

			proofSegments.push({x: pos.pathX - nodeRadius, y: pos.pathY - nodeRadius,
				w: nodeRadius * 2, h: nodeRadius * 2, hash: pathHash,
				label: isRoot ? 'Root Hash' : isLeaf ? 'Leaf Hash (index ' + proofData.leafIndex + ')' : 'Intermediate Path Node'});
		}

		// Labels
		ctx.fillStyle = '#475569'; ctx.font = '10px system-ui'; ctx.textAlign = 'center';
		ctx.fillText('Tree Size: ' + proofData.treeSize.toLocaleString() + '  |  Proof Depth: ' + depth + '  |  Leaf Index: ' + proofData.leafIndex, W / 2, H - 12);
	}

	function drawProofNode(x, y, r, color, hash, label, highlight) {
		// Glow for highlighted nodes
		if (highlight) {
			ctx.beginPath(); ctx.arc(x, y, r + 4, 0, Math.PI * 2);
			ctx.fillStyle = color + '20'; ctx.fill();
		}
		// Node circle
		ctx.beginPath(); ctx.arc(x, y, r, 0, Math.PI * 2);
		ctx.fillStyle = color + '30'; ctx.fill();
		ctx.strokeStyle = color; ctx.lineWidth = 2; ctx.stroke();
		// Hash text (truncated)
		if (hash) {
			ctx.fillStyle = '#e2e8f0'; ctx.font = 'bold 9px monospace'; ctx.textAlign = 'center';
			ctx.fillText(hash.substring(0, 8), x, y + 1);
		}
		// Label below
		ctx.fillStyle = '#64748b'; ctx.font = '9px system-ui'; ctx.textAlign = 'center';
		ctx.fillText(label, x, y + r + 12);
	}

	function renderProofLegend() {
		const items = [
			{c:'#22c55e',l:'Inclusion Path (leaf \u2192 root)'},
			{c:'#3b82f6',l:'Proof Hashes (siblings)'},
		];
		document.getElementById('legendRow').innerHTML = items.map(i =>
			'<div class="leg"><div class="leg-c" style="background:' + i.c + '"></div>' + i.l + '</div>'
		).join('');
	}

	function renderProofSidePanel() {
		const title = document.getElementById('sideTitle');
		const content = document.getElementById('sideContent');
		if (!proofData) {
			title.textContent = 'Proof Explorer';
			content.innerHTML = '<div style="color:#64748b;padding:20px;text-align:center">Enter a leaf index to view its Merkle inclusion proof.</div>';
			return;
		}

		title.textContent = 'Inclusion Proof';
		let html = '<div class="detail-card" style="border-left-color:#22c55e">' +
			'<div class="domain">Leaf #' + proofData.leafIndex + '</div>' +
			'<div class="meta">' +
			'Tree Size: ' + proofData.treeSize.toLocaleString() + '<br>' +
			'Proof Depth: ' + proofData.proofPath.length + '<br>' +
			'<a href="/admin/certs/' + proofData.leafIndex + '" style="color:#38bdf8">View certificate \u2192</a>' +
			'</div></div>';

		html += '<div class="detail-card" style="border-left-color:#22c55e">' +
			'<div style="font-size:.72rem;color:#64748b;text-transform:uppercase;letter-spacing:.05em;margin-bottom:4px">Leaf Hash</div>' +
			'<div style="font-family:monospace;font-size:.72rem;color:#34d399;word-break:break-all">' + proofData.leafHash + '</div></div>';

		html += '<div class="detail-card" style="border-left-color:#a78bfa">' +
			'<div style="font-size:.72rem;color:#64748b;text-transform:uppercase;letter-spacing:.05em;margin-bottom:4px">Root Hash</div>' +
			'<div style="font-family:monospace;font-size:.72rem;color:#a78bfa;word-break:break-all">' + proofData.rootHash + '</div></div>';

		if (proofData.proofPath.length) {
			html += '<div style="margin:10px 0 6px;font-size:.78rem;color:#94a3b8;font-weight:600">Proof Path (' + proofData.proofPath.length + ' hashes)</div>';
			proofData.proofPath.forEach((h, i) => {
				const side = proofData.proofSides[i];
				html += '<div class="detail-card" style="border-left-color:#3b82f6;padding:8px 12px">' +
					'<div style="display:flex;justify-content:space-between;align-items:center">' +
					'<span style="color:#94a3b8;font-size:.7rem">Level ' + i + ' (' + side + ')</span>' +
					'</div>' +
					'<div style="font-family:monospace;font-size:.68rem;color:#60a5fa;word-break:break-all;margin-top:2px">' + h + '</div></div>';
			});
		}

		content.innerHTML = html;
	}

	// Keyboard shortcuts
	document.addEventListener('keydown', e => {
		if (e.key === 'Escape') { if (viewMode === 'proof' || viewMode === 'merkle') return; drillUp(); }
		if (e.key === 'Backspace' && !e.target.matches('input,textarea')) { e.preventDefault(); resetView(); }
	});

	// Init
	window.addEventListener('resize', redraw);
	(async function init() {
		await loadData();
		const params = new URLSearchParams(window.location.search);
		const tab = params.get('tab');
		const index = params.get('index');
		if (tab && ['sunburst', 'treemap', 'proof', 'merkle', 'consistency'].includes(tab)) {
			switchView(tab);
		}
		if (index !== null && index !== '') {
			if (tab === 'proof') {
				document.getElementById('proofIndex').value = index;
				loadProof();
			} else if (tab === 'sunburst' || tab === 'treemap') {
				try {
					const res = await fetch('/admin/viz/cert-info/' + index);
					if (res.ok) {
						const info = await res.json();
						if (info.ca) drillIntoByName(info.ca);
						if (info.batch) drillIntoByName(info.batch);
						if (info.algo) drillIntoByName(info.algo);
					}
				} catch (e) { console.warn('cert-info lookup failed:', e); }
			}
		}
		if (tab === 'consistency') {
			const oldParam = params.get('old');
			const newParam = params.get('new');
			if (oldParam && newParam) {
				setTimeout(() => {
					document.getElementById('oldSizeSelect').value = oldParam;
					document.getElementById('newSizeSelect').value = newParam;
					loadConsistencyProof();
				}, 500);
			}
		}
	})();
	</script>
</body>
</html>`
