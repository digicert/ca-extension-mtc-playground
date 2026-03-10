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
				<a href="/admin/acme-demo" class="opacity-75 hover:opacity-100">ACME Demo</a>
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
				<a href="/admin/acme-demo" class="opacity-75 hover:opacity-100">ACME Demo</a>
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
				<a href="/admin/acme-demo" class="opacity-75 hover:opacity-100">ACME Demo</a>
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
				<a href="/admin/acme-demo" class="opacity-75 hover:opacity-100">ACME Demo</a>
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

const acmeDemoHTML = `<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>MTC Bridge — ACME Demo</title>
	<script src="https://cdn.tailwindcss.com"></script>
	<style>
		#steps.compact { gap: 0 !important; }
		#steps.compact .step-card { margin-bottom: 0; border-radius: 0; box-shadow: none; border-bottom: 1px solid #e5e7eb; }
		#steps.compact .step-card:first-child { border-top-left-radius: 0.5rem; border-top-right-radius: 0.5rem; }
		#steps.compact .step-card:last-child { border-bottom-left-radius: 0.5rem; border-bottom-right-radius: 0.5rem; border-bottom: none; }
		#steps.compact .step-header { padding: 4px 12px; }
		#steps.compact .step-detail { display: none !important; }
		#steps.compact .step-title { font-size: 0.75rem; }
		#steps.compact .step-chevron { display: none; }
		#steps.compact .step-icon { width: 1.25rem; height: 1.25rem; }
		#steps.compact .step-icon svg { width: 0.75rem; height: 0.75rem; }
	</style>
</head>
<body class="bg-gray-50 min-h-screen">
	<nav class="bg-indigo-700 text-white px-6 py-4 shadow">
		<div class="flex items-center justify-between max-w-7xl mx-auto">
			<h1 class="text-xl font-bold">MTC Bridge Dashboard</h1>
			<div class="flex gap-4 text-sm">
				<a href="/admin" class="opacity-75 hover:opacity-100">Dashboard</a>
				<a href="/admin/certs" class="opacity-75 hover:opacity-100">Certificates</a>
				<a href="/admin/viz" class="opacity-75 hover:opacity-100">Visualization</a>
				<a href="/admin/acme-demo" class="font-semibold underline">ACME Demo</a>
			</div>
		</div>
	</nav>

	<main class="max-w-4xl mx-auto px-6 py-8">
		<div class="flex items-center justify-between mb-6">
			<div>
				<h2 class="text-2xl font-bold text-gray-900">ACME Enrollment Demo</h2>
				<p class="text-gray-500 text-sm mt-1">
					Interactive RFC 8555 certificate enrollment with MTC Merkle proofs — runs entirely in your browser
				</p>
			</div>
			<button id="run-btn" onclick="runDemo()"
				class="px-6 py-3 bg-indigo-600 text-white rounded-lg font-semibold hover:bg-indigo-700 transition disabled:opacity-50 disabled:cursor-not-allowed">
				Run Demo
			</button>
		</div>

		<div class="mb-6 flex items-center gap-4">
			<label class="text-sm font-medium text-gray-700">Domain:</label>
			<input type="text" id="demo-domain" value="acme-demo.example.com"
				class="px-4 py-2 border border-gray-300 rounded-lg text-sm w-80 focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500"
				placeholder="Domain name for certificate">
		</div>

		<div id="steps-toolbar" class="flex items-center justify-end gap-2 mb-3 hidden">
			<button onclick="expandAll()" class="px-3 py-1.5 text-xs font-medium text-gray-600 bg-white border border-gray-300 rounded-md hover:bg-gray-50 transition">Expand All</button>
			<button onclick="collapseAll()" class="px-3 py-1.5 text-xs font-medium text-gray-600 bg-white border border-gray-300 rounded-md hover:bg-gray-50 transition">Collapse All</button>
			<button onclick="toggleCompact()" id="compact-btn" class="px-3 py-1.5 text-xs font-medium text-indigo-600 bg-indigo-50 border border-indigo-200 rounded-md hover:bg-indigo-100 transition">Compact View</button>
		</div>
		<div id="steps" class="space-y-3"></div>

		<!-- Results section (hidden until complete) -->
		<div id="results" class="hidden mt-8">
			<div class="border-b border-gray-200 mb-4">
				<nav class="flex gap-4">
					<button onclick="showResultTab('cert')" id="tab-cert" class="px-4 py-2 text-sm font-medium border-b-2 border-indigo-600 text-indigo-600">Certificate</button>
					<button onclick="showResultTab('inclusion')" id="tab-inclusion" class="px-4 py-2 text-sm font-medium border-b-2 border-transparent text-gray-500 hover:text-gray-700">Inclusion Proof</button>
					<button onclick="showResultTab('consistency')" id="tab-consistency" class="px-4 py-2 text-sm font-medium border-b-2 border-transparent text-gray-500 hover:text-gray-700">Consistency Proof</button>
				</nav>
			</div>
			<div id="result-cert" class="bg-white rounded-lg shadow p-6"></div>
			<div id="result-inclusion" class="bg-white rounded-lg shadow p-6 hidden"></div>
			<div id="result-consistency" class="bg-white rounded-lg shadow p-6 hidden"></div>
		</div>
	</main>

<script>
// ============================================================
// Configuration
// ============================================================
const ACME_EXTERNAL_URL = '{{ .ACMEExternalURL }}';
const PROXY_BASE = '/admin/acme-proxy';

// ============================================================
// Step definitions
// ============================================================
const STEPS = [
	{ id: 'keygen',      title: '1. Generate Account Key Pair (ECDSA P-256)' },
	{ id: 'directory',   title: '2. Fetch ACME Directory' },
	{ id: 'nonce',       title: '3. Get Initial Nonce' },
	{ id: 'account',     title: '4. Create Account' },
	{ id: 'order',       title: '5. Create Order' },
	{ id: 'authz',       title: '6. Fetch Authorization' },
	{ id: 'challenge',   title: '7. Respond to Challenge' },
	{ id: 'poll-ready',  title: '8. Poll Order → Ready' },
	{ id: 'certkey',     title: '9. Generate Certificate Key Pair' },
	{ id: 'csr',         title: '10. Build CSR (PKCS#10)' },
	{ id: 'finalize',    title: '11. Finalize Order' },
	{ id: 'download',    title: '12. Download Certificate' },
	{ id: 'inclusion',   title: '13. Fetch Inclusion Proof' },
	{ id: 'consistency', title: '14. Fetch Consistency Proof' },
	{ id: 'verify',      title: '15. Verify Proofs' },
];

function renderSteps() {
	const container = document.getElementById('steps');
	container.innerHTML = STEPS.map(s => ` +
		"`" + `
		<div class="step-card bg-white rounded-lg shadow overflow-hidden" id="step-${s.id}">
			<div class="step-header flex items-center justify-between px-5 py-3 cursor-pointer select-none" onclick="toggleStep('${s.id}')">
				<div class="flex items-center gap-3">
					<span id="icon-${s.id}" class="step-icon w-6 h-6 rounded-full bg-gray-200 flex items-center justify-center text-xs text-gray-400">-</span>
					<span class="step-title font-medium text-sm text-gray-800">${s.title}</span>
				</div>
				<div class="flex items-center gap-2">
					<span id="timing-${s.id}" class="text-xs text-gray-400"></span>
					<svg id="chevron-${s.id}" class="step-chevron w-4 h-4 text-gray-400 transition-transform duration-200" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"/></svg>
				</div>
			</div>
			<div class="step-detail hidden border-t px-5 py-4 bg-gray-50" id="detail-${s.id}">
				<div class="grid md:grid-cols-2 gap-4">
					<div>
						<h4 class="text-xs font-semibold text-gray-500 mb-2 uppercase">Request</h4>
						<pre id="req-${s.id}" class="text-xs bg-gray-900 text-green-400 p-3 rounded overflow-x-auto max-h-64 whitespace-pre-wrap"></pre>
					</div>
					<div>
						<h4 class="text-xs font-semibold text-gray-500 mb-2 uppercase">Response</h4>
						<pre id="res-${s.id}" class="text-xs bg-gray-900 text-blue-400 p-3 rounded overflow-x-auto max-h-64 whitespace-pre-wrap"></pre>
					</div>
				</div>
			</div>
		</div>
	` + "`" + `).join('');
	document.getElementById('steps-toolbar').classList.remove('hidden');
}

function toggleStep(id) {
	const el = document.getElementById('detail-' + id);
	const chevron = document.getElementById('chevron-' + id);
	el.classList.toggle('hidden');
	chevron.classList.toggle('rotate-90');
}

function expandAll() {
	STEPS.forEach(s => {
		document.getElementById('detail-' + s.id).classList.remove('hidden');
		document.getElementById('chevron-' + s.id).classList.add('rotate-90');
	});
}

function collapseAll() {
	STEPS.forEach(s => {
		document.getElementById('detail-' + s.id).classList.add('hidden');
		document.getElementById('chevron-' + s.id).classList.remove('rotate-90');
	});
}

function toggleCompact() {
	const steps = document.getElementById('steps');
	const btn = document.getElementById('compact-btn');
	steps.classList.toggle('compact');
	const isCompact = steps.classList.contains('compact');
	btn.textContent = isCompact ? 'Expanded View' : 'Compact View';
}

function setStepStatus(id, status) {
	const icon = document.getElementById('icon-' + id);
	if (status === 'running') {
		icon.className = 'step-icon w-6 h-6 rounded-full bg-indigo-100 flex items-center justify-center';
		icon.innerHTML = '<svg class="w-4 h-4 text-indigo-600 animate-spin" fill="none" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v4a4 4 0 00-4 4H4z"></path></svg>';
	} else if (status === 'success') {
		icon.className = 'step-icon w-6 h-6 rounded-full bg-green-100 flex items-center justify-center';
		icon.innerHTML = '<svg class="w-4 h-4 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/></svg>';
	} else if (status === 'error') {
		icon.className = 'step-icon w-6 h-6 rounded-full bg-red-100 flex items-center justify-center';
		icon.innerHTML = '<svg class="w-4 h-4 text-red-600" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/></svg>';
	}
}

function setStepDetail(id, req, res) {
	if (req !== null) document.getElementById('req-' + id).textContent = typeof req === 'string' ? req : JSON.stringify(req, null, 2);
	if (res !== null) document.getElementById('res-' + id).textContent = typeof res === 'string' ? res : JSON.stringify(res, null, 2);
}

function setStepTiming(id, ms) {
	document.getElementById('timing-' + id).textContent = ms + ' ms';
}

// ============================================================
// Base64url utilities
// ============================================================
function base64url(bytes) {
	const bin = Array.from(bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes))
		.map(b => String.fromCharCode(b)).join('');
	return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64urlEncode(str) {
	return base64url(new TextEncoder().encode(str));
}

function base64urlDecode(str) {
	str = str.replace(/-/g, '+').replace(/_/g, '/');
	while (str.length % 4) str += '=';
	const bin = atob(str);
	const bytes = new Uint8Array(bin.length);
	for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
	return bytes;
}

function hexEncode(bytes) {
	return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function hexDecode(hex) {
	const bytes = new Uint8Array(hex.length / 2);
	for (let i = 0; i < hex.length; i += 2) bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
	return bytes;
}

// ============================================================
// Crypto utilities (Web Crypto API)
// ============================================================
async function generateKeyPair() {
	return crypto.subtle.generateKey(
		{ name: 'ECDSA', namedCurve: 'P-256' },
		true,
		['sign']
	);
}

async function exportJWK(keyPair) {
	const jwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey);
	return { crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y };
}

async function jwkThumbprint(jwk) {
	const canonical = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y });
	const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(canonical));
	return base64url(new Uint8Array(hash));
}

async function ecSign(privateKey, data) {
	const sig = await crypto.subtle.sign(
		{ name: 'ECDSA', hash: 'SHA-256' },
		privateKey,
		new TextEncoder().encode(data)
	);
	return new Uint8Array(sig);
}

// Convert DER ECDSA signature to raw r||s (64 bytes for P-256)
function derToRaw(der) {
	let offset = 2; // skip SEQUENCE tag + length
	if (der[1] & 0x80) offset += (der[1] & 0x7f); // long-form length
	// Parse r
	if (der[offset] !== 0x02) throw new Error('Expected INTEGER tag for r');
	const rLen = der[offset + 1];
	const rBytes = der.slice(offset + 2, offset + 2 + rLen);
	offset += 2 + rLen;
	// Parse s
	if (der[offset] !== 0x02) throw new Error('Expected INTEGER tag for s');
	const sLen = der[offset + 1];
	const sBytes = der.slice(offset + 2, offset + 2 + sLen);
	// Pad/trim to 32 bytes each
	const raw = new Uint8Array(64);
	const rTrim = rBytes.length > 32 ? rBytes.slice(rBytes.length - 32) : rBytes;
	const sTrim = sBytes.length > 32 ? sBytes.slice(sBytes.length - 32) : sBytes;
	raw.set(rTrim, 32 - rTrim.length);
	raw.set(sTrim, 64 - sTrim.length);
	return raw;
}

// ============================================================
// JWS builder
// ============================================================
async function buildJWS(acmeURL, nonce, payload, keyPair, jwk, kid) {
	const header = { alg: 'ES256', nonce: nonce, url: acmeURL };
	if (jwk) header.jwk = jwk;
	if (kid) header.kid = kid;
	const protectedB64 = base64urlEncode(JSON.stringify(header));
	const payloadB64 = payload === '' ? '' : base64urlEncode(JSON.stringify(payload));
	const sigInput = protectedB64 + '.' + payloadB64;
	const sig = await ecSign(keyPair.privateKey, sigInput);
	return { protected: protectedB64, payload: payloadB64, signature: base64url(sig) };
}

// ============================================================
// ACME HTTP client (through proxy)
// ============================================================
let currentNonce = '';

async function acmePost(proxyPath, jws) {
	const resp = await fetch(PROXY_BASE + proxyPath, {
		method: 'POST',
		headers: { 'Content-Type': 'application/jose+json' },
		body: JSON.stringify(jws),
	});
	const nonce = resp.headers.get('Replay-Nonce');
	if (nonce) currentNonce = nonce;
	const ct = resp.headers.get('Content-Type') || '';
	let body;
	if (ct.includes('application/json') || ct.includes('application/problem+json')) {
		body = await resp.json();
	} else {
		body = await resp.text();
	}
	return { status: resp.status, body, location: resp.headers.get('Location'), nonce };
}

function extractProxyPath(fullURL) {
	return fullURL.replace(ACME_EXTERNAL_URL, '');
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

// ============================================================
// ASN.1 DER helpers for CSR builder
// ============================================================
function asn1Length(len) {
	if (len < 0x80) return new Uint8Array([len]);
	if (len < 0x100) return new Uint8Array([0x81, len]);
	return new Uint8Array([0x82, (len >> 8) & 0xff, len & 0xff]);
}

function asn1Wrap(tag, ...items) {
	let total = 0;
	for (const it of items) total += it.length;
	const lenBytes = asn1Length(total);
	const out = new Uint8Array(1 + lenBytes.length + total);
	out[0] = tag;
	out.set(lenBytes, 1);
	let off = 1 + lenBytes.length;
	for (const it of items) { out.set(it, off); off += it.length; }
	return out;
}

function asn1Sequence(...items) { return asn1Wrap(0x30, ...items); }
function asn1Set(...items) { return asn1Wrap(0x31, ...items); }
function asn1ContextConstructed(tagNum, ...items) { return asn1Wrap(0xa0 | tagNum, ...items); }

function asn1OID(encoded) { return asn1Wrap(0x06, new Uint8Array(encoded)); }
function asn1BitString(bytes) {
	const out = new Uint8Array(bytes.length + 1);
	out[0] = 0x00; // no unused bits
	out.set(bytes, 1);
	return asn1Wrap(0x03, out);
}
function asn1OctetString(bytes) { return asn1Wrap(0x04, bytes); }
function asn1Integer(val) {
	if (typeof val === 'number') {
		if (val === 0) return new Uint8Array([0x02, 0x01, 0x00]);
		const bytes = [];
		let v = val;
		while (v > 0) { bytes.unshift(v & 0xff); v >>= 8; }
		if (bytes[0] & 0x80) bytes.unshift(0);
		return asn1Wrap(0x02, new Uint8Array(bytes));
	}
	return asn1Wrap(0x02, val);
}

// Common OIDs (pre-encoded)
const OID_EC_PUBLIC_KEY = [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]; // 1.2.840.10045.2.1
const OID_PRIME256V1   = [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]; // 1.2.840.10045.3.1.7
const OID_ECDSA_SHA256 = [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02]; // 1.2.840.10045.4.3.2
const OID_SAN          = [0x55, 0x1d, 0x11]; // 2.5.29.17
const OID_EXT_REQUEST  = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x0e]; // 1.2.840.113549.1.9.14

async function buildCSR(certKeyPair, domain) {
	// 1. Export public key as raw uncompressed point (65 bytes: 0x04 || x || y)
	const rawPub = new Uint8Array(await crypto.subtle.exportKey('raw', certKeyPair.publicKey));

	// 2. Build SubjectPublicKeyInfo
	const algId = asn1Sequence(asn1OID(OID_EC_PUBLIC_KEY), asn1OID(OID_PRIME256V1));
	const spki = asn1Sequence(algId, asn1BitString(rawPub));

	// 3. Build SAN extension: SEQUENCE { CONTEXT[2] IA5String(domain) }
	const domainBytes = new TextEncoder().encode(domain);
	const dnsName = asn1Wrap(0x82, domainBytes); // context [2] implicit IA5String
	const sanValue = asn1Sequence(dnsName);
	const sanExt = asn1Sequence(asn1OID(OID_SAN), asn1OctetString(sanValue));
	const extensions = asn1Sequence(sanExt);

	// 4. Build extensionRequest attribute
	const extReqAttr = asn1Sequence(
		asn1OID(OID_EXT_REQUEST),
		asn1Set(extensions)
	);
	const attributes = asn1ContextConstructed(0, extReqAttr);

	// 5. Build TBSCertificationRequest
	const emptySubject = asn1Sequence(); // empty subject DN
	const tbs = asn1Sequence(
		asn1Integer(0), // version 0
		emptySubject,
		spki,
		attributes
	);

	// 6. Sign TBS
	const tbsSig = await crypto.subtle.sign(
		{ name: 'ECDSA', hash: 'SHA-256' },
		certKeyPair.privateKey,
		tbs
	);
	const rawSig = new Uint8Array(tbsSig);

	// Need to re-encode rawSig as DER for the CSR signature
	function asn1IntegerFromBytes(b) {
		let start = 0;
		while (start < b.length - 1 && b[start] === 0) start++;
		let val = b.slice(start);
		if (val[0] & 0x80) { const padded = new Uint8Array(val.length + 1); padded.set(val, 1); val = padded; }
		return asn1Wrap(0x02, val);
	}
	const sigDER = asn1Sequence(
		asn1IntegerFromBytes(rawSig.slice(0, 32)),
		asn1IntegerFromBytes(rawSig.slice(32))
	);

	// 7. Build CertificationRequest
	const sigAlg = asn1Sequence(asn1OID(OID_ECDSA_SHA256));
	return asn1Sequence(tbs, sigAlg, asn1BitString(sigDER));
}

// ============================================================
// Result display helpers
// ============================================================
function showResultTab(tab) {
	['cert', 'inclusion', 'consistency'].forEach(t => {
		document.getElementById('result-' + t).classList.toggle('hidden', t !== tab);
		const btn = document.getElementById('tab-' + t);
		if (t === tab) {
			btn.className = 'px-4 py-2 text-sm font-medium border-b-2 border-indigo-600 text-indigo-600';
		} else {
			btn.className = 'px-4 py-2 text-sm font-medium border-b-2 border-transparent text-gray-500 hover:text-gray-700';
		}
	});
}

function renderCertResult(pemText) {
	const el = document.getElementById('result-cert');
	// Try to parse certificate fields from PEM
	let certHTML = '';
	try {
		const b64 = pemText.split('-----BEGIN CERTIFICATE-----')[1].split('-----END CERTIFICATE-----')[0].trim();
		const der = base64Decode(b64);
		const fields = parseCertDER(der);
		certHTML = renderCertFields(fields);
	} catch (e) {
		certHTML = '<p class="text-sm text-gray-500 mb-4">Could not parse certificate fields: ' + e.message + '</p>';
	}
	certHTML += '<h4 class="text-sm font-semibold text-gray-600 mt-6 mb-2">Raw PEM</h4>';
	certHTML += '<pre class="text-xs bg-gray-900 text-green-400 p-4 rounded overflow-x-auto max-h-96 whitespace-pre-wrap">' + escapeHTML(pemText) + '</pre>';
	el.innerHTML = certHTML;
}

function base64Decode(b64) {
	const bin = atob(b64.replace(/\s/g, ''));
	const bytes = new Uint8Array(bin.length);
	for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
	return bytes;
}

function escapeHTML(s) {
	return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

// ============================================================
// Minimal X.509 DER parser (no external libraries)
// ============================================================
function parseCertDER(der) {
	const fields = {};
	try {
		// Parse outer SEQUENCE
		const cert = readASN1(der, 0);
		const tbs = readASN1(der, cert.contentStart);

		let pos = tbs.contentStart;
		// Version (context [0] explicit)
		if (der[pos] === 0xa0) {
			const ver = readASN1(der, pos);
			const verInt = readASN1(der, ver.contentStart);
			fields.version = der[verInt.contentStart] + 1;
			pos = ver.end;
		}
		// Serial number
		const serial = readASN1(der, pos);
		let serialBytes = der.slice(serial.contentStart, serial.end);
		while (serialBytes.length > 1 && serialBytes[0] === 0) serialBytes = serialBytes.slice(1);
		fields.serialNumber = hexEncode(serialBytes);
		pos = serial.end;

		// Signature algorithm
		const sigAlg = readASN1(der, pos);
		fields.signatureAlgorithm = readOIDString(der, sigAlg.contentStart);
		pos = sigAlg.end;

		// Issuer
		const issuer = readASN1(der, pos);
		fields.issuer = readDN(der, issuer.contentStart, issuer.end);
		pos = issuer.end;

		// Validity
		const validity = readASN1(der, pos);
		let vPos = validity.contentStart;
		const notBefore = readASN1(der, vPos);
		fields.notBefore = readTimeString(der, notBefore);
		vPos = notBefore.end;
		const notAfter = readASN1(der, vPos);
		fields.notAfter = readTimeString(der, notAfter);
		pos = validity.end;

		// Subject
		const subject = readASN1(der, pos);
		fields.subject = readDN(der, subject.contentStart, subject.end);
		pos = subject.end;

		// SubjectPublicKeyInfo
		const spki = readASN1(der, pos);
		const spkiAlg = readASN1(der, spki.contentStart);
		fields.publicKeyAlgorithm = readOIDString(der, spkiAlg.contentStart);
		if (der[spkiAlg.contentStart + readASN1(der, spkiAlg.contentStart).end - spkiAlg.contentStart] === 0x06) {
			// curve OID
			const curveOid = readASN1(der, readASN1(der, spkiAlg.contentStart).end);
			fields.publicKeyCurve = oidToName(readOIDBytes(der, curveOid.contentStart, curveOid.end));
		}
		pos = spki.end;

		// Extensions (context [3])
		while (pos < tbs.end) {
			const tag = der[pos];
			if (tag === 0xa3) {
				const extWrapper = readASN1(der, pos);
				const extsSeq = readASN1(der, extWrapper.contentStart);
				fields.extensions = readExtensions(der, extsSeq.contentStart, extsSeq.end);
			}
			const skip = readASN1(der, pos);
			pos = skip.end;
		}

		// Signature algorithm (outer)
		const outerSigAlg = readASN1(der, tbs.end);
		fields.outerSignatureAlgorithm = readOIDString(der, outerSigAlg.contentStart);

	} catch (e) {
		fields._parseError = e.message;
	}
	return fields;
}

function readASN1(der, offset) {
	const tag = der[offset];
	let len, hdrLen;
	if (der[offset + 1] < 0x80) {
		len = der[offset + 1]; hdrLen = 2;
	} else {
		const numBytes = der[offset + 1] & 0x7f;
		len = 0;
		for (let i = 0; i < numBytes; i++) len = (len << 8) | der[offset + 2 + i];
		hdrLen = 2 + numBytes;
	}
	return { tag, contentStart: offset + hdrLen, end: offset + hdrLen + len, length: len };
}

function readOIDBytes(der, start, end) {
	return Array.from(der.slice(start, end));
}

function readOIDString(der, pos) {
	const oid = readASN1(der, pos);
	if (oid.tag !== 0x06) return 'unknown';
	const bytes = der.slice(oid.contentStart, oid.end);
	const parts = [];
	parts.push(Math.floor(bytes[0] / 40));
	parts.push(bytes[0] % 40);
	let val = 0;
	for (let i = 1; i < bytes.length; i++) {
		val = (val << 7) | (bytes[i] & 0x7f);
		if (!(bytes[i] & 0x80)) { parts.push(val); val = 0; }
	}
	const oidStr = parts.join('.');
	return oidToName(oidStr) || oidStr;
}

function oidToName(oid) {
	const oidStr = Array.isArray(oid) ? oid.join('.') : oid;
	const names = {
		'1.2.840.10045.2.1': 'EC Public Key',
		'1.2.840.10045.3.1.7': 'P-256',
		'1.2.840.10045.4.3.2': 'ECDSA-SHA256',
		'1.2.840.113549.1.1.1': 'RSA',
		'1.2.840.113549.1.1.11': 'SHA256-RSA',
		'1.3.6.1.4.1.44363.47.0': 'id-alg-mtcProof (MTC)',
		'2.5.29.17': 'Subject Alternative Name',
		'2.5.29.15': 'Key Usage',
		'2.5.29.19': 'Basic Constraints',
		'2.5.29.14': 'Subject Key Identifier',
		'2.5.29.35': 'Authority Key Identifier',
	};
	return names[oidStr] || oidStr;
}

function readDN(der, start, end) {
	const parts = [];
	let pos = start;
	while (pos < end) {
		const set = readASN1(der, pos);
		if (set.tag !== 0x31) { pos = set.end; continue; }
		const seq = readASN1(der, set.contentStart);
		const oidNode = readASN1(der, seq.contentStart);
		const valNode = readASN1(der, oidNode.end);
		const oid = readOIDString(der, seq.contentStart);
		const val = new TextDecoder().decode(der.slice(valNode.contentStart, valNode.end));
		const shortNames = {
			'2.5.4.3': 'CN', '2.5.4.6': 'C', '2.5.4.7': 'L', '2.5.4.8': 'ST',
			'2.5.4.10': 'O', '2.5.4.11': 'OU',
		};
		// Re-read OID as raw string for lookup
		const rawOid = readASN1(der, seq.contentStart);
		const oidBytes = der.slice(rawOid.contentStart, rawOid.end);
		const oidParts = [];
		oidParts.push(Math.floor(oidBytes[0] / 40));
		oidParts.push(oidBytes[0] % 40);
		let v = 0;
		for (let i = 1; i < oidBytes.length; i++) {
			v = (v << 7) | (oidBytes[i] & 0x7f);
			if (!(oidBytes[i] & 0x80)) { oidParts.push(v); v = 0; }
		}
		const label = shortNames[oidParts.join('.')] || oidParts.join('.');
		parts.push({ label, value: val });
		pos = set.end;
	}
	return parts;
}

function readTimeString(der, node) {
	const bytes = der.slice(node.contentStart, node.end);
	const str = new TextDecoder().decode(bytes);
	if (node.tag === 0x17) { // UTCTime
		const y = parseInt(str.substr(0, 2));
		return (y >= 50 ? '19' : '20') + str.substr(0, 2) + '-' + str.substr(2, 2) + '-' + str.substr(4, 2) + ' ' + str.substr(6, 2) + ':' + str.substr(8, 2) + ':' + str.substr(10, 2) + ' UTC';
	}
	// GeneralizedTime
	return str.substr(0, 4) + '-' + str.substr(4, 2) + '-' + str.substr(6, 2) + ' ' + str.substr(8, 2) + ':' + str.substr(10, 2) + ':' + str.substr(12, 2) + ' UTC';
}

function readExtensions(der, start, end) {
	const exts = [];
	let pos = start;
	while (pos < end) {
		const extSeq = readASN1(der, pos);
		if (extSeq.tag !== 0x30) { pos = extSeq.end; continue; }
		const oidNode = readASN1(der, extSeq.contentStart);
		const oidBytes = der.slice(oidNode.contentStart, oidNode.end);
		const oidParts = [];
		oidParts.push(Math.floor(oidBytes[0] / 40));
		oidParts.push(oidBytes[0] % 40);
		let v = 0;
		for (let i = 1; i < oidBytes.length; i++) {
			v = (v << 7) | (oidBytes[i] & 0x7f);
			if (!(oidBytes[i] & 0x80)) { oidParts.push(v); v = 0; }
		}
		const oidStr = oidParts.join('.');
		const name = oidToName(oidStr);

		let critical = false;
		let valueStart = oidNode.end;
		const next = readASN1(der, valueStart);
		if (next.tag === 0x01) { // BOOLEAN (critical)
			critical = der[next.contentStart] !== 0;
			valueStart = next.end;
		}

		let detail = '';
		// Try to parse SAN
		if (oidStr === '2.5.29.17') {
			try {
				const octet = readASN1(der, valueStart);
				const sanSeq = readASN1(der, octet.contentStart);
				let sp = sanSeq.contentStart;
				const names = [];
				while (sp < sanSeq.end) {
					const entry = readASN1(der, sp);
					if ((entry.tag & 0x1f) === 2) { // dNSName
						names.push(new TextDecoder().decode(der.slice(entry.contentStart, entry.end)));
					}
					sp = entry.end;
				}
				detail = names.join(', ');
			} catch (e) { detail = '(parse error)'; }
		}

		exts.push({ oid: oidStr, name, critical, detail });
		pos = extSeq.end;
	}
	return exts;
}

function renderCertFields(f) {
	let html = '<div class="space-y-4">';

	// Signature algorithm (highlight MTC)
	const sigName = f.outerSignatureAlgorithm || f.signatureAlgorithm || 'Unknown';
	const isMTC = sigName.includes('mtcProof') || sigName.includes('MTC');
	if (isMTC) {
		html += '<div class="bg-purple-50 border border-purple-200 rounded-lg p-4"><p class="text-sm font-semibold text-purple-800">Signature Algorithm: ' + escapeHTML(sigName) + '</p><p class="text-xs text-purple-600 mt-1">This is an MTC-spec certificate — the signature value carries a Merkle inclusion proof, not a traditional cryptographic signature.</p></div>';
	}

	// Subject
	if (f.subject && f.subject.length > 0) {
		html += '<div><h4 class="text-xs font-semibold text-gray-500 uppercase mb-1">Subject</h4><div class="bg-gray-50 rounded p-3 text-sm">';
		f.subject.forEach(p => { html += '<div><span class="text-gray-500 mr-2">' + escapeHTML(p.label) + ':</span><span class="font-mono">' + escapeHTML(p.value) + '</span></div>'; });
		html += '</div></div>';
	}

	// Issuer
	if (f.issuer && f.issuer.length > 0) {
		html += '<div><h4 class="text-xs font-semibold text-gray-500 uppercase mb-1">Issuer</h4><div class="bg-gray-50 rounded p-3 text-sm">';
		f.issuer.forEach(p => { html += '<div><span class="text-gray-500 mr-2">' + escapeHTML(p.label) + ':</span><span class="font-mono">' + escapeHTML(p.value) + '</span></div>'; });
		html += '</div></div>';
	}

	// Grid: Version, Serial, Validity, Key
	html += '<div class="grid md:grid-cols-2 gap-4">';
	if (f.version) html += '<div><h4 class="text-xs font-semibold text-gray-500 uppercase mb-1">Version</h4><p class="text-sm font-mono">v' + f.version + '</p></div>';
	if (f.serialNumber) html += '<div><h4 class="text-xs font-semibold text-gray-500 uppercase mb-1">Serial Number</h4><p class="text-sm font-mono break-all">' + escapeHTML(f.serialNumber) + '</p></div>';
	if (f.notBefore) html += '<div><h4 class="text-xs font-semibold text-gray-500 uppercase mb-1">Not Before</h4><p class="text-sm">' + escapeHTML(f.notBefore) + '</p></div>';
	if (f.notAfter) html += '<div><h4 class="text-xs font-semibold text-gray-500 uppercase mb-1">Not After</h4><p class="text-sm">' + escapeHTML(f.notAfter) + '</p></div>';
	if (f.publicKeyAlgorithm) html += '<div><h4 class="text-xs font-semibold text-gray-500 uppercase mb-1">Public Key</h4><p class="text-sm">' + escapeHTML(f.publicKeyAlgorithm) + (f.publicKeyCurve ? ' (' + escapeHTML(f.publicKeyCurve) + ')' : '') + '</p></div>';
	if (!isMTC && f.signatureAlgorithm) html += '<div><h4 class="text-xs font-semibold text-gray-500 uppercase mb-1">Signature Algorithm</h4><p class="text-sm">' + escapeHTML(f.signatureAlgorithm) + '</p></div>';
	html += '</div>';

	// Extensions
	if (f.extensions && f.extensions.length > 0) {
		html += '<div><h4 class="text-xs font-semibold text-gray-500 uppercase mb-1">Extensions</h4><div class="space-y-1">';
		f.extensions.forEach(ext => {
			html += '<div class="bg-gray-50 rounded px-3 py-2 text-sm flex items-center gap-2">';
			html += '<span class="font-medium">' + escapeHTML(ext.name) + '</span>';
			if (ext.critical) html += '<span class="text-xs bg-red-100 text-red-700 px-1.5 rounded">critical</span>';
			if (ext.detail) html += '<span class="text-gray-500 ml-2">' + escapeHTML(ext.detail) + '</span>';
			html += '</div>';
		});
		html += '</div></div>';
	}

	html += '</div>';
	return html;
}

function renderInclusionProof(data) {
	const el = document.getElementById('result-inclusion');
	let html = '<div class="space-y-4">';
	html += '<div class="grid md:grid-cols-2 gap-4">';
	html += '<div><h4 class="text-xs font-semibold text-gray-500 uppercase mb-1">Leaf Index</h4><p class="text-lg font-mono font-bold">' + data.leaf_index + '</p></div>';
	html += '<div><h4 class="text-xs font-semibold text-gray-500 uppercase mb-1">Tree Size</h4><p class="text-lg font-mono font-bold">' + data.tree_size + '</p></div>';
	html += '</div>';
	html += '<div><h4 class="text-xs font-semibold text-gray-500 uppercase mb-1">Leaf Hash</h4><p class="text-xs font-mono break-all bg-gray-50 rounded p-2">' + escapeHTML(data.leaf_hash) + '</p></div>';
	html += '<div><h4 class="text-xs font-semibold text-gray-500 uppercase mb-1">Root Hash</h4><p class="text-xs font-mono break-all bg-gray-50 rounded p-2">' + escapeHTML(data.root_hash) + '</p></div>';

	// Proof path
	html += '<div><h4 class="text-xs font-semibold text-gray-500 uppercase mb-1">Proof Path (' + data.proof.length + ' hashes)</h4><div class="space-y-1">';
	data.proof.forEach((h, i) => {
		html += '<div class="flex items-center gap-2 text-xs"><span class="bg-indigo-100 text-indigo-700 px-2 py-0.5 rounded font-medium w-6 text-center">' + i + '</span><span class="font-mono break-all">' + escapeHTML(h) + '</span></div>';
	});
	html += '</div></div>';

	// Verification badge
	html += '<div id="inclusion-verify" class="mt-2"></div>';

	// Checkpoint
	html += '<details class="mt-4"><summary class="text-xs text-gray-500 cursor-pointer">Signed Checkpoint</summary><pre class="text-xs bg-gray-900 text-blue-400 p-3 rounded mt-2 whitespace-pre-wrap">' + escapeHTML(data.checkpoint) + '</pre></details>';

	html += '</div>';
	el.innerHTML = html;
}

function renderConsistencyProof(data) {
	const el = document.getElementById('result-consistency');
	let html = '<div class="space-y-4">';
	html += '<div class="grid md:grid-cols-2 gap-4">';
	html += '<div><h4 class="text-xs font-semibold text-gray-500 uppercase mb-1">Old Tree Size</h4><p class="text-lg font-mono font-bold">' + data.old_size + '</p></div>';
	html += '<div><h4 class="text-xs font-semibold text-gray-500 uppercase mb-1">New Tree Size</h4><p class="text-lg font-mono font-bold">' + data.new_size + '</p></div>';
	html += '</div>';
	html += '<div><h4 class="text-xs font-semibold text-gray-500 uppercase mb-1">Old Root</h4><p class="text-xs font-mono break-all bg-gray-50 rounded p-2">' + escapeHTML(data.old_root) + '</p></div>';
	html += '<div><h4 class="text-xs font-semibold text-gray-500 uppercase mb-1">New Root</h4><p class="text-xs font-mono break-all bg-gray-50 rounded p-2">' + escapeHTML(data.new_root) + '</p></div>';

	html += '<div><h4 class="text-xs font-semibold text-gray-500 uppercase mb-1">Proof Hashes (' + data.proof.length + ')</h4><div class="space-y-1">';
	data.proof.forEach((h, i) => {
		html += '<div class="flex items-center gap-2 text-xs"><span class="bg-amber-100 text-amber-700 px-2 py-0.5 rounded font-medium w-6 text-center">' + i + '</span><span class="font-mono break-all">' + escapeHTML(h) + '</span></div>';
	});
	html += '</div></div>';

	html += '<div id="consistency-verify" class="mt-2"></div>';
	html += '</div>';
	el.innerHTML = html;
}

// ============================================================
// Client-side Merkle proof verification
// ============================================================
async function sha256(data) {
	const hash = await crypto.subtle.digest('SHA-256', data);
	return new Uint8Array(hash);
}

// RFC 9162 §2.1.3.2 inclusion proof verification using recursive decomposition.
async function verifyInclusionProof(leafHash, index, treeSize, proofHashes, rootHash) {
	const hash = hexDecode(leafHash);
	const proof = proofHashes.map(h => hexDecode(h));
	let proofIdx = 0;

	async function rootFromProof(idx, start, end, h) {
		const n = end - start;
		if (n === 1) return h;
		if (proofIdx >= proof.length) return h;
		const k = splitPoint(n);
		if (idx - start < k) {
			const left = await rootFromProof(idx, start, start + k, h);
			if (proofIdx < proof.length) {
				const right = proof[proofIdx++];
				return await interiorHash(left, right);
			}
			return left;
		} else {
			const right = await rootFromProof(idx, start + k, end, h);
			if (proofIdx < proof.length) {
				const left = proof[proofIdx++];
				return await interiorHash(left, right);
			}
			return right;
		}
	}

	function splitPoint(n) {
		if (n < 2) return 0;
		return 1 << (Math.floor(Math.log2(n - 1)));
	}

	async function interiorHash(left, right) {
		const combined = new Uint8Array(1 + 32 + 32);
		combined[0] = 0x01;
		combined.set(left, 1);
		combined.set(right, 33);
		return await sha256(combined);
	}

	const computed = await rootFromProof(index, 0, treeSize, hash);
	return hexEncode(computed) === rootHash;
}

// ============================================================
// Main demo flow
// ============================================================
let accountKey, accountJWK, accountURL, certKey;
let snapshotTreeSize = 0;

async function runDemo() {
	const btn = document.getElementById('run-btn');
	btn.disabled = true;
	btn.textContent = 'Running...';
	document.getElementById('results').classList.add('hidden');
	renderSteps();

	const domain = document.getElementById('demo-domain').value.trim() || 'acme-demo.example.com';
	let certPEM = '';
	let certSerial = '';
	let inclusionData = null;
	let consistencyData = null;
	let errorStep = '';

	async function step(id, fn) {
		setStepStatus(id, 'running');
		const t0 = performance.now();
		try {
			await fn();
			setStepTiming(id, Math.round(performance.now() - t0));
			setStepStatus(id, 'success');
		} catch (e) {
			setStepTiming(id, Math.round(performance.now() - t0));
			setStepStatus(id, 'error');
			setStepDetail(id, null, 'Error: ' + e.message);
			errorStep = id;
			throw e;
		}
	}

	try {
		// Step 1: Generate account key
		await step('keygen', async () => {
			accountKey = await generateKeyPair();
			accountJWK = await exportJWK(accountKey);
			const thumbprint = await jwkThumbprint(accountJWK);
			setStepDetail('keygen', 'Web Crypto: ECDSA P-256', { jwk: accountJWK, thumbprint });
		});

		// Snapshot tree size for consistency proof later
		try {
			const cpResp = await fetch('/checkpoint');
			const cpText = await cpResp.text();
			const lines = cpText.trim().split('\n');
			snapshotTreeSize = parseInt(lines[1]) || 0;
		} catch (e) { snapshotTreeSize = 0; }

		// Step 2: Fetch directory
		await step('directory', async () => {
			const resp = await fetch(PROXY_BASE + '/acme/directory');
			const body = await resp.json();
			currentNonce = resp.headers.get('Replay-Nonce') || '';
			setStepDetail('directory', 'GET /acme/directory', body);
		});

		// Step 3: Get nonce
		await step('nonce', async () => {
			const resp = await fetch(PROXY_BASE + '/acme/new-nonce', { method: 'HEAD' });
			currentNonce = resp.headers.get('Replay-Nonce') || currentNonce;
			setStepDetail('nonce', 'HEAD /acme/new-nonce', { nonce: currentNonce });
		});

		// Step 4: Create account
		await step('account', async () => {
			const jws = await buildJWS(
				ACME_EXTERNAL_URL + '/acme/new-account', currentNonce,
				{ termsOfServiceAgreed: true, contact: ['mailto:demo@example.com'] },
				accountKey, accountJWK, null
			);
			const resp = await acmePost('/acme/new-account', jws);
			accountURL = resp.location;
			setStepDetail('account', { protected: '(JWS with jwk)', payload: { termsOfServiceAgreed: true } }, { status: resp.status, location: accountURL, body: resp.body });
		});

		// Step 5: Create order
		let orderURL, orderBody;
		await step('order', async () => {
			const jws = await buildJWS(
				ACME_EXTERNAL_URL + '/acme/new-order', currentNonce,
				{ identifiers: [{ type: 'dns', value: domain }] },
				accountKey, null, accountURL
			);
			const resp = await acmePost('/acme/new-order', jws);
			orderURL = resp.location;
			orderBody = resp.body;
			setStepDetail('order', { identifiers: [{ type: 'dns', value: domain }] }, resp.body);
		});

		// Step 6: Fetch authorization
		let challengeURL;
		await step('authz', async () => {
			const authzFullURL = orderBody.authorizations[0];
			const jws = await buildJWS(
				authzFullURL, currentNonce, '', accountKey, null, accountURL
			);
			const resp = await acmePost(extractProxyPath(authzFullURL), jws);
			challengeURL = resp.body.challenges[0].url;
			setStepDetail('authz', 'POST-as-GET ' + authzFullURL, resp.body);
		});

		// Step 7: Respond to challenge
		await step('challenge', async () => {
			const jws = await buildJWS(
				challengeURL, currentNonce, {}, accountKey, null, accountURL
			);
			const resp = await acmePost(extractProxyPath(challengeURL), jws);
			setStepDetail('challenge', 'POST {} to challenge (auto-approve)', resp.body);
		});

		// Step 8: Poll order until ready
		await step('poll-ready', async () => {
			let order = orderBody;
			let polls = 0;
			while (order.status === 'pending' || order.status === 'processing') {
				if (++polls > 30) throw new Error('Order did not become ready after 30 polls');
				await sleep(1000);
				const jws = await buildJWS(orderURL, currentNonce, '', accountKey, null, accountURL);
				const resp = await acmePost(extractProxyPath(orderURL), jws);
				order = resp.body;
			}
			orderBody = order;
			setStepDetail('poll-ready', 'Polled ' + polls + ' times', order);
			if (order.status !== 'ready') throw new Error('Order status: ' + order.status);
		});

		// Step 9: Generate certificate key
		await step('certkey', async () => {
			certKey = await generateKeyPair();
			const certJWK = await exportJWK(certKey);
			setStepDetail('certkey', 'Web Crypto: ECDSA P-256', { jwk: certJWK });
		});

		// Step 10: Build CSR
		let csrB64;
		await step('csr', async () => {
			const csrDER = await buildCSR(certKey, domain);
			csrB64 = base64url(csrDER);
			setStepDetail('csr', 'PKCS#10 DER (' + csrDER.length + ' bytes)', { csr_base64url: csrB64.substring(0, 80) + '...' });
		});

		// Step 11: Finalize order
		await step('finalize', async () => {
			const finalizeURL = orderBody.finalize;
			const jws = await buildJWS(
				finalizeURL, currentNonce, { csr: csrB64 }, accountKey, null, accountURL
			);
			const resp = await acmePost(extractProxyPath(finalizeURL), jws);
			let order = resp.body;
			let polls = 0;
			while (order.status === 'processing') {
				if (++polls > 60) throw new Error('Finalization timed out');
				await sleep(2000);
				const pollJWS = await buildJWS(orderURL, currentNonce, '', accountKey, null, accountURL);
				const pollResp = await acmePost(extractProxyPath(orderURL), pollJWS);
				order = pollResp.body;
			}
			orderBody = order;
			setStepDetail('finalize', { csr: csrB64.substring(0, 40) + '...' }, order);
			if (order.status !== 'valid') {
				const detail = order.error ? ' — ' + order.error.detail : '';
				throw new Error('Order status: ' + order.status + detail);
			}
		});

		// Step 12: Download certificate
		await step('download', async () => {
			const certURL = orderBody.certificate;
			const jws = await buildJWS(certURL, currentNonce, '', accountKey, null, accountURL);
			const resp = await acmePost(extractProxyPath(certURL), jws);
			certPEM = typeof resp.body === 'string' ? resp.body : JSON.stringify(resp.body);

			// Extract serial from PEM for proof lookups
			try {
				const b64 = certPEM.split('-----BEGIN CERTIFICATE-----')[1].split('-----END CERTIFICATE-----')[0].trim();
				const der = base64Decode(b64);
				const fields = parseCertDER(der);
				certSerial = (fields.serialNumber || '').toUpperCase();
			} catch (e) { /* serial extraction failed, proofs may not work */ }

			setStepDetail('download', 'POST-as-GET ' + certURL, certPEM.substring(0, 200) + '...');
		});

		// Step 13: Fetch inclusion proof
		await step('inclusion', async () => {
			if (!certSerial) throw new Error('No certificate serial available');
			const resp = await fetch('/proof/inclusion?serial=' + certSerial);
			if (!resp.ok) throw new Error('HTTP ' + resp.status);
			inclusionData = await resp.json();
			setStepDetail('inclusion', 'GET /proof/inclusion?serial=' + certSerial, inclusionData);
		});

		// Step 14: Fetch consistency proof
		await step('consistency', async () => {
			if (snapshotTreeSize <= 0) throw new Error('No tree snapshot available');
			const newSize = inclusionData ? inclusionData.tree_size : snapshotTreeSize + 1;
			if (snapshotTreeSize >= newSize) {
				setStepDetail('consistency', 'Skipped', { reason: 'Tree did not grow (old=' + snapshotTreeSize + ', new=' + newSize + ')' });
				return;
			}
			const resp = await fetch('/proof/consistency?old=' + snapshotTreeSize + '&new=' + newSize);
			if (!resp.ok) throw new Error('HTTP ' + resp.status);
			consistencyData = await resp.json();
			setStepDetail('consistency', 'GET /proof/consistency?old=' + snapshotTreeSize + '&new=' + newSize, consistencyData);
		});

		// Step 15: Verify proofs
		await step('verify', async () => {
			const results = {};
			if (inclusionData) {
				const ok = await verifyInclusionProof(
					inclusionData.leaf_hash, inclusionData.leaf_index,
					inclusionData.tree_size, inclusionData.proof, inclusionData.root_hash
				);
				results.inclusion = ok ? 'PASS' : 'FAIL';
			}
			results.consistency = consistencyData ? 'PRESENT' : 'SKIPPED';
			setStepDetail('verify', 'Client-side SHA-256 verification', results);
		});

		// Show results
		document.getElementById('results').classList.remove('hidden');
		renderCertResult(certPEM);
		if (inclusionData) {
			renderInclusionProof(inclusionData);
			// Run verification and show badge
			try {
				const ok = await verifyInclusionProof(
					inclusionData.leaf_hash, inclusionData.leaf_index,
					inclusionData.tree_size, inclusionData.proof, inclusionData.root_hash
				);
				document.getElementById('inclusion-verify').innerHTML = ok
					? '<span class="inline-flex items-center gap-1 px-3 py-1 rounded-full bg-green-100 text-green-800 text-sm font-medium">PASS — Inclusion proof verified</span>'
					: '<span class="inline-flex items-center gap-1 px-3 py-1 rounded-full bg-red-100 text-red-800 text-sm font-medium">FAIL — Root hash mismatch</span>';
			} catch (e) {
				document.getElementById('inclusion-verify').innerHTML = '<span class="text-sm text-gray-500">Verification error: ' + escapeHTML(e.message) + '</span>';
			}
		}
		if (consistencyData) {
			renderConsistencyProof(consistencyData);
			document.getElementById('consistency-verify').innerHTML = '<span class="inline-flex items-center gap-1 px-3 py-1 rounded-full bg-green-100 text-green-800 text-sm font-medium">PRESENT — Append-only consistency proof available</span>';
		}
		showResultTab('cert');

	} catch (e) {
		console.error('Demo failed at step ' + errorStep + ':', e);
	}

	btn.disabled = false;
	btn.textContent = 'Run Demo';
}

// Initialize
if (!ACME_EXTERNAL_URL) {
	document.getElementById('steps').innerHTML = '<div class="bg-amber-50 border border-amber-200 rounded-lg p-6 text-center"><p class="text-amber-800 font-medium">ACME server is not configured</p><p class="text-amber-600 text-sm mt-1">Enable the ACME server in config.yaml (acme.enabled: true) and restart the service.</p></div>';
	document.getElementById('run-btn').disabled = true;
} else {
	renderSteps();
}
</script>
</body>
</html>`
