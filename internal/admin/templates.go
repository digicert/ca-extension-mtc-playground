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
