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
			<span class="text-sm opacity-75">Merkle Tree Certificates — Experimental</span>
		</div>
	</nav>

	<main class="max-w-7xl mx-auto px-6 py-8">
		<!-- Stats Panel -->
		<section class="bg-white rounded-lg shadow p-6 mb-8"
			hx-get="/admin/stats" hx-trigger="every 5s" hx-swap="innerHTML">
			<h2 class="text-lg font-semibold mb-4">Log Statistics</h2>
			<dl class="grid grid-cols-2 md:grid-cols-3 gap-4">
				<dt class="text-gray-500">Tree Size</dt>
				<dd class="text-2xl font-bold">{{ .Stats.TreeSize }}</dd>
				<dt class="text-gray-500">Revocations</dt>
				<dd class="text-2xl font-bold">{{ .Stats.RevocationCount }}</dd>
				<dt class="text-gray-500">Checkpoints</dt>
				<dd class="text-2xl font-bold">{{ .Stats.CheckpointCount }}</dd>
				<dt class="text-gray-500">Watcher</dt>
				<dd class="text-2xl font-bold">{{ if .WatcherStats.Running }}
					<span class="text-green-600">Running</span>
				{{ else }}
					<span class="text-red-600">Stopped</span>
				{{ end }}</dd>
				<dt class="text-gray-500">Certs Processed</dt>
				<dd class="text-2xl font-bold">{{ .WatcherStats.CertsProcessed }}</dd>
				<dt class="text-gray-500">Latest Checkpoint</dt>
				<dd class="text-sm">{{ formatTime .Stats.LatestCheckpoint }}</dd>
			</dl>
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
