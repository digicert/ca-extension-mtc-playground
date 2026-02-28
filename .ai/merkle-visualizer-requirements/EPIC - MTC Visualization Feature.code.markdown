# EPIC: Merkle Tree Certificate (MTC) Visual Explorer

**Epic ID:** MTC-VIZ-001
**Priority:** P1
**Team:** Platform Engineering / Frontend
**Sprint Target:** 3 sprints (6 weeks)
**Epic Owner:** _[TBD]_
**Last Updated:** 2026-02-28

---

## Executive Summary

Add an interactive visualization feature to the existing MTC platform that provides operators and auditors with sunburst and treemap views of the certificate tree. The visualization must handle trees containing millions of certificates, surface trust/revocation status at a glance, support drill-down navigation from CA → Batch Window → Key Algorithm → Individual Certificate, and integrate seamlessly into the existing main navigation.

The existing system already manages the Merkle tree structure, assertion data, and certificate lifecycle. This epic focuses exclusively on the **read-side visualization layer** that consumes existing APIs and data models.

---

## Problem Statement

The current system provides programmatic and tabular access to certificate and tree data, but lacks a visual interface for:

- Quickly assessing the health and revocation posture of the tree at scale
- Identifying anomalous issuance patterns across CAs and batch windows
- Understanding post-quantum algorithm adoption rates
- Communicating tree state to non-technical stakeholders and auditors
- Drilling from a macro view (millions of certs) down to a single certificate's inclusion proof

Operators currently rely on log queries and tabular reports to answer questions like _"What percentage of Let's Encrypt certs in the last batch window are revoked?"_ — this should be answerable in one glance.

---

## Architecture Context

```
┌─────────────────────────────────────────────────────────┐
│                   Existing System                       │
│                                                         │
│  ┌──────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │ Merkle   │  │  Assertion   │  │   Certificate    │  │
│  │ Tree     │  │  Store       │  │   Lifecycle      │  │
│  │ Engine   │  │              │  │   Manager        │  │
│  └────┬─────┘  └──────┬───────┘  └────────┬─────────┘  │
│       │               │                    │            │
│       └───────────┬───┴────────────────────┘            │
│                   │                                     │
│            ┌──────▼───────┐                             │
│            │  Existing    │                             │
│            │  REST/gRPC   │                             │
│            │  APIs        │                             │
│            └──────┬───────┘                             │
│                   │                                     │
└───────────────────┼─────────────────────────────────────┘
                    │
          ┌─────────▼──────────┐
          │                    │
          │  ★ NEW: MTC        │  ◄── This Epic
          │  Visual Explorer   │
          │                    │
          │  - Sunburst View   │
          │  - Treemap View    │
          │  - Drill-down Nav  │
          │  - Cert Inspector  │
          │  - Anomaly Overlay │
          │                    │
          └────────────────────┘
```

---

## Success Criteria

- [ ] Visualization renders trees of 1M+ certificates without browser performance degradation
- [ ] Users can switch between sunburst and treemap views
- [ ] Revoked certificates are visually distinct at every zoom level
- [ ] Drill-down from root → CA → Batch → Algorithm → Certificate completes in < 200ms
- [ ] Feature is accessible from main navigation with no disruption to existing workflows
- [ ] Color modes for trust status, key algorithm, and certificate age are available
- [ ] Side panel shows contextual detail for any selected segment or certificate
- [ ] Feature passes accessibility audit (WCAG 2.1 AA)

---

## Dependencies

| Dependency | Owner | Status |
|------------|-------|--------|
| Certificate listing API (paginated, filterable by CA, batch, algo, status) | Backend | ✅ Exists |
| Revocation status API (bitmap or list of revoked indices) | Backend | ✅ Exists |
| Tree metadata API (tree head, depth, total leaves, batch windows) | Backend | ✅ Exists |
| Inclusion proof API (given cert index, return proof path) | Backend | ✅ Exists |
| Main navigation shell (sidebar/topnav component) | Frontend | ✅ Exists |
| Design system / component library | Frontend | ✅ Exists |

### New API Requirements (if not already available)

| Endpoint | Purpose | Notes |
|----------|---------|-------|
| `GET /api/v1/tree/summary` | Aggregated counts by CA, batch, algorithm, status | Needed for rendering without fetching all certs |
| `GET /api/v1/tree/summary?groupBy=ca,batch,algo` | Hierarchical aggregation | Powers the drill-down without client-side aggregation of millions of rows |
| `GET /api/v1/tree/anomalies` | Flagged issuance patterns | Optional, supports anomaly overlay (Story 10) |
| `WS /api/v1/tree/stream` | Real-time batch append events | Optional, supports live streaming (Story 11) |

---

## Stories

---

### Story 1: Navigation Integration & Feature Shell

**ID:** MTC-VIZ-101
**Points:** 3
**Priority:** P0 — Must Have
**Sprint:** 1

#### Description

Add a new "Tree Explorer" entry to the main navigation. Clicking it renders a new page/view container that will host the visualization components. This story establishes the route, layout shell, and lazy-loading boundary.

#### Acceptance Criteria

- [ ] New navigation item "Tree Explorer" with a tree/graph icon appears in the main sidebar/topnav
- [ ] Route `/explorer` (or equivalent) is registered and renders the shell component
- [ ] Shell includes: header area, tab bar (Sunburst / Treemap), controls toolbar, main visualization area, and collapsible side panel
- [ ] Layout is responsive: side panel collapses below the visualization on viewports < 768px
- [ ] Visualization component is lazy-loaded (code-split) to avoid impacting initial bundle size
- [ ] Empty state renders a loading skeleton while data is fetched
- [ ] Navigation item shows an active/selected state when on the explorer route

#### Technical Notes

```
- Add route to existing router configuration
- Use existing layout shell component; add new nav entry via config
- Create <ExplorerShell> component with slots for:
    - <ControlsToolbar>
    - <VisualizationCanvas>
    - <DetailSidePanel>
- Use React.lazy() or equivalent framework dynamic import
- Side panel width: 320px desktop, full-width on mobile
- Persist last-used view mode (sunburst/treemap) in localStorage
```

---

### Story 2: Data Aggregation API Integration

**ID:** MTC-VIZ-102
**Points:** 5
**Priority:** P0 — Must Have
**Sprint:** 1

#### Description

Implement the data layer that fetches and transforms tree summary data into the hierarchical structure needed by both visualization views. This must handle the scale constraint — we cannot fetch millions of individual certificates for the top-level view.

#### Acceptance Criteria

- [ ] Data service calls `GET /api/v1/tree/summary?groupBy=ca,batch,algo` to retrieve aggregated hierarchy
- [ ] Response is transformed into a nested tree structure:
  ```
  Root
  ├── CA: Let's Encrypt
  │   ├── Batch: 2026-02-28T06:00Z
  │   │   ├── Algo: ML-DSA-44 (count: 12,340, revoked: 23)
  │   │   ├── Algo: ECDSA-P256 (count: 8,120, revoked: 5)
  │   │   └── ...
  │   ├── Batch: 2026-02-28T12:00Z
  │   │   └── ...
  │   └── ...
  ├── CA: DigiCert
  │   └── ...
  └── ...
  ```
- [ ] Each node in the hierarchy includes: `name`, `certCount`, `revokedCount`, `pqCount`, `children[]`
- [ ] Data is cached client-side with a configurable TTL (default: 60 seconds)
- [ ] Loading, error, and empty states are handled and surfaced to the UI
- [ ] When user drills to leaf level, a paginated call to `GET /api/v1/certificates?ca=X&batch=Y&algo=Z` fetches individual certs
- [ ] Revocation status is fetched via `GET /api/v1/revocations` and merged into the hierarchy

#### Technical Notes

```
- Create a DataService class/module:
    - fetchTreeSummary(groupBy: string[]): HierarchyNode
    - fetchCertificates(filters: CertFilter, page: number): CertPage
    - fetchRevocations(): RevocationBitmap
- Use SWR, React Query, or equivalent for caching and revalidation
- HierarchyNode interface:
    interface HierarchyNode {
      name: string;
      level: 'root' | 'ca' | 'batch' | 'algo' | 'cert';
      certCount: number;
      revokedCount: number;
      pqCount: number;
      classicalCount: number;
      children?: HierarchyNode[];
      metadata?: Record<string, unknown>;
    }
- For leaf-level cert data:
    interface Certificate {
      index: number;
      domain: string;
      ca: string;
      algorithm: string;
      isPQ: boolean;
      issuedAt: string;
      batchWindow: string;
      revoked: boolean;
      revocationReason?: string;
    }
- Pagination: 500 certs per page at leaf level
- Total response size for summary endpoint should be < 50KB even for 10M cert trees
```

---

### Story 3: Sunburst Visualization — Core Rendering

**ID:** MTC-VIZ-103
**Points:** 8
**Priority:** P0 — Must Have
**Sprint:** 1

#### Description

Implement the sunburst (radial partition) visualization that renders the certificate hierarchy as concentric rings. Each ring represents a level in the hierarchy (CA → Batch → Algorithm). Arc size is proportional to certificate count. Revocation status is overlaid as a red sub-arc.

#### Acceptance Criteria

- [ ] Sunburst renders with center circle showing current context name and total cert count
- [ ] Ring 1 (inner): CA-level segments, arc width proportional to cert count
- [ ] Ring 2 (middle): Batch window segments within each CA arc
- [ ] Ring 3 (outer): Algorithm segments within each batch arc
- [ ] Each arc has a revocation overlay — a red-tinted sub-arc proportional to the revocation ratio within that segment
- [ ] An outer glow ring shows post-quantum algorithm adoption ratio per CA (purple tint)
- [ ] Arcs have small gaps between them for visual separation
- [ ] Labels render inside arcs when the arc sweep is large enough (> ~10°); labels are rotated to follow the arc
- [ ] Canvas-based rendering using `<canvas>` for performance at scale
- [ ] Renders 500+ segments (typical for a large tree summary) at 60fps
- [ ] Gradient fills from inner to outer edge of each arc for depth perception

#### Technical Notes

```
- Use HTML5 Canvas (not SVG) for performance
- Rendering pipeline:
    1. Compute arc angles from hierarchy data (proportional layout)
    2. Draw edges (gaps between arcs)
    3. Draw arcs per ring with radial gradients
    4. Overlay revocation sub-arcs
    5. Draw PQ outer glow ring
    6. Render labels with rotation transforms
- Ring radii (as fraction of min(width, height) / 2):
    - Center circle: 0 → 0.18
    - Ring 1 (CA): 0.20 → 0.48
    - Ring 2 (Batch): 0.50 → 0.72
    - Ring 3 (Algo): 0.74 → 0.88
    - PQ glow: 0.90 → 0.96
- Color assignment: each CA gets a distinct hue; children inherit with reduced saturation
- Arc gap: 0.008 radians between segments
- Label font size: scale with arc sweep, min 6px, max 12px
- Use requestAnimationFrame for smooth transitions when drilling
```

---

### Story 4: Treemap Visualization — Core Rendering

**ID:** MTC-VIZ-104
**Points:** 8
**Priority:** P0 — Must Have
**Sprint:** 1

#### Description

Implement the treemap (squarified rectangle partition) visualization as an alternative view. Each rectangle's area represents certificate count. Rectangles contain nested detail: revocation strip, PQ indicator bar, and individual certificate dots when zoomed in.

#### Acceptance Criteria

- [ ] Treemap renders using a squarified layout algorithm (minimizes aspect ratio of rectangles)
- [ ] Each rectangle represents a node at the current drill-down level
- [ ] Rectangle area is proportional to certificate count
- [ ] Each rectangle displays:
    - Node name (CA, batch label, or algorithm)
    - Certificate count
    - Revocation percentage
    - A **red bottom strip** whose height is proportional to revocation ratio
    - A **purple top bar** whose width is proportional to PQ algorithm ratio
- [ ] When a rectangle is large enough (> 80px × 70px), render individual certificate dots inside it:
    - Each dot represents one certificate
    - Dot color reflects the active color mode (status / algorithm / age)
    - Revoked certs show as red dots with an ✕ overlay
- [ ] Canvas-based rendering for performance
- [ ] Handles 200+ rectangles at the top level without jank

#### Technical Notes

```
- Implement squarified treemap algorithm:
    function squarify(values: number[], rect: Rect): Rect[]
  Reference: Bruls, Huizing, van Wijk (2000) — "Squarified Treemaps"
- Rendering pipeline:
    1. Compute squarified layout from hierarchy data
    2. Draw rectangle backgrounds with rounded corners (r=6)
    3. Draw revocation strip (bottom)
    4. Draw PQ indicator bar (top, 4px height)
    5. Render labels (name, count, revocation %)
    6. If space permits, render cert dot grid
- Cert dot sizing:
    dotSize = clamp(3, 16, sqrt(rectArea / certCount) * 0.6)
- Dot grid columns:
    cols = floor(availableWidth / (dotSize + 1))
- Max dots rendered per rectangle: cols × floor(availableHeight / (dotSize + 1))
- Padding: 2px between rectangles, 6px internal padding
```

---

### Story 5: Drill-Down Navigation & Breadcrumb

**ID:** MTC-VIZ-105
**Points:** 5
**Priority:** P0 — Must Have
**Sprint:** 2

#### Description

Implement click-to-drill-down on both sunburst and treemap views, with a breadcrumb trail for navigation context. Clicking a segment drills into that node's children. The breadcrumb allows jumping back to any ancestor level.

#### Acceptance Criteria

- [ ] Clicking a segment (arc or rectangle) that has children drills into it:
    - The clicked node becomes the new root of the visualization
    - The visualization re-renders with the children of the clicked node
    - Transition animates smoothly (fade or zoom, < 300ms)
- [ ] Clicking a leaf-level segment (no children) opens the detail panel instead of drilling
- [ ] Breadcrumb trail renders above the visualization:
    - Format: `All CAs › Let's Encrypt › Feb 28 06:00 › ML-DSA-44`
    - Each breadcrumb segment is clickable to jump to that level
    - Current level is visually highlighted
- [ ] "Drill Up" button in the toolbar navigates one level up
- [ ] Drill path is preserved in URL query params for shareability:
    - Example: `/explorer?path=letsencrypt/2026-02-28T06:00Z/ML-DSA-44`
- [ ] Keyboard shortcut: `Escape` drills up one level, `Backspace` returns to root

#### Technical Notes

```
- Maintain a drillPath: HierarchyNode[] stack
- On drill-down:
    1. Push clicked node onto drillPath
    2. Set currentNode = clicked node
    3. If node.level === 'algo' (leaf group), fetch paginated certs via API
    4. Re-render visualization with currentNode.children
    5. Update breadcrumb
    6. Update URL query params
- On drill-up:
    1. Pop from drillPath
    2. Set currentNode = drillPath[last]
    3. Re-render
- Animation: use canvas globalAlpha fade from 0→1 over 200ms
- URL sync: use URLSearchParams, update on drill, read on mount
```

---

### Story 6: Interactive Hover & Tooltip System

**ID:** MTC-VIZ-106
**Points:** 5
**Priority:** P0 — Must Have
**Sprint:** 2

#### Description

Implement hover detection on canvas-rendered segments and display contextual tooltips with summary data. Hit-testing must be efficient for hundreds of segments.

#### Acceptance Criteria

- [ ] Hovering over a segment highlights it (brightness increase or border glow)
- [ ] A tooltip appears near the cursor showing:
    - **For group nodes:** Name, cert count, revoked count (with %), PQ count, "Click to drill down"
    - **For individual certs:** Domain, CA, algorithm, issued date, batch, revocation status
- [ ] Tooltip repositions to stay within viewport bounds
- [ ] Tooltip appears within 50ms of hover (no perceptible delay)
- [ ] Cursor changes to `pointer` when over a clickable segment
- [ ] Hover state clears when cursor leaves the canvas

#### Technical Notes

```
- Maintain a segments[] array populated during each render pass:
    interface Segment {
      type: 'arc' | 'rect';
      // For arcs:
      cx?: number; cy?: number; r1?: number; r2?: number;
      startAngle?: number; endAngle?: number;
      // For rects:
      x?: number; y?: number; w?: number; h?: number;
      // Data:
      node: HierarchyNode;
      certs?: Certificate[];
    }
- Hit-testing on mousemove:
    - For rects: simple bounds check
    - For arcs: compute distance from center and angle, check if within ring and arc bounds
- Throttle mousemove handler to 16ms (60fps) using requestAnimationFrame
- Tooltip is a positioned HTML div (not canvas-rendered) for text selection and accessibility
- Highlight: re-render the single hovered segment with modified fill (brightness +30%)
```

---

### Story 7: Color Mode Switching

**ID:** MTC-VIZ-107
**Points:** 3
**Priority:** P1 — Should Have
**Sprint:** 2

#### Description

Implement three color modes that re-color the visualization to answer different questions. The mode is selected via a dropdown in the controls toolbar.

#### Acceptance Criteria

- [ ] **Trust Status** mode (default):
    - Valid = green (#34d399 family)
    - Revoked = red (#f87171 family)
    - Applied to: cert dots, revocation overlays, arc fills
- [ ] **Key Algorithm** mode:
    - Post-Quantum (ML-DSA-44, ML-DSA-65, SLH-DSA) = purple (#a78bfa family)
    - Classical (ECDSA, Ed25519, RSA) = blue (#60a5fa family)
    - Revoked certs still show red border/overlay regardless of mode
- [ ] **Certificate Age** mode:
    - Fresh (0-2 days) = green
    - Mid-life (3-9 days) = amber/orange
    - Expiring (10-14 days) = red
    - Uses a continuous gradient, not discrete buckets
- [ ] Switching modes re-renders the visualization without resetting drill-down state
- [ ] A dynamic legend row below the controls updates to reflect the active color mode
- [ ] Color mode preference persists in localStorage

#### Technical Notes

```
- Create a colorStrategy(cert: Certificate, mode: ColorMode): {fill, stroke, glow}
- ColorMode = 'status' | 'algorithm' | 'age'
- For group-level rendering (arcs/rects), aggregate:
    - status: use revocation ratio for red intensity
    - algorithm: use PQ ratio for purple vs blue blend
    - age: use average age for gradient position
- Legend component reads active mode and renders appropriate swatches
- Re-render is a full canvas redraw (cheap since layout doesn't change)
```

---

### Story 8: Detail Side Panel

**ID:** MTC-VIZ-108
**Points:** 5
**Priority:** P0 — Must Have
**Sprint:** 2

#### Description

Implement the collapsible side panel that shows contextual details for the selected/hovered segment. At the top level it shows a CA summary; at leaf level it shows individual certificate details.

#### Acceptance Criteria

- [ ] **Default state (no selection):** Shows overview with all CAs listed as cards:
    - CA name, cert count, revoked count, PQ percentage
    - Cards sorted by cert count descending
- [ ] **Group node selected:** Shows:
    - Node name, total certs, revoked count and percentage, PQ count
    - List of revoked certificates within that group (scrollable, max 50 shown with "load more")
    - Each revoked cert card shows: domain, CA, algorithm, index
- [ ] **Individual certificate selected:** Shows:
    - Domain name
    - CA name
    - Key algorithm with PQ/Classical badge
    - Issued date and batch window
    - Certificate index in tree
    - Age in days
    - Revocation status with reason (if revoked)
    - Button: "Show Inclusion Proof" (triggers proof path visualization — see Story 9)
- [ ] Panel is collapsible via a toggle button
- [ ] Panel scrolls independently from the main visualization
- [ ] Search input at top of panel filters the certificate list by domain name

#### Technical Notes

```
- Component: <DetailSidePanel>
    Props:
      - selectedNode: HierarchyNode | null
      - selectedCert: Certificate | null
      - allCerts: Certificate[] (for default overview)
      - revocations: Set<number>
      - onShowProof: (certIndex: number) => void
- Certificate cards are virtualized (react-window or equivalent) for leaf-level lists
- Search is debounced (300ms) and filters client-side within the current group
- Revoked certs section uses a distinct red-bordered card style
- "Show Inclusion Proof" dispatches to the proof visualization system (Story 9)
```

---

### Story 9: Inclusion Proof Path Visualization

**ID:** MTC-VIZ-109
**Points:** 5
**Priority:** P1 — Should Have
**Sprint:** 2

#### Description

When a user selects a certificate and clicks "Show Inclusion Proof," fetch the Merkle inclusion proof from the API and overlay the proof path on the visualization. This answers: _"How do I know this certificate is in the tree?"_

#### Acceptance Criteria

- [ ] Clicking "Show Inclusion Proof" in the side panel calls `GET /api/v1/tree/proof/{certIndex}`
- [ ] The API returns the sibling hashes needed to recompute the path from leaf to root
- [ ] On the **sunburst view:** The segments containing the proof path nodes glow gold (#fbbf24), with animated pulse
- [ ] On the **treemap view:** The rectangles containing proof path nodes get a gold border and glow
- [ ] A proof summary appears in the side panel:
    - Proof length (number of hashes)
    - Proof size in bytes (hashes × 32)
    - Each hash in the path listed with its level
    - Verification result: ✅ Valid (recomputed root matches signed tree head) or ❌ Invalid
- [ ] "Clear Proof" button removes the overlay
- [ ] If the tree is too deep to show all proof nodes in the current view, auto-drill to the appropriate level

#### Technical Notes

```
- API response shape:
    interface InclusionProof {
      certIndex: number;
      treeSize: number;
      proofHashes: string[];  // sibling hashes, leaf-to-root order
      treeHead: string;       // signed root hash
    }
- Client-side verification:
    1. Start with leaf hash = cert.hash
    2. For each proofHash[i], compute parent = H(left || right) based on index parity
    3. Compare final result to treeHead
- Highlight mapping:
    - Map each proof hash to its position in the hierarchy
    - For sunburst: find the arc segment containing that subtree range
    - For treemap: find the rectangle containing that subtree range
- Gold highlight: draw a second pass over highlighted segments with strokeStyle=#fbbf24, lineWidth=3, shadowBlur=10
- Pulse animation: oscillate shadowBlur between 6 and 14 using requestAnimationFrame
```

---

### Story 10: Anomaly Detection Overlay (Heatmap)

**ID:** MTC-VIZ-110
**Points:** 8
**Priority:** P2 — Nice to Have
**Sprint:** 3

#### Description

Add an optional heatmap overlay that highlights anomalous issuance patterns. This helps operators detect misissuance — certificates issued for domains that don't match expected patterns, unusual spikes in issuance volume, or unexpected algorithm usage.

#### Acceptance Criteria

- [ ] Toggle button "🔥 Anomaly Overlay" in the controls toolbar enables/disables the overlay
- [ ] When enabled, calls `GET /api/v1/tree/anomalies` to fetch flagged patterns
- [ ] Anomaly types supported:
    - **Volume spike:** A batch window has > 2σ more certs than the rolling average
    - **Unexpected algorithm:** A CA issues certs with an algorithm not in their declared set
    - **Domain pattern mismatch:** Certs issued for domains outside the CA's typical TLD distribution
    - **Revocation cluster:** A batch has > 5% revocation rate (significantly above baseline)
- [ ] Anomalous segments are overlaid with a pulsing orange/red heatmap gradient
- [ ] Anomaly severity is mapped to color intensity (low = warm yellow, high = hot red)
- [ ] Hovering an anomalous segment shows the anomaly type and details in the tooltip
- [ ] Side panel shows an "Anomalies" tab listing all flagged segments with severity and type
- [ ] Anomaly data refreshes on the same cadence as the main data (configurable TTL)

#### Technical Notes

```
- API response shape:
    interface Anomaly {
      segmentPath: string[];  // e.g., ["Let's Encrypt", "2026-02-28T06:00Z"]
      type: 'volume_spike' | 'unexpected_algo' | 'domain_mismatch' | 'revocation_cluster';
      severity: number;       // 0.0 → 1.0
      details: string;
      detectedAt: string;
    }
- Overlay rendering:
    - After main render pass, iterate anomalies
    - For each anomaly, find matching segment(s) in the segments[] array
    - Draw a semi-transparent overlay:
        - Sunburst: radial gradient on the arc, orange→red based on severity
        - Treemap: full-rect overlay with pulsing opacity
- Pulse: sinusoidal opacity oscillation, period = 2s, range = 0.3 → 0.7
- If API is unavailable, degrade gracefully (button disabled with tooltip explaining why)
```

---

### Story 11: Real-Time Streaming & Tree Growth Animation

**ID:** MTC-VIZ-111
**Points:** 8
**Priority:** P2 — Nice to Have
**Sprint:** 3

#### Description

Connect to the WebSocket stream of new batch publications and animate the tree growing in real time. As new batches are appended, the visualization smoothly expands to incorporate them.

#### Acceptance Criteria

- [ ] Toggle button "⚡ Live Mode" in the controls toolbar enables/disables streaming
- [ ] When enabled, connects to `WS /api/v1/tree/stream`
- [ ] Incoming events include:
    - `batch_published`: New batch with summary counts
    - `cert_revoked`: Individual certificate revocation
    - `tree_head_signed`: New signed tree head
- [ ] On `batch_published`:
    - New batch segment animates into the visualization (grows from 0 to full size over 500ms)
    - Stats bar updates in real time
    - A brief toast notification shows: "New batch: +{count} certs from {CA}"
- [ ] On `cert_revoked`:
    - The affected segment's revocation overlay grows
    - If the cert is visible as a dot, it turns red with an ✕ animation
    - Side panel revoked list updates if the affected group is selected
- [ ] On `tree_head_signed`:
    - Root node pulses briefly to indicate a new signed head
    - Tree head hash updates in the UI
- [ ] Connection status indicator: 🟢 Connected / 🔴 Disconnected / 🟡 Reconnecting
- [ ] Auto-reconnect with exponential backoff (1s, 2s, 4s, max 30s)
- [ ] Live mode does not disrupt current drill-down state

#### Technical Notes

```
- WebSocket message format:
    interface TreeEvent {
      type: 'batch_published' | 'cert_revoked' | 'tree_head_signed';
      timestamp: string;
      data: BatchPublished | CertRevoked | TreeHeadSigned;
    }
- On batch_published:
    1. Insert new node into hierarchy at correct position
    2. Recompute layout with animation interpolation
    3. Use FLIP technique: record old positions, compute new, animate delta
- On cert_revoked:
    1. Add index to local revocation set
    2. Increment revokedCount on affected hierarchy nodes (walk up)
    3. Re-render affected segments only (dirty flag)
- Animation: use requestAnimationFrame with easing (ease-out cubic)
- Toast: use existing notification system or a lightweight toast component
- Reconnection: implement in DataService with event emitter pattern
```

---

### Story 12: Consistency Proof Visualization

**ID:** MTC-VIZ-112
**Points:** 5
**Priority:** P2 — Nice to Have
**Sprint:** 3

#### Description

Visualize how two tree heads relate to each other via a consistency proof, demonstrating that the log is append-only. This is a key auditability feature of the MTC architecture.

#### Acceptance Criteria

- [ ] "Compare Tree Heads" button opens a modal/drawer with two tree head selectors
- [ ] User selects an older tree head and a newer tree head (from a dropdown of recent heads)
- [ ] System calls `GET /api/v1/tree/consistency-proof?old={hash}&new={hash}`
- [ ] Visualization shows:
    - The older tree as a shaded region within the newer tree
    - The consistency proof path highlighted in a distinct color (cyan)
    - Nodes that exist only in the newer tree shown with a "new" badge
- [ ] Side panel shows:
    - Old tree head hash and size
    - New tree head hash and size
    - Number of new certificates added
    - Consistency proof verification result: ✅ Append-only confirmed or ❌ Inconsistency detected
- [ ] If inconsistency is detected, a prominent red warning banner appears

#### Technical Notes

```
- API response shape:
    interface ConsistencyProof {
      oldTreeSize: number;
      newTreeSize: number;
      proofHashes: string[];
      verified: boolean;
    }
- Visual approach:
    - Render the full (new) tree
    - Overlay a semi-transparent mask on the region corresponding to the old tree
    - Highlight consistency proof nodes in cyan
- For sunburst: the old tree region is the first N leaves; shade the corresponding arcs
- For treemap: shade the first N certs' rectangles
```

---

### Story 13: Accessibility & Keyboard Navigation

**ID:** MTC-VIZ-113
**Points:** 5
**Priority:** P1 — Should Have
**Sprint:** 3

#### Description

Ensure the visualization meets WCAG 2.1 AA accessibility standards and is navigable via keyboard.

#### Acceptance Criteria

- [ ] All interactive elements (tabs, buttons, dropdowns) are keyboard-accessible
- [ ] Canvas visualization has an ARIA role and label
- [ ] Tab key cycles through segments in the visualization (focus ring rendered on canvas)
- [ ] Enter/Space activates the focused segment (drill-down or select)
- [ ] Escape drills up one level
- [ ] Screen reader announces: segment name, cert count, revocation status when focused
- [ ] Color modes all pass contrast ratio requirements (4.5:1 for text, 3:1 for UI components)
- [ ] A high-contrast mode is available that uses patterns (hatching for revoked) in addition to color
- [ ] Tooltip content is accessible to screen readers via aria-live region
- [ ] All text is resizable to 200% without loss of functionality

#### Technical Notes

```
- Maintain a focusedSegmentIndex state
- On Tab: increment index, re-render with focus ring on that segment
- Focus ring: 2px dashed white outline around the segment
- ARIA: <canvas role="img" aria-label="Merkle Tree Certificate visualization">
- Hidden screen-reader div updated on focus change:
    <div aria-live="polite" class="sr-only">{segment description}</div>
- High-contrast mode: draw diagonal hatching pattern on revoked segments
- Test with: axe-core, VoiceOver, NVDA
```

---

### Story 14: Performance Optimization for 1M+ Certificate Trees

**ID:** MTC-VIZ-114
**Points:** 8
**Priority:** P1 — Should Have
**Sprint:** 3

#### Description

Optimize rendering and data handling to ensure smooth performance when the tree contains millions of certificates. The summary API handles server-side aggregation, but client-side rendering and interaction must also be optimized.

#### Acceptance Criteria

- [ ] Initial render of summary data (top 2 hierarchy levels) completes in < 100ms
- [ ] Drill-down re-render completes in < 200ms
- [ ] Hover hit-testing responds in < 16ms (60fps)
- [ ] Memory usage stays below 200MB for a 10M certificate tree
- [ ] Canvas rendering uses offscreen canvas for complex layers (pre-rendered, composited)
- [ ] Cert dot grid at leaf level uses virtualization — only renders dots visible in the viewport
- [ ] Web Worker handles data transformation and layout computation off the main thread
- [ ] Debounced resize handler prevents layout thrashing
- [ ] Profile and eliminate any forced synchronous layouts

#### Technical Notes

```
- Optimization strategies:
    1. Server-side aggregation: never fetch all certs at once
    2. Offscreen canvas: pre-render static layers (backgrounds, labels)
       and composite onto main canvas
    3. Spatial index for hit-testing: build a simple grid-based index
       on render, O(1) lookup on mousemove
    4. Web Worker for layout:
       - squarify() computation
       - Arc angle computation
       - Post to main thread as transferable ArrayBuffer
    5. Level-of-detail: at high zoom levels, skip rendering segments
       smaller than 1px
    6. RequestIdleCallback for non-critical updates (legend, stats)
- Benchmarking:
    - Create synthetic datasets: 100K, 1M, 10M cert summaries
    - Measure: time-to-first-render, drill-down latency, memory
    - Target: all metrics green on mid-range laptop (8GB RAM, integrated GPU)
- Memory management:
    - Release leaf-level cert data when drilling up
    - Use WeakRef for cached hierarchy nodes
```

---

### Story 15: Export & Sharing

**ID:** MTC-VIZ-115
**Points:** 3
**Priority:** P2 — Nice to Have
**Sprint:** 3

#### Description

Allow users to export the current visualization state as an image or shareable link for reports and audits.

#### Acceptance Criteria

- [ ] "Export" dropdown in toolbar with options:
    - **PNG:** Exports current canvas as a high-resolution PNG (2x DPI)
    - **SVG:** Generates an SVG equivalent of the current view (for vector editing)
    - **Share Link:** Copies a URL with encoded view state (view mode, drill path, color mode, highlighted proof)
    - **JSON:** Exports the current hierarchy data as JSON
- [ ] Exported images include: title, timestamp, legend, and stats bar
- [ ] Share link restores the exact view state when opened
- [ ] Export respects the current color mode and any active overlays

#### Technical Notes

```
- PNG: canvas.toDataURL('image/png') at 2x resolution
- SVG: re-render using an SVG renderer (same layout logic, different output)
    - Consider using a shared layout engine that outputs to both Canvas and SVG
- Share link: encode state in URL hash:
    #view=sunburst&path=letsencrypt/batch1&color=status&proof=42
- JSON: serialize currentNode subtree with counts
- Add watermark/footer to exported images with system name and timestamp
```

---

## Non-Functional Requirements

| Requirement | Target | Measurement |
|-------------|--------|-------------|
| Initial load time | < 2s on 4G | Lighthouse |
| Bundle size (visualization module) | < 150KB gzipped | Webpack analyzer |
| Canvas FPS during interaction | ≥ 60fps | Chrome DevTools Performance |
| Memory (10M cert summary) | < 200MB | Chrome DevTools Memory |
| API response (summary) | < 500ms p95 | Server metrics |
| Accessibility | WCAG 2.1 AA | axe-core audit |
| Browser support | Chrome 120+, Firefox 120+, Safari 17+, Edge 120+ | Manual testing |

---

## Testing Strategy

| Test Type | Scope | Tool |
|-----------|-------|------|
| Unit | Layout algorithms (squarify, arc computation), color strategies, data transforms | Jest / Vitest |
| Integration | Data service → visualization rendering pipeline | Testing Library + Canvas mock |
| Visual regression | Snapshot comparison of rendered canvases across changes | Playwright + Percy |
| Performance | Render benchmarks at 100K / 1M / 10M scale | Custom benchmark harness |
| Accessibility | Keyboard nav, screen reader, contrast | axe-core + manual VoiceOver/NVDA |
| E2E | Full user flows: navigate, drill, hover, export | Playwright |

---

## Rollout Plan

| Phase | Scope | Gate |
|-------|-------|------|
| Alpha | Internal team only, feature-flagged | All P0 stories complete |
| Beta | Select operator accounts, opt-in | P0 + P1 stories complete, performance targets met |
| GA | All users, main navigation | All stories complete, accessibility audit passed |

---

## Open Questions

| # | Question | Owner | Status |
|---|----------|-------|--------|
| 1 | Does the summary aggregation API exist, or does it need to be built? | Backend | 🔴 Open |
| 2 | What is the maximum number of CAs we need to support in a single tree? | Product | 🔴 Open |
| 3 | Should the anomaly detection run server-side or client-side? | Architecture | 🔴 Open |
| 4 | What is the WebSocket event schema for live streaming? | Backend | 🔴 Open |
| 5 | Do we need to support offline/cached viewing of the visualization? | Product | 🔴 Open |
| 6 | What revocation reasons should be displayed? (Key compromise only per MTC spec, or broader?) | Security | 🔴 Open |

---

## References

- [IETF PLANTS — Merkle Tree Certificates Draft](https://datatracker.ietf.org/doc/draft-ietf-plants-merkle-tree-certs/)
- [Google Security Blog — Cultivating Robust and Efficient Certificate Management](https://security.googleblog.com/2026/02/cultivating-robust-and-efficient.html)
- [Cloudflare — Keeping the Internet Fast and Secure: Introducing Merkle Tree Certificates](https://blog.cloudflare.com/bootstrap-mtc/)
- [Squarified Treemaps — Bruls, Huizing, van Wijk (2000)](https://www.win.tue.nl/~vanwijk/stm.pdf)
- [Certificate Transparency RFC 6962](https://datatracker.ietf.org/doc/html/rfc6962)