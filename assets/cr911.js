/* CyRECS911 Matrix — attack-first rendering (no legacy merge)
   - Tiles show technique names (not CR-IDs)
   - Click shows attack details (from layer metadata / NG911 Note)
   - Playbook remains a secondary link (not rendered inline)
*/
(function () {
  console.log("[CyRECS911] cr911.js loaded (attack-first, no legacy merge) v2");

  const esc = (s) =>
    String(s || "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;");

  // Column ordering (stable)
  const tacticOrder = [
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
    "unmapped"
  ];

  const tacticLabelOverrides = {
    impact: "Impact / Availability",
    collection: "Collection / Monitoring",
    "defense-evasion": "Defense Evasion",
    "privilege-escalation": "Privilege Escalation",
    "initial-access": "Initial Access",
    exfiltration: "Exfiltration",
    "command-and-control": "Command & Control",
    unmapped: "Unmapped"
  };

  function tacticTitle(id) {
    if (!id) return "Unmapped";
    if (tacticLabelOverrides[id]) return tacticLabelOverrides[id];
    return id
      .split("-")
      .map((p) => p.charAt(0).toUpperCase() + p.slice(1))
      .join(" ");
  }

  function metaToObject(metadataArr) {
    const o = Object.create(null);
    (metadataArr || []).forEach((m) => {
      if (!m || !m.name) return;
      o[m.name] = m.value;
    });
    return o;
  }

  // Example: "Phishing → workstation compromises (PSAP, IT_Network)"
  // returns { title: "Phishing → workstation compromises", affected: ["PSAP","IT_NETWORK"] }
  function parseNoteForTitleAndAffected(noteOrComment) {
    const raw = String(noteOrComment || "").trim();
    if (!raw) return { title: "", affected: [] };

    const m = raw.match(/^(.*?)(?:\s*\((.*?)\)\s*)?$/);
    const title = (m && m[1] ? m[1].trim() : raw).trim();

    const affectedRaw = m && m[2] ? m[2].trim() : "";
    const affected = affectedRaw
      ? affectedRaw
          .split(/[;,]+/)
          .map((s) => s.trim())
          .filter(Boolean)
          .map((s) => s.replace(/\s+/g, "_").toUpperCase())
      : [];

    return { title, affected };
  }

  function renderMarkdown(md) {
    marked.setOptions({ mangle: false, headerIds: true, breaks: false });
    const html = marked.parse(md || "");
    return DOMPurify.sanitize(html);
  }

  function highlightCode() {
    try {
      hljs.highlightAll();
    } catch (e) {}
  }

  function setPlaybookButtons(playbookPath, fallbackName) {
    const openRaw = document.getElementById("btn-open-raw");
    const download = document.getElementById("btn-download");
    if (!openRaw || !download) return;

    if (!playbookPath) {
      openRaw.style.display = "none";
      download.style.display = "none";
      return;
    }

    // Normalize to a relative file URL
    let href = String(playbookPath).trim();
    if (!href) {
      openRaw.style.display = "none";
      download.style.display = "none";
      return;
    }

    // If they gave only an id, assume playbooks/<id>.md
    if (!href.includes("/") && !href.endsWith(".md")) {
      href = "playbooks/" + href + ".md";
    } else if (!href.includes("/") && href.endsWith(".md")) {
      href = "playbooks/" + href;
    }

    openRaw.href = href;
    openRaw.style.display = "inline-flex";

    download.href = href;
    download.style.display = "inline-flex";
    download.setAttribute("download", (fallbackName || "playbook") + ".md");
  }

  function normalizeTechniqueFromLayer(entry, tacticName) {
    const meta = metaToObject(entry.metadata || []);

    const displayName =
      meta["Display Name"] ||
      meta["Technique Name"] ||
      meta["NG911 Title"] ||
      "";

    const note =
      meta["Attack Overview"] ||
      meta["How it works"] ||
      meta["How the Attack Works"] ||
      meta["Attack Mechanics"] ||
      meta["NG911 Note"] ||
      entry.comment ||
      "";

    // Derive a clean title and affected tags even when we only have NG911 Note
    const parsed = parseNoteForTitleAndAffected(displayName || note || entry.comment);

    const name = (displayName || parsed.title || entry.comment || entry.techniqueID || "").trim();

    const affectedText =
      meta["Affected elements"] ||
      meta["Affected Elements"] ||
      meta["Targets"] ||
      (parsed.affected.length ? parsed.affected.join(", ") : "");

    const affected = affectedText
      ? affectedText
          .split(/[;,]+/)
          .map((s) => s.trim())
          .filter(Boolean)
          .map((s) => s.replace(/\s+/g, "_").toUpperCase())
      : parsed.affected;

    const playbook =
      meta["Playbook"] ||
      meta["Related Playbook"] ||
      meta["Playbooks"] ||
      meta["Related Playbooks"] ||
      null;

    const technique = {
      // Keep IDs available, but DO NOT show CR-IDs as the tile name
      techniqueID: entry.techniqueID || "",
      tacticId: entry.tactic || "unmapped",
      tacticName: tacticName || tacticTitle(entry.tactic || "unmapped"),

      name, // THIS is what the tile title uses (human readable)

      score: typeof entry.score === "number" ? entry.score : null,
      color: entry.color || null,

      // Attack-first content (may be sparse until you enrich the layer)
      attack: {
        overview: meta["Attack Overview"] || meta["Attack Focus"] || meta["NG911 Note"] || entry.comment || "",
        mechanics: meta["How it works"] || meta["How the Attack Works"] || meta["Attack Mechanics"] || "",
        impact: meta["Operational impact"] || meta["Operational Impact"] || "",
        affected: affected,
        sources:
          meta["Sources"] ||
          meta["Source extracts"] ||
          meta["Source Extracts"] ||
          ""
      },

      playbook: playbook
    };

    // Tile sub-line
    technique.displayMeta = [
      technique.techniqueID ? technique.techniqueID : null,
      technique.score != null ? "Score " + technique.score : null
    ]
      .filter(Boolean)
      .join(" • ");

    return technique;
  }

  function groupByTacticFromLayer(layerTechniques) {
    const buckets = new Map();

    (layerTechniques || []).forEach((entry) => {
      const tid = entry.tactic || "unmapped";
      if (!buckets.has(tid)) {
        buckets.set(tid, { id: tid, name: tacticTitle(tid), techniques: [] });
      }
      buckets.get(tid).techniques.push(normalizeTechniqueFromLayer(entry, tacticTitle(tid)));
    });

    const ordered = Array.from(buckets.values()).sort((a, b) => {
      const ai = tacticOrder.indexOf(a.id);
      const bi = tacticOrder.indexOf(b.id);
      if (ai === -1 && bi === -1) return a.name.localeCompare(b.name);
      if (ai === -1) return 1;
      if (bi === -1) return -1;
      return ai - bi;
    });

    // Sort techniques (score desc, then name)
    ordered.forEach((bucket) => {
      bucket.techniques.sort((x, y) => {
        if (x.score != null && y.score != null && x.score !== y.score) return y.score - x.score;
        return (x.name || "").localeCompare(y.name || "");
      });
    });

    return { tactics: ordered };
  }

  function createCell(tech) {
    const c = document.createElement("div");
    c.className = "cell";

    if (tech.color) {
      c.style.borderColor = tech.color;
      c.style.boxShadow = "inset 0 0 0 1px " + tech.color + "55";
    }

    c.innerHTML =
      '<div class="title">' +
      esc(tech.name) +
      '</div><div class="meta">' +
      esc(tech.displayMeta || "") +
      "</div>";

    return c;
  }

  function createColumn(tactic) {
    const col = document.createElement("div");
    col.className = "column";

    const head = document.createElement("div");
    head.className = "col-head";
    head.textContent = tactic.name;
    col.appendChild(head);

    const grid = document.createElement("div");
    grid.className = "cell-grid";

    (tactic.techniques || []).forEach((tech) => {
      const c = createCell(tech);

      c.onclick = function () {
        // Modal title/subtitle
        document.getElementById("modal-title").textContent = tech.name;
        document.getElementById("modal-sub").textContent = "Tactic: " + tactic.name;

        // Right rail: IDs/score/note etc. (use the IDs that actually exist in your HTML)
        const idEl = document.getElementById("id");
        if (idEl) idEl.textContent = tech.techniqueID || "—";

        const scoreEl = document.getElementById("score");
        if (scoreEl) scoreEl.textContent = tech.score != null ? String(tech.score) : "—";

        const noteEl = document.getElementById("ng911-note");
        if (noteEl) noteEl.textContent = tech.attack.overview || "";

        // We are intentionally not showing mitigations here (playbooks later)
        const mitig = document.getElementById("mitigations");
        if (mitig) {
          mitig.innerHTML = "";
          const span = document.createElement("span");
          span.className = "tag muted";
          span.textContent = "Response actions are in the playbook (linked above).";
          mitig.appendChild(span);
        }

        // Affected tags
        const aff = document.getElementById("affected");
        if (aff) {
          aff.innerHTML = "";
          (tech.attack.affected || []).forEach((a) => {
            const s = document.createElement("span");
            s.className = "tag";
            s.textContent = a;
            aff.appendChild(s);
          });
          if (!aff.childElementCount) {
            const span = document.createElement("span");
            span.className = "tag muted";
            span.textContent = "No elements listed";
            aff.appendChild(span);
          }
        }

        // Evidence area
        const evidenceEl = document.getElementById("evidence");
        if (evidenceEl) evidenceEl.textContent = tech.attack.sources || "(none)";

        // Main content (attack-first)
        const parts = [];

        if (tech.attack.overview) parts.push("## Attack Overview\n" + tech.attack.overview);
        if (tech.attack.mechanics) parts.push("## How the Attack Works\n" + tech.attack.mechanics);
        if (tech.attack.impact) parts.push("## Operational Impact\n" + tech.attack.impact);

        // Even if we only have NG911 Note today, this still renders nicely.
        if (!parts.length) parts.push("## Attack Overview\n" + (tech.name || tech.techniqueID));

        const html = renderMarkdown(parts.join("\n\n"));
        const content = document.getElementById("modal-content");
        content.innerHTML = html;
        highlightCode();

        // Playbook buttons (link only)
        setPlaybookButtons(tech.playbook, tech.name || tech.techniqueID);

        // Show modal
        const bd = document.getElementById("backdrop");
        bd.style.display = "flex";
        bd.setAttribute("aria-hidden", "false");

        // Print the attack info
        document.getElementById("btn-print").onclick = function () {
          const safeHTML = html.replace(/<\/script/gi, "<\\/script");
          const head =
            '<html><head><meta charset="utf-8"><title>' +
            esc(tech.name) +
            '</title>' +
            '<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/styles/github-dark.min.css">' +
            "<style>body{font-family:Inter,system-ui,Arial;padding:24px;background:#fff;color:#111}" +
            "h1,h2,h3{margin:12px 0 6px}pre{border:1px solid #ddd;padding:12px;border-radius:8px;overflow:auto;background:#0a1f33;color:#e6eef8}" +
            ".meta{margin:8px 0 16px;color:#444;font-size:12px}</style></head><body>";

          const body =
            "<h1>" +
            esc(tech.name) +
            "</h1>" +
            '<div class="meta">Tactic: ' +
            esc(tactic.name) +
            "</div>" +
            safeHTML +
            '<script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/highlight.min.js"><\\/script>' +
            "<script>try{hljs.highlightAll()}catch(e){}<\\/script>" +
            "</body></html>";

          const w = window.open("", "_blank");
          w.document.open();
          w.document.write(head + body);
          w.document.close();
          setTimeout(function () {
            w.print();
          }, 300);
        };
      };

      grid.appendChild(c);
    });

    col.appendChild(grid);
    return col;
  }

  async function loadJSON(path) {
    try {
      const r = await fetch(path, { cache: "no-store" });
      if (r.ok) return await r.json();
    } catch (e) {}
    return null;
  }

  async function load() {
    // Layer is authoritative for UI
    const layer = await loadJSON("ng911_attck_layer.json");

    if (!layer || !Array.isArray(layer.techniques)) {
      console.error("[CyRECS911] ng911_attck_layer.json missing or invalid. Cannot render attack-first matrix.");
      const matrix = document.getElementById("matrix");
      matrix.innerHTML =
        '<div style="padding:16px;color:#9fb0c9">Error: ng911_attck_layer.json not found or invalid.</div>';
      return;
    }

    const mapping = groupByTacticFromLayer(layer.techniques);

    const matrix = document.getElementById("matrix");
    matrix.innerHTML = "";
    (mapping.tactics || []).forEach((t) => matrix.appendChild(createColumn(t)));

    // Search
    const q = document.getElementById("q");
    q.oninput = function () {
      const qv = q.value.trim().toLowerCase();
      const filtered = (mapping.tactics || [])
        .map((t) => {
          const techs = (t.techniques || []).filter((tc) => {
            const hay = [
              tc.name,
              tc.techniqueID,
              tc.tacticName,
              tc.attack && tc.attack.overview,
              tc.attack && tc.attack.mechanics,
              tc.attack && tc.attack.impact,
              (tc.attack && tc.attack.affected && tc.attack.affected.join(" ")) || ""
            ]
              .filter(Boolean)
              .join(" ")
              .toLowerCase();
            return hay.includes(qv);
          });
          return { id: t.id, name: t.name, techniques: techs };
        })
        .filter((t) => t.techniques.length > 0);

      matrix.innerHTML = "";
      filtered.forEach((t) => matrix.appendChild(createColumn(t)));
    };

    // Close modal
    document.getElementById("closeBtn").onclick = function () {
      const bd = document.getElementById("backdrop");
      bd.style.display = "none";
      bd.setAttribute("aria-hidden", "true");
    };

    document.getElementById("backdrop").onclick = function (e) {
      if (e.target && e.target.id === "backdrop") {
        const bd = document.getElementById("backdrop");
        bd.style.display = "none";
        bd.setAttribute("aria-hidden", "true");
      }
    };
  }

  load();
})();
