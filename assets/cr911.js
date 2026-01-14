/* CR911 Threat Matrix logic (attack-first; playbook is a secondary link) */
(function () {
  const esc = s =>
    String(s || "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;");

  // Order used for columns (keep stable ordering)
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
    "impact"
  ];

  const tacticTitleCache = Object.create(null);
  const tacticLabelOverrides = {
    impact: "Impact / Availability",
    collection: "Collection / Monitoring",
    "defense-evasion": "Defense Evasion",
    "privilege-escalation": "Privilege Escalation",
    "initial-access": "Initial Access",
    persistence: "Persistence",
    execution: "Execution",
    exfiltration: "Exfiltration",
    "command-and-control": "Command & Control"
  };

  function tacticTitle(id) {
    if (!id) return "Unmapped";
    if (tacticTitleCache[id]) return tacticTitleCache[id];
    const cached = tacticLabelOverrides[id];
    if (cached) {
      tacticTitleCache[id] = cached;
      return cached;
    }
    const titled = id
      .split("-")
      .map(part => part.charAt(0).toUpperCase() + part.slice(1))
      .join(" ");
    tacticTitleCache[id] = titled;
    return titled;
  }

  // Convert layer metadata array -> object map
  function metaToObject(metadataArr) {
    const o = Object.create(null);
    (metadataArr || []).forEach(m => {
      if (!m || !m.name) return;
      o[m.name] = m.value;
    });
    return o;
  }

  function splitElements(text) {
    const raw = String(text || "").trim();
    if (!raw) return [];
    return raw
      .split(/[,;]+/)
      .map(s => s.trim())
      .filter(Boolean);
  }

  // Build a technique object from ng911_attck_layer.json entry (attack-first)
  function normalizeTechniqueFromLayer(entry, tacticName) {
    const meta = metaToObject(entry.metadata || []);
    const cyrecsId = meta["CyRECS ID"] || meta["CyRECS IDs"] || meta["CyRECS Technique"] || meta["CyRECS Techniques"] || "";

    const displayName =
      meta["Display Name"] ||
      meta["Technique Name"] ||
      entry.comment ||
      entry.techniqueID;

    const affectedText =
      meta["Affected elements"] ||
      meta["Affected Elements"] ||
      meta["Targets"] ||
      "";

    const sourcesText =
      meta["Sources"] ||
      meta["Source"] ||
      "";

    const extractsText =
      meta["Source extracts"] ||
      meta["Source Extracts"] ||
      "";

    const playbook =
      meta["Playbook"] ||
      meta["Related Playbook"] ||
      meta["Playbooks"] ||
      meta["Related Playbooks"] ||
      null;

    const attackOverview =
      meta["Attack Overview"] ||
      meta["Attack Focus"] ||
      "";

    const howItWorks =
      meta["How it works"] ||
      meta["How the Attack Works"] ||
      meta["Attack Mechanics"] ||
      "";

    const operationalImpact =
      meta["Operational impact"] ||
      meta["Operational Impact"] ||
      "";

    // This is the attack-centric “evidence” (not mitigations)
    const evidence =
      [sourcesText, extractsText].filter(Boolean).join("\n\n") ||
      "";

    const affected = splitElements(affectedText);

    const technique = {
      id: cyrecsId || entry.techniqueID,              // what we show as the primary ID in UI if needed
      cyrecsId: cyrecsId || null,
      mitreId: entry.techniqueID || null,             // kept for reference/search
      name: displayName,                              // tile title MUST be the human name
      tacticId: entry.tactic || "unmapped",
      tacticName: tacticName || tacticTitle(entry.tactic || "unmapped"),
      score: typeof entry.score === "number" ? entry.score : null,
      color: entry.color || null,
      playbook: playbook,

      // Attack-first content (rendered into the modal)
      attack: {
        overview: attackOverview,
        mechanics: howItWorks,
        affectedText: affectedText,
        affected: affected,
        impact: operationalImpact,
        evidence: evidence
      }
    };

    // Tile meta line: keep concise and readable
    technique.displayMeta = [
      technique.cyrecsId ? technique.cyrecsId : null,
      technique.mitreId ? technique.mitreId : null,
      technique.score != null ? "Score " + technique.score : null
    ]
      .filter(Boolean)
      .join(" • ");

    return technique;
  }

  // If ng911_attck_layer.json is missing, we can still render legacy mapping.json minimally
  function normalizeTechniqueFromLegacy(tech, tactic) {
    const affected = Array.isArray(tech.affected) ? tech.affected : [];
    const technique = {
      id: tech.id || "",
      cyrecsId: null,
      mitreId: null,
      name: tech.name || tech.id || "",
      tacticId: tactic.id || "unmapped",
      tacticName: tactic.name || tacticTitle(tactic.id || "unmapped"),
      score: null,
      color: null,
      playbook: tech.id ? ("playbooks/" + tech.id + ".md") : null,
      attack: {
        overview: tech.description || "",
        mechanics: "",
        affectedText: affected.join(", "),
        affected: affected,
        impact: "",
        evidence: tech.evidence || ""
      }
    };

    technique.displayMeta = [
      technique.id ? technique.id : null,
      affected.length ? affected.join(", ") : null
    ]
      .filter(Boolean)
      .join(" • ");

    return technique;
  }

  function groupByTacticFromLayer(layerTechniques) {
    const buckets = new Map();

    (layerTechniques || []).forEach(entry => {
      const tid = entry.tactic || "unmapped";
      if (!buckets.has(tid)) {
        buckets.set(tid, {
          id: tid,
          name: tacticTitle(tid),
          techniques: []
        });
      }
      const bucket = buckets.get(tid);
      bucket.techniques.push(
        normalizeTechniqueFromLayer(entry, bucket.name)
      );
    });

    // Sort tactics
    const ordered = Array.from(buckets.values()).sort((a, b) => {
      const ai = tacticOrder.indexOf(a.id);
      const bi = tacticOrder.indexOf(b.id);
      if (ai === -1 && bi === -1) return a.name.localeCompare(b.name);
      if (ai === -1) return 1;
      if (bi === -1) return -1;
      return ai - bi;
    });

    // Sort techniques within each tactic (score desc, then name)
    ordered.forEach(bucket => {
      bucket.techniques.sort((a, b) => {
        if (a.score != null && b.score != null && a.score !== b.score) {
          return b.score - a.score;
        }
        return (a.name || "").localeCompare(b.name || "");
      });
    });

    return { tactics: ordered };
  }

  function groupByTacticFromLegacyMapping(legacy) {
    const tactics = (legacy && legacy.tactics) ? legacy.tactics : [];
    const normalized = tactics.map(t => {
      const bucket = {
        id: t.id || "unmapped",
        name: t.name || tacticTitle(t.id || "unmapped"),
        techniques: []
      };
      (t.techniques || []).forEach(tech => {
        bucket.techniques.push(normalizeTechniqueFromLegacy(tech, bucket));
      });
      bucket.techniques.sort((a, b) => (a.name || "").localeCompare(b.name || ""));
      return bucket;
    });

    // Try to keep consistent ordering if tactic ids resemble common ones
    normalized.sort((a, b) => {
      const ai = tacticOrder.indexOf(a.id);
      const bi = tacticOrder.indexOf(b.id);
      if (ai === -1 && bi === -1) return a.name.localeCompare(b.name);
      if (ai === -1) return 1;
      if (bi === -1) return -1;
      return ai - bi;
    });

    return { tactics: normalized };
  }

  function renderMarkdown(md) {
    marked.setOptions({ mangle: false, headerIds: true, breaks: false });
    const html = marked.parse(md || "");
    return DOMPurify.sanitize(html);
  }

  function highlightCode() {
    try { hljs.highlightAll(); } catch (e) {}
  }

  // Optional: fetch the playbook markdown only when the user explicitly wants it later.
  // For now, we only provide a link/button to open it.
  function setPlaybookButtons(playbookPath, fallbackId) {
    const openRaw = document.getElementById("btn-open-raw");
    const download = document.getElementById("btn-download");

    if (!openRaw || !download) return;

    if (!playbookPath) {
      openRaw.style.display = "none";
      download.style.display = "none";
      return;
    }

    const href = playbookPath.startsWith("playbooks/") ? playbookPath : ("playbooks/" + playbookPath.replace(/^\/+/, ""));
    openRaw.href = href;
    openRaw.style.display = "inline-flex";

    download.href = href;
    download.style.display = "inline-flex";
    download.setAttribute("download", (fallbackId || "playbook") + ".md");
  }

  function createCell(tech) {
    const c = document.createElement("div");
    c.className = "cell";

    if (tech.color) {
      c.style.borderColor = tech.color;
      c.style.boxShadow = "inset 0 0 0 1px " + tech.color + "55";
    }

    const meta = tech.displayMeta || "";
    c.innerHTML =
      '<div class="title">' + esc(tech.name) + "</div>" +
      '<div class="meta">' + esc(meta) + "</div>";

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

    (tactic.techniques || []).forEach(tech => {
      const c = createCell(tech);

      c.onclick = function () {
        // Title/subtitle
        const title = tech.name;
        document.getElementById("modal-title").textContent = title;
        document.getElementById("modal-sub").textContent = "Tactic: " + tactic.name;

        // Right rail meta (keep useful attack-side info)
        const mitre = document.getElementById("mitre-id");
        if (mitre) mitre.textContent = tech.mitreId || "—";

        const scoreEl = document.getElementById("mitre-score");
        if (scoreEl) scoreEl.textContent = (tech.score != null ? String(tech.score) : "—");

        const noteEl = document.getElementById("ng911-note");
        if (noteEl) noteEl.textContent = tech.attack.overview || "";

        // We are not showing mitigations in the attack view (playbooks later)
        const mitig = document.getElementById("mitigations");
        if (mitig) {
          mitig.innerHTML = "";
          const span = document.createElement("span");
          span.className = "tag muted";
          span.textContent = "Response guidance is in the playbook";
          mitig.appendChild(span);
        }

        // Affected elements (attack-side metadata)
        const aff = document.getElementById("affected");
        if (aff) {
          aff.innerHTML = "";
          (tech.attack.affected || []).forEach(a => {
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

        const evidenceEl = document.getElementById("evidence");
        if (evidenceEl) evidenceEl.textContent = tech.attack.evidence || "(none)";

        // Build attack-first modal content (Markdown)
        const sections = [];

        if (tech.cyrecsId) {
          sections.push("**Technique ID:** " + esc(tech.cyrecsId));
        } else if (tech.id && !tech.mitreId) {
          sections.push("**Technique ID:** " + esc(tech.id));
        }

        if (tech.attack.overview) {
          sections.push("## Attack Overview\n" + tech.attack.overview);
        }
        if (tech.attack.mechanics) {
          sections.push("## How the Attack Works\n" + tech.attack.mechanics);
        }
        if (tech.attack.affectedText) {
          sections.push("## Affected NG911 Elements\n" + tech.attack.affectedText);
        }
        if (tech.attack.impact) {
          sections.push("## Operational Impact\n" + tech.attack.impact);
        }
        if (tech.attack.evidence) {
          sections.push("## Sources / Evidence\n" + tech.attack.evidence);
        }

        const md = sections.join("\n\n");
        const html = renderMarkdown(md);
        const content = document.getElementById("modal-content");
        content.innerHTML = html;
        highlightCode();

        // Playbook buttons (link only; we are not rendering playbook content yet)
        setPlaybookButtons(tech.playbook, tech.cyrecsId || tech.id || tech.mitreId || "playbook");

        // Show modal
        const bd = document.getElementById("backdrop");
        bd.style.display = "flex";
        bd.setAttribute("aria-hidden", "false");

        // Print attack page
        document.getElementById("btn-print").onclick = function () {
          var safeHTML = html.replace(/<\/script/gi, "<\\/script");
          var head =
            "<html><head><meta charset=\"utf-8\"><title>" +
            esc(title) +
            "</title>" +
            "<link rel=\"stylesheet\" href=\"https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/styles/github-dark.min.css\">" +
            "<style>body{font-family:Inter,system-ui,Arial;padding:24px;background:#fff;color:#111}" +
            "h1,h2,h3{margin:12px 0 6px}pre{border:1px solid #ddd;padding:12px;border-radius:8px;overflow:auto;background:#0a1f33;color:#e6eef8}" +
            ".meta{margin:8px 0 16px;color:#444;font-size:12px}</style></head><body>";

          var body =
            "<h1>" + esc(title) + "</h1>" +
            "<div class=\"meta\">Tactic: " + esc(tactic.name) + "</div>" +
            safeHTML +
            "<script src=\"https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/highlight.min.js\"><\\/script>" +
            "<script>try{hljs.highlightAll()}catch(e){}<\\/script>" +
            "</body></html>";

          var w = window.open("", "_blank");
          w.document.open();
          w.document.write(head + body);
          w.document.close();
          setTimeout(function () { w.print(); }, 300);
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
    // Prefer the layer as the authoritative attack presentation source
    const layer = await loadJSON("ng911_attck_layer.json");

    let mapping;
    if (layer && Array.isArray(layer.techniques)) {
      mapping = groupByTacticFromLayer(layer.techniques);
    } else {
      // Minimal fallback (legacy mapping.json)
      const legacy = await loadJSON("mapping.json");
      mapping = groupByTacticFromLegacyMapping(legacy || { tactics: [] });
    }

    const matrix = document.getElementById("matrix");
    matrix.innerHTML = "";
    (mapping.tactics || []).forEach(t => matrix.appendChild(createColumn(t)));

    // Search across attack-first fields
    const q = document.getElementById("q");
    q.oninput = function () {
      const qv = q.value.trim().toLowerCase();

      const filtered = (mapping.tactics || [])
        .map(t => {
          const techs = (t.techniques || []).filter(tc => {
            const hay = [
              tc.name,
              tc.id,
              tc.cyrecsId,
              tc.mitreId,
              tc.tacticName,
              tc.attack && tc.attack.overview,
              tc.attack && tc.attack.mechanics,
              tc.attack && tc.attack.impact,
              tc.attack && tc.attack.affectedText,
              (tc.attack && tc.attack.affected && tc.attack.affected.join(" ")) || "",
              tc.attack && tc.attack.evidence
            ]
              .filter(Boolean)
              .join(" ")
              .toLowerCase();
            return hay.includes(qv);
          });
          return { id: t.id, name: t.name, techniques: techs };
        })
        .filter(t => t.techniques.length > 0);

      matrix.innerHTML = "";
      filtered.forEach(t => matrix.appendChild(createColumn(t)));
    };

    // Close modal handlers
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
