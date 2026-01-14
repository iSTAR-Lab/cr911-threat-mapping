/* CyRECS911 Matrix — attack-first + playbook links (no legacy merge)
   FIX: Playbook links resolve to actual /playbooks/*.md filenames (not CR-IDs)
   UI: No score displayed; colors retained
*/
(function () {
  console.log("[CyRECS911] assets/cr911.js loaded v5");

  const esc = (s) =>
    String(s || "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;");

  const inPlaybooksFolder = () => window.location.pathname.includes("/playbooks/");
  const layerPath = () => (inPlaybooksFolder() ? "../ng911_attck_layer.json" : "ng911_attck_layer.json");
  const playbooksBase = () => (inPlaybooksFolder() ? "" : "playbooks/");

  // ✅ IMPORTANT: map CyRECS IDs -> repo playbook filenames (without .md)
  // These must match your /playbooks/*.md filenames exactly.
  const playbookIdByCyrecs = {
    "CR-IA-01": "phishing_workstation",
    "CR-IA-02": "supply_chain_component",
    "CR-IA-03": "legacy_protocol_injection",

    "CR-ID-01": "caller_id_spoof",
    "CR-ID-02": "lis_impersonation",

    "CR-PA-01": "protocol_downgrade",
    "CR-PA-02": "rtp_injection",

    "CR-CO-01": "data_exfil_lis",

    "CR-DM-01": "lvf_gis_poison",
    "CR-DM-02": "lis_data_tamper",

    "CR-SD-01": "tdos_sip_flood",
    "CR-SD-03": "lpg_isolation",

    "CR-IM-01": "ransomware_psap",

    "CR-VE-01": "sw_bugs_esrp",
    "CR-MC-01": "misconfig_admin",

    // You have this playbook file too; hook it up when you add a technique for it:
    // "CR-??-??": "lis_query_flood"
  };

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

  function splitTags(text) {
    const raw = String(text || "").trim();
    if (!raw) return [];
    return raw
      .split(/[;,]+/)
      .map((s) => s.trim())
      .filter(Boolean)
      .map((s) => s.replace(/\s+/g, "_").toUpperCase());
  }

  function renderMarkdown(md) {
    marked.setOptions({ mangle: false, headerIds: true, breaks: false });
    const html = marked.parse(md || "");
    return DOMPurify.sanitize(html);
  }

  function highlightCode() {
    try { hljs.highlightAll(); } catch (e) {}
  }

  function normalizePlaybookId(v) {
    // Accept: "file.md" or "playbooks/file.md" or "file"
    let s = String(v || "").trim();
    if (!s) return null;
    s = s.replace(/^playbooks\//, "");
    s = s.replace(/\.md$/i, "");
    return s || null;
  }

  function resolvePlaybookId(meta, cyrecsId) {
    // 1) If ng911_attck_layer.json has a direct filename, use it
    const direct = normalizePlaybookId(meta["Playbook"] || meta["Playbooks"] || "");
    if (direct && direct !== cyrecsId) return direct;

    // 2) Otherwise map from CyRECS ID -> repo filename
    if (cyrecsId && playbookIdByCyrecs[cyrecsId]) return playbookIdByCyrecs[cyrecsId];

    // 3) Nothing found
    return null;
  }

  function playbookMdPath(pbId) {
    if (!pbId) return null;
    return playbooksBase() + pbId + ".md";
  }

  function playbookViewUrl(pbId) {
    if (!pbId) return null;
    return playbooksBase() + "view.html?id=" + encodeURIComponent(pbId);
  }

  function normalizeTechniqueFromLayer(entry) {
    const meta = metaToObject(entry.metadata || []);

    const cyrecsId = meta["CyRECS ID"] || meta["CyRECS IDs"] || "";
    const name = meta["Display Name"] || entry.comment || entry.techniqueID || "Unnamed technique";

    // ✅ resolved to actual playbook filename like "legacy_protocol_injection"
    const pbId = resolvePlaybookId(meta, cyrecsId);

    const technique = {
      cyrecsId: cyrecsId || null,
      techniqueID: entry.techniqueID || null,
      tacticId: entry.tactic || "unmapped",
      tacticName: tacticTitle(entry.tactic || "unmapped"),
      name,
      color: entry.color || null,

      playbookId: pbId,
      playbookView: pbId ? playbookViewUrl(pbId) : null,
      playbookMd: pbId ? playbookMdPath(pbId) : null,

      attack: {
        overview: meta["Attack Overview"] || "",
        mechanics: meta["How it works"] || "",
        impact: meta["Operational impact"] || "",
        affected: splitTags(meta["Affected elements"] || ""),
        sources: meta["Sources"] || ""
      }
    };

    // ✅ no score
    technique.displayMeta = [technique.cyrecsId, technique.techniqueID].filter(Boolean).join(" • ");
    return technique;
  }

  function groupByTactic(layerTechniques) {
    const buckets = new Map();

    (layerTechniques || []).forEach((entry) => {
      const tid = entry.tactic || "unmapped";
      if (!buckets.has(tid)) {
        buckets.set(tid, { id: tid, name: tacticTitle(tid), techniques: [] });
      }
      buckets.get(tid).techniques.push(normalizeTechniqueFromLayer(entry));
    });

    const ordered = Array.from(buckets.values()).sort((a, b) => {
      const ai = tacticOrder.indexOf(a.id);
      const bi = tacticOrder.indexOf(b.id);
      if (ai === -1 && bi === -1) return a.name.localeCompare(b.name);
      if (ai === -1) return 1;
      if (bi === -1) return -1;
      return ai - bi;
    });

    ordered.forEach((bucket) => {
      bucket.techniques.sort((x, y) => (x.name || "").localeCompare(y.name || ""));
    });

    return { tactics: ordered };
  }

  function setPlaybookButtons(tech) {
    const openRaw = document.getElementById("btn-open-raw");
    const download = document.getElementById("btn-download");
    if (!openRaw || !download) return;

    if (!tech.playbookId) {
      openRaw.style.display = "none";
      download.style.display = "none";
      return;
    }

    // Keep label consistent with your view.html UI
    openRaw.textContent = "Open Playbook";
    openRaw.href = tech.playbookView;
    openRaw.style.display = "inline-flex";

    download.href = tech.playbookMd;
    download.style.display = "inline-flex";
    download.setAttribute("download", tech.playbookId + ".md");
  }

  function createCell(tech) {
    const c = document.createElement("div");
    c.className = "cell";

    // Keep colors
    if (tech.color) {
      c.style.borderColor = tech.color;
      c.style.boxShadow = "inset 0 0 0 1px " + tech.color + "55";
    }

    const pbLink = tech.playbookView
      ? `<a class="pb-link" href="${esc(tech.playbookView)}" target="_blank" rel="noopener">Playbook →</a>`
      : `<span class="pb-link muted">No playbook</span>`;

    c.innerHTML =
      `<div class="title">${esc(tech.name)}</div>` +
      `<div class="meta">${esc(tech.displayMeta || "")}</div>` +
      `<div style="margin-top:8px;font-size:12px">${pbLink}</div>`;

    const a = c.querySelector("a.pb-link");
    if (a) a.addEventListener("click", (ev) => ev.stopPropagation());

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
      const cell = createCell(tech);

      cell.onclick = function () {
        document.getElementById("modal-title").textContent = tech.name;
        document.getElementById("modal-sub").textContent = "Tactic: " + tactic.name;

        const idEl = document.getElementById("id");
        if (idEl) idEl.textContent = tech.cyrecsId || tech.techniqueID || "—";

        // Hide score block if it exists in HTML
        const scoreEl = document.getElementById("score");
        if (scoreEl) {
          const block = scoreEl.closest(".meta-block");
          if (block) block.style.display = "none";
        }

        const noteEl = document.getElementById("ng911-note");
        if (noteEl) noteEl.textContent = tech.attack.overview || "";

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

        const evidenceEl = document.getElementById("evidence");
        if (evidenceEl) evidenceEl.textContent = tech.attack.sources || "(none)";

        const mitig = document.getElementById("mitigations");
        if (mitig) {
          mitig.innerHTML = "";
          const span = document.createElement("span");
          span.className = "tag muted";
          span.textContent = "Mitigation guidance is in the playbook.";
          mitig.appendChild(span);
        }

        const parts = [];
        parts.push(`**Technique:** ${esc(tech.name)}`);
        parts.push(`**Identifiers:** ${esc([tech.cyrecsId, tech.techniqueID].filter(Boolean).join(" • ") || "—")}`);

        if (tech.attack.overview) parts.push("## Attack Overview\n" + tech.attack.overview);
        if (tech.attack.mechanics) parts.push("## How the Attack Works\n" + tech.attack.mechanics);
        if (tech.attack.impact) parts.push("## Operational Impact\n" + tech.attack.impact);
        if (tech.attack.sources) parts.push("## Sources\n" + tech.attack.sources);

        const html = renderMarkdown(parts.join("\n\n"));
        const content = document.getElementById("modal-content");
        content.innerHTML = html;
        highlightCode();

        setPlaybookButtons(tech);

        const bd = document.getElementById("backdrop");
        bd.style.display = "flex";
        bd.setAttribute("aria-hidden", "false");
      };

      grid.appendChild(cell);
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

  // If playbooks/index.html has pb-index, this builds it
  function buildPlaybooksIndex(mapping) {
    const listRoot = document.getElementById("pb-index");
    if (!listRoot) return;

    listRoot.innerHTML = "";
    (mapping.tactics || []).forEach((t) => {
      const section = document.createElement("div");
      section.className = "pb-section";

      const h = document.createElement("div");
      h.className = "pb-title";
      h.textContent = t.name;
      section.appendChild(h);

      const ul = document.createElement("ul");
      ul.className = "pb-list";

      (t.techniques || []).forEach((tech) => {
        const li = document.createElement("li");
        li.className = "pb-item";

        const label = tech.name; // show names
        const meta = [tech.cyrecsId, tech.techniqueID].filter(Boolean).join(" • ");

        if (tech.playbookView) {
          li.innerHTML =
            `<a href="${esc(tech.playbookView)}" class="pb-a">` +
            `${esc(label)}` +
            `</a>` +
            `<span class="pb-meta">${esc(meta)}</span>`;
        } else {
          li.innerHTML =
            `<span class="pb-a muted">${esc(label)}</span>` +
            `<span class="pb-meta">${esc(meta)}</span>` +
            ` <span class="pb-meta muted">(no playbook)</span>`;
        }

        ul.appendChild(li);
      });

      section.appendChild(ul);
      listRoot.appendChild(section);
    });
  }

  async function load() {
    const layer = await loadJSON(layerPath());
    if (!layer || !Array.isArray(layer.techniques)) {
      console.error("[CyRECS911] layer missing/invalid:", layerPath());
      const matrix = document.getElementById("matrix");
      if (matrix) {
        matrix.innerHTML =
          '<div style="padding:16px;color:#9fb0c9">Error: ng911_attck_layer.json not found or invalid.</div>';
      }
      return;
    }

    const mapping = groupByTactic(layer.techniques);

    const matrix = document.getElementById("matrix");
    if (matrix) {
      matrix.innerHTML = "";
      (mapping.tactics || []).forEach((t) => matrix.appendChild(createColumn(t)));
    }

    buildPlaybooksIndex(mapping);

    // Search
    const q = document.getElementById("q");
    if (q && matrix) {
      q.oninput = function () {
        const qv = q.value.trim().toLowerCase();
        const filtered = (mapping.tactics || [])
          .map((t) => {
            const techs = (t.techniques || []).filter((tc) => {
              const hay = [
                tc.name,
                tc.cyrecsId,
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
    }

    // Modal close
    const closeBtn = document.getElementById("closeBtn");
    if (closeBtn) {
      closeBtn.onclick = function () {
        const bd = document.getElementById("backdrop");
        if (!bd) return;
        bd.style.display = "none";
        bd.setAttribute("aria-hidden", "true");
      };
    }

    const backdrop = document.getElementById("backdrop");
    if (backdrop) {
      backdrop.onclick = function (e) {
        if (e.target && e.target.id === "backdrop") {
          backdrop.style.display = "none";
          backdrop.setAttribute("aria-hidden", "true");
        }
      };
    }
  }

  load();
})();
