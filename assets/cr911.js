/* CyRECS911 Matrix — attack-first + playbook links (no legacy merge)
   - Removes score from UI (tiles + modal)
   - Keeps color styling
   - Builds Playbooks index from ng911_attck_layer.json (names, not IDs)
*/
(function () {
  console.log("[CyRECS911] assets/cr911.js loaded v4");

  const esc = (s) =>
    String(s || "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;");

  const inPlaybooksFolder = () => window.location.pathname.includes("/playbooks/");
  const layerPath = () => (inPlaybooksFolder() ? "../ng911_attck_layer.json" : "ng911_attck_layer.json");
  const playbooksBase = () => (inPlaybooksFolder() ? "" : "playbooks/");

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

  function playbookIdFromMetaValue(v) {
    let s = String(v || "").trim();
    if (!s) return null;
    s = s.replace(/^playbooks\//, "");
    s = s.replace(/\.md$/i, "");
    return s || null;
  }

  function playbookMdPath(pbId) {
    if (!pbId) return null;
    return playbooksBase() + pbId + ".md";
  }

  function playbookViewUrl(pbId) {
    if (!pbId) return null;
    // from root -> playbooks/view.html
    // from /playbooks -> view.html
    return playbooksBase() + "view.html?pb=" + encodeURIComponent(pbId);
  }

  function normalizeTechniqueFromLayer(entry) {
    const meta = metaToObject(entry.metadata || []);
    const cyid = meta["CyRECS ID"] || "";
    const name = meta["Display Name"] || entry.comment || entry.techniqueID || "Unnamed technique";
    const pbId = playbookIdFromMetaValue(meta["Playbook"] || "");

    const technique = {
      cyrecsId: cyid || null,
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

    // ✅ Removed score entirely from tile sub-line
    technique.displayMeta = [
      technique.cyrecsId ? technique.cyrecsId : null,
      technique.techniqueID ? technique.techniqueID : null
    ]
      .filter(Boolean)
      .join(" • ");

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

    // Sort techniques alphabetically (stable + clean)
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

    // ✅ keep colors
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

        // Right rail: Technique ID
        const idEl = document.getElementById("id");
        if (idEl) idEl.textContent = tech.cyrecsId || tech.techniqueID || "—";

        // ✅ Hide the “Navigator score” block (and never set it)
        const scoreEl = document.getElementById("score");
        if (scoreEl && scoreEl.closest(".meta-block")) {
          scoreEl.closest(".meta-block").style.display = "none";
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

        // Main content (attack-first)
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

        const printBtn = document.getElementById("btn-print");
        if (printBtn) {
          printBtn.onclick = function () {
            const safeHTML = html.replace(/<\/script/gi, "<\\/script");
            const headHtml =
              `<html><head><meta charset="utf-8"><title>${esc(tech.name)}</title>` +
              `<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/styles/github-dark.min.css">` +
              `<style>body{font-family:Inter,system-ui,Arial;padding:24px;background:#fff;color:#111}` +
              `h1,h2,h3{margin:12px 0 6px}pre{border:1px solid #ddd;padding:12px;border-radius:8px;overflow:auto;background:#0a1f33;color:#e6eef8}` +
              `.meta{margin:8px 0 16px;color:#444;font-size:12px}</style></head><body>`;

            const bodyHtml =
              `<h1>${esc(tech.name)}</h1>` +
              `<div class="meta">Tactic: ${esc(tactic.name)}</div>` +
              safeHTML +
              `<script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/highlight.min.js"><\\/script>` +
              `<script>try{hljs.highlightAll()}catch(e){}<\\/script>` +
              `</body></html>`;

            const w = window.open("", "_blank");
            w.document.open();
            w.document.write(headHtml + bodyHtml);
            w.document.close();
            setTimeout(() => w.print(), 300);
          };
        }
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

        // ✅ show NAME, not CR-ID
        const label = tech.name;

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
            `<span class="pb-meta">${esc(meta)}</span>`;
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
      const pb = document.getElementById("pb-index");
      if (pb) pb.innerHTML = '<div class="muted">Error loading layer data.</div>';
      return;
    }

    const mapping = groupByTactic(layer.techniques);

    const matrix = document.getElementById("matrix");
    if (matrix) {
      matrix.innerHTML = "";
      (mapping.tactics || []).forEach((t) => matrix.appendChild(createColumn(t)));
    }

    // Playbooks page auto-index
    buildPlaybooksIndex(mapping);

    // Search (matrix page)
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
