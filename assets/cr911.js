/* CR911 Threat Matrix logic (external; no inline backticks) */
(function () {
  const esc = s => String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  const tacticOrder = ['reconnaissance','resource-development','initial-access','execution','persistence','privilege-escalation','defense-evasion','credential-access','discovery','lateral-movement','collection','command-and-control','exfiltration','impact'];
  const tacticTitleCache = Object.create(null);
  const tacticLabelOverrides = {
    'impact': 'Impact / Availability',
    'collection': 'Collection / Monitoring',
    'defense-evasion': 'Defense Evasion',
    'privilege-escalation': 'Privilege Escalation',
    'initial-access': 'Initial Access',
    'persistence': 'Persistence',
    'execution': 'Execution',
    'exfiltration': 'Exfiltration',
    'command-and-control': 'Command & Control'
  };
  const normalize = str => (str||'').toLowerCase().replace(/[^a-z0-9]+/g,'');
  function collectLookupKeys(str){
    const keys = new Set();
    if(!str) return keys;
    const variants = new Set([str]);
    variants.add(str.replace(/[“”]/g,'"'));
    variants.add(str.replace(/\b(\w+?)s\b/gi,'$1'));
    variants.add(str.replace(/\b(\w+?)es\b/gi,'$1'));
    variants.add(str.replace(/\b(\w+?)ies\b/gi,'$1y'));
    variants.forEach(variant=>{
      const norm = normalize(variant);
      if(norm) keys.add(norm);
    });
    return keys;
  }

  function tacticTitle(id){
    if(!id) return 'Unmapped';
    if(tacticTitleCache[id]) return tacticTitleCache[id];
    const cached = tacticLabelOverrides[id];
    if(cached){ tacticTitleCache[id] = cached; return cached; }
    const titled = id.split('-').map(part=>part.charAt(0).toUpperCase()+part.slice(1)).join(' ');
    tacticTitleCache[id] = titled;
    return titled;
  }

  function parseNote(note){
    if(!note) return {name:'', affected:[]};
    const match = note.match(/\(([^)]+)\)\s*$/);
    const affected = match ? match[1].split(',').map(s=>s.trim()).filter(Boolean) : [];
    const name = match ? note.slice(0, match.index).trim() : note.trim();
    return {name, affected};
  }

  function buildLegacyLookup(mapping){
    const lookup = new Map();
    if(!mapping) return lookup;
    (mapping.tactics||[]).forEach(tactic => {
      (tactic.techniques||[]).forEach(tech => {
        const value = {tech, tactic};
        const keys = new Set();
        collectLookupKeys(tech.name).forEach(k=>keys.add(k));
        collectLookupKeys(tech.id).forEach(k=>keys.add(k));
        collectLookupKeys(tech.description).forEach(k=>keys.add(k));
        keys.forEach(k=>{ if(!lookup.has(k)) lookup.set(k, value); });
      });
    });
    return lookup;
  }

  function mergeLayer(layer, legacyMapping){
    const legacyLookup = buildLegacyLookup(legacyMapping);
    const tacticBuckets = new Map();
    const addBucket = tacticId => {
      if(!tacticBuckets.has(tacticId)){
        tacticBuckets.set(tacticId, {id:tacticId, name:tacticTitle(tacticId), techniques:[]});
      }
      return tacticBuckets.get(tacticId);
    };
    (layer.techniques||[]).forEach(entry => {
      const bucket = addBucket(entry.tactic || 'unmapped');
      const metaEntry = (entry.metadata||[]).find(m=>m.name==='NG911 Note') || (entry.metadata||[])[0];
      const note = metaEntry ? metaEntry.value : entry.comment || entry.techniqueID;
      const parsed = parseNote(note);
      let legacy = null;
      for(const key of collectLookupKeys(parsed.name)){ if(legacyLookup.has(key)){ legacy = legacyLookup.get(key); break; } }
      if(!legacy && entry.comment){
        for(const key of collectLookupKeys(entry.comment)){ if(legacyLookup.has(key)){ legacy = legacyLookup.get(key); break; } }
      }
      const legacyTech = legacy ? legacy.tech : null;
      const technique = {
        id: legacyTech ? legacyTech.id : entry.techniqueID,
        name: parsed.name || (legacyTech && legacyTech.name) || entry.techniqueID,
        description: (legacyTech && legacyTech.description) || entry.comment || note,
        affected: parsed.affected.length ? parsed.affected : ((legacyTech && legacyTech.affected) || []),
        mitigations: (legacyTech && legacyTech.mitigations) || [],
        evidence: (legacyTech && legacyTech.evidence) || '',
        mitreId: entry.techniqueID,
        ng911Note: note,
        score: typeof entry.score === 'number' ? entry.score : null,
        color: entry.color || null,
        tacticName: bucket.name,
        tacticId: bucket.id,
        hasLegacy: !!legacyTech
      };
      technique.playbookId = legacyTech ? legacyTech.id : entry.techniqueID;
      technique.legacyId = legacyTech ? legacyTech.id : null;
      technique.displayMeta = [
        technique.mitreId || null,
        (legacyTech && technique.mitreId !== technique.playbookId) ? ('Playbook ' + technique.playbookId) : null,
        technique.affected.join(', '),
        technique.score!=null ? 'Score ' + technique.score : null
      ]
        .filter(Boolean)
        .join(' • ');
      bucket.techniques.push(technique);
    });

    const ordered = Array.from(tacticBuckets.values()).sort((a,b)=>{
      const ai = tacticOrder.indexOf(a.id);
      const bi = tacticOrder.indexOf(b.id);
      if(ai === -1 && bi === -1) return a.name.localeCompare(b.name);
      if(ai === -1) return 1;
      if(bi === -1) return -1;
      return ai - bi;
    }).map(bucket => ({
      ...bucket,
      techniques: bucket.techniques.sort((a,b)=>{
        if(a.score!=null && b.score!=null && a.score!==b.score) return b.score - a.score;
        return a.name.localeCompare(b.name);
      })
    }));

    return {tactics: ordered};
  }

  function renderMarkdown(md){
    marked.setOptions({ mangle:false, headerIds:true, breaks:false });
    const html = marked.parse(md || '');
    return DOMPurify.sanitize(html);
  }
  function highlightCode(){ try{ hljs.highlightAll(); }catch(e){} }

  // Fallback playbook (used if no MD file is found)
  function buildPlaybookFromTech(tactic, tech){
    const lines = [];
    lines.push('# ' + esc(tech.name));
    if(tech.description) lines.push('\n' + esc(tech.description));
    if(tech.mitreId) lines.push('\n> MITRE ATT&CK mapping: **' + esc(tech.mitreId) + '** → ' + esc(tactic.name));
    if(tech.ng911Note && tech.ng911Note !== tech.description) lines.push('\n> NG911 context: ' + esc(tech.ng911Note));
    lines.push('\n## Detection & Telemetry');
  const id=(tech.playbookId||tech.id||''); let sig=[];
    if(['lis_impersonation','lis_data_tamper','data_exfil_lis'].includes(id))
      sig=['Certificate or signer mismatch for PIDF-LO/location tokens','Unusual LVF revalidations','Location-by-value vs by-reference mismatch','Spikes in LIS queries from atypical clients'];
    else if(['tdos_sip_flood','caller_id_spoof','lis_query_flood'].includes(id))
      sig=['SIP INVITE surges from few IPs','ESRP errors & PSAP queue spikes','BCF rate-limit counters firing','Invalid STIR/SHAKEN attestations'];
    else if(['lvf_gis_poison'].includes(id))
      sig=['LVF validation failures after updates','GIS hash/version drift','Unauthorized LVF/GIS writes'];
    else if(['legacy_protocol_injection','rtp_injection'].includes(id))
      sig=['LNG/LPG protocol conformance violations','RTP/SRTP negotiation anomalies','Unexpected SDP/codec attributes'];
    else if(['sw_bugs_esrp','protocol_downgrade'].includes(id))
      sig=['ESRP/ECRF/LIS crashes/restarts','TLS downgrades','IDS/WAF CVE hits'];
    else if(['phishing_workstation','ransomware_psap','misconfig_admin','supply_chain_component'].includes(id))
      sig=['Suspicious processes on PSAP hosts','EDR ransomware indicators','Privileged changes outside window','Unexpected vendor updates'];
    else
      sig=['Anomalous auth/config or request patterns','Error/latency/throughput anomalies'];
    lines.push(sig.map(s=>'- '+s).join('\n'));
    lines.push('\n## Triage\n- Scope affected elements and paths\n- Compare 24h vs 7d\n- Validate certs/IDs/rates/schema');
    lines.push('\n## Containment\n- Block/rate-limit at BCF\n- Quarantine & failover\n- Disable creds; rotate keys');
    lines.push('\n## Eradication\n- Patch/reconfigure\n- Rebuild if integrity uncertain\n- Restore validated LVF/GIS');
    lines.push('\n## Recovery\n- Reintroduce traffic under monitoring\n- Verify origination→BCF→ESRP→ECRF/LVF→PSAP\n- Post-incident review');
    lines.push('\n## Metrics/KPIs\n- MTTD, MTTC, MTTR\n- False positives\n- % endpoints with mTLS/STIR-SHAKEN');
    return lines.join('\n');
  }

  async function loadPlaybookMD(id){
    try{ const r=await fetch('playbooks/' + id + '.md', {cache:'no-store'}); if(r.ok) return await r.text(); }catch(e){}
    return null;
  }

  function createCell(tech){
    const c=document.createElement('div'); c.className='cell';
    if(tech.color){ c.style.borderColor = tech.color; c.style.boxShadow = 'inset 0 0 0 1px ' + tech.color + '55'; }
    const meta = tech.displayMeta || (tech.affected||[]).join(', ');
    c.innerHTML='<div class="title">'+esc(tech.name)+'</div><div class="meta">'+esc(meta)+'</div>';
    return c;
  }

  function createColumn(tactic){
    const col=document.createElement('div'); col.className='column';
    const head=document.createElement('div'); head.className='col-head'; head.textContent=tactic.name; col.appendChild(head);
    const grid=document.createElement('div'); grid.className='cell-grid';

    (tactic.techniques||[]).forEach(tech=>{
  const c=createCell(tech);
  c.onclick=async function(){
    const title = tech.name + ' (' + tech.mitreId + ')';
    document.getElementById('modal-title').textContent = title;
    document.getElementById('modal-sub').textContent   = 'Tactic: ' + tactic.name;

    const mitre=document.getElementById('mitre-id');
    if(mitre){ mitre.textContent = tech.mitreId || tech.id || '(unknown)'; }
    const scoreEl = document.getElementById('mitre-score');
    if(scoreEl){ scoreEl.textContent = tech.score!=null ? String(tech.score) : '—'; }
    const noteEl = document.getElementById('ng911-note');
    if(noteEl){ noteEl.textContent = tech.ng911Note || tech.description || ''; }

    // Right rail meta
    const mitig=document.getElementById('mitigations'); mitig.innerHTML='';
    (tech.mitigations||tech.mitigation||[]).forEach(m=>{ const s=document.createElement('span'); s.className='tag'; s.textContent=m; mitig.appendChild(s); });
    if(!mitig.childElementCount){ const span=document.createElement('span'); span.className='tag muted'; span.textContent='No mapped mitigations'; mitig.appendChild(span); }
    const aff=document.getElementById('affected'); aff.innerHTML='';
    (tech.affected||[]).forEach(a=>{ const s=document.createElement('span'); s.className='tag'; s.textContent=a; aff.appendChild(s); });
    if(!aff.childElementCount){ const span=document.createElement('span'); span.className='tag muted'; span.textContent='No elements extracted'; aff.appendChild(span); }
    document.getElementById('evidence').textContent = tech.evidence || '(none)';

    // Content
    let md = await loadPlaybookMD(tech.playbookId || tech.id);
    if(!md) md = buildPlaybookFromTech(tactic, tech);
    const html = renderMarkdown(md);
    const content = document.getElementById('modal-content');
    content.innerHTML = html; highlightCode();

    // Toolbar links
    const rawHref = 'playbooks/' + tech.playbookId + '.md';
    document.getElementById('btn-open-raw').href = rawHref;
    document.getElementById('btn-download').href = rawHref;
    document.getElementById('btn-download').setAttribute('download', tech.playbookId + '.md');

        // Show modal
        const bd=document.getElementById('backdrop'); bd.style.display='flex'; bd.setAttribute('aria-hidden','false');

        // Print (no backticks; escape </script>)
        document.getElementById('btn-print').onclick = function(){
          var safeHTML = html.replace(/<\/script/gi, '<\\/script');
          var head = ''
            + '<html><head><meta charset="utf-8"><title>' + esc(title) + '</title>'
            + '<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/styles/github-dark.min.css">'
            + '<style>body{font-family:Inter,system-ui,Arial;padding:24px;background:#fff;color:#111}'
            + 'h1,h2,h3{margin:12px 0 6px}pre{border:1px solid #ddd;padding:12px;border-radius:8px;overflow:auto;background:#0a1f33;color:#e6eef8}'
            + '.meta{margin:8px 0 16px;color:#444;font-size:12px}</style></head><body>';
          var body = ''
            + '<h1>' + esc(title) + '</h1>'
            + '<div class="meta">Tactic: ' + esc(tactic.name) + '</div>'
            + safeHTML
            + '<script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/highlight.min.js"><\\/script>'
            + '<script>try{hljs.highlightAll()}catch(e){}<\\/script>'
            + '</body></html>';
          var w = window.open('', '_blank'); w.document.open(); w.document.write(head + body); w.document.close();
          setTimeout(function(){ w.print(); }, 300);
        };
      };
      grid.appendChild(c);
    });
    col.appendChild(grid);
    return col;
  }

  async function load(){
    let legacy={tactics:[]};
    let layer=null;
    try{ const r=await fetch('mapping.json',{cache:'no-store'}); if(r.ok) legacy=await r.json(); }catch(e){}
    try{ const r=await fetch('ng911_attck_layer.json',{cache:'no-store'}); if(r.ok) layer=await r.json(); }catch(e){}

    const mapping = layer ? mergeLayer(layer, legacy) : legacy;
    const matrix=document.getElementById('matrix'); matrix.innerHTML='';
    (mapping.tactics||[]).forEach(t=>matrix.appendChild(createColumn(t)));

    const q=document.getElementById('q');
    q.oninput=function(){
      const qv=q.value.trim().toLowerCase();
      const filtered=(mapping.tactics||[]).map(t=>{
        const techs=(t.techniques||[]).filter(tc=>
          (tc.name||'').toLowerCase().includes(qv) ||
          (tc.id||'').toLowerCase().includes(qv) ||
          (tc.mitreId||'').toLowerCase().includes(qv) ||
          (tc.ng911Note||'').toLowerCase().includes(qv) ||
          (tc.affected||[]).join(' ').toLowerCase().includes(qv)
        );
        return {name:t.name, techniques:techs};
      }).filter(t=>t.techniques.length>0);
      matrix.innerHTML=''; filtered.forEach(t=>matrix.appendChild(createColumn(t)));
    };

    document.getElementById('closeBtn').onclick=function(){
      const bd=document.getElementById('backdrop'); bd.style.display='none'; bd.setAttribute('aria-hidden','true');
    };
    document.getElementById('backdrop').onclick=function(e){
      if(e.target && e.target.id==='backdrop'){
        const bd=document.getElementById('backdrop'); bd.style.display='none'; bd.setAttribute('aria-hidden','true');
      }
    };
  }
  load();
})();
