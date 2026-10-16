'use strict';
const $ = id => document.getElementById(id);
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
let catalog = [], commands = {}, guides = [], training, selected, page = 0, records = [];
const size = 12, storageKey = 'assessment-desk-v1';
function notice(message) { $('notice').textContent = message; }
function link(url, label) { try { const u = new URL(url, location.origin); if (!['http:', 'https:'].includes(u.protocol)) return esc(label); return `<a href="${esc(u.href)}" target="_blank" rel="noopener noreferrer">${esc(label)}</a>`; } catch { return esc(label); } }
function tab(name) {
  notice('');
  document.querySelectorAll('.tab').forEach(e => e.hidden = e.id !== name);
  document.querySelectorAll('nav button').forEach(e => e.classList.toggle('active', e.dataset.tab === name));
  $('page-title').textContent = {catalog:'Follow the vulnerability guide.',guides:'Knowledge you can work from.',training:'Train the analyst. Test the control.',library:'Sources, kept for provenance.',workbench:'Keep the evidence together.'}[name];
  if (name === 'workbench') showRecords();
}
function filtered() {
  const q = $('search').value.trim().toLowerCase();
  return catalog.filter(r => (!q || [r.cveID,r.vendorProject,r.product,r.shortDescription,r.cwes].join(' ').toLowerCase().includes(q)) && (!$('family').value || r.playbook === $('family').value) && (!$('ransom').value || r.knownRansomwareCampaignUse === $('ransom').value));
}
function showRows() {
  const list = filtered(); page = Math.min(page, Math.max(0, Math.ceil(list.length / size)-1));
  $('count').textContent = `${list.length.toLocaleString()} entries`;
  $('rows').innerHTML = list.slice(page*size,(page+1)*size).map(r => `<button class="cve-row ${selected?.cveID === r.cveID ? 'selected' : ''}" data-cve="${r.cveID}"><span class="row-top"><strong>${r.cveID}</strong>${r.knownRansomwareCampaignUse === 'Known' ? '<span class="badge">RANSOMWARE</span>' : ''}</span><div class="product">${esc(r.vendorProject)} · ${esc(r.product)}</div><small>${esc(r.vulnerabilityName.trim())}</small></button>`).join('') || '<div class="empty">No matches. Try a broader term or clear filters.</div>';
  $('page').textContent = `Page ${page+1} / ${Math.max(1,Math.ceil(list.length/size))}`;
  $('prev').disabled = page === 0; $('next').disabled = (page+1)*size >= list.length;
  document.querySelectorAll('[data-cve]').forEach(e => e.onclick = () => selectCve(e.dataset.cve));
}
function assessmentStatus(f) {
  if (f.present === 'no') return f.evidence.trim() ? 'Not applicable (analyst-recorded)' : 'Needs inventory evidence';
  if (f.present !== 'yes') return 'Needs inventory evidence';
  if (!f.version.trim() || !f.advisory.trim() || !f.evidence.trim()) return 'Needs applicability evidence';
  if (f.affected === 'no') return 'Not affected (analyst-recorded)';
  if (f.affected !== 'yes') return 'Candidate — applicability unresolved';
  if (f.fixed === 'yes' && f.retest === 'yes') return 'Remediated — retest recorded';
  if (f.fixed === 'yes' && f.retest === 'no') return 'Fix applied — retest failed; investigate';
  if (f.fixed === 'yes') return 'Fix applied — retest pending';
  if (f.test === 'yes') return 'Verified in lab (analyst-recorded)';
  if (f.test === 'no') return 'Inconclusive — failed test does not establish absence';
  return 'Applicable — lab verification pending';
}
function options(items) { return items.map(([value,label])=>`<option value="${value}">${label}</option>`).join(''); }
const yn = [['unknown','Unknown / not checked'],['yes','Yes'],['no','No']];
function stepsHtml(items) { return '<ol>'+items.map(s=>`<li>${esc(s)}</li>`).join('')+'</ol>'; }
function commandHtml(items) { return items.map(c=>`<h3>${esc(c.title)}</h3><p class="description">${esc(c.language)} · ${esc(c.interpretation)}</p><pre>${esc(c.code)}</pre>`).join(''); }
function guideHtml(g) {
  return `<article class="method-guide"><h2>${esc(g.title)}</h2><p class="description">${esc(g.scope)}</p>${g.concepts.map(s=>`<p>${esc(s)}</p>`).join('')}<h3>01 · Discover the boundary</h3>${commandHtml(g.discover) || '<p>Use the configuration, source and approved fixture review below. No generic network command establishes this weakness.</p>'}<h3>02 · Verify and interpret</h3>${stepsHtml(g.verify)}<h3>Decision branches</h3><ul>${g.branches.map(b=>`<li><strong>If ${esc(b.condition)}:</strong> ${esc(b.outcome)}</li>`).join('')}</ul><h3>03 · Fix / prevent</h3>${stepsHtml(g.fix)}<h3>04 · Retest</h3>${stepsHtml(g.retest)}<h3>Detection evidence</h3>${stepsHtml(g.detection)}<details><summary>Optional provenance (${g.provenance.length} passages)</summary><p>These sources informed the self-contained instructions above; opening them is not a required step.</p>${g.provenance.map(p=>`<p>${link(`/sources/${p.source}#page=${p.page}`,`${p.source}, PDF page ${p.page}`)} · ${esc(p.reason)}</p>`).join('')}</details></article>`;
}
function showGuides() {
  const q = $('guide-search').value.trim().toLowerCase();
  const matches = guides.filter(g=>JSON.stringify(g).toLowerCase().includes(q));
  $('guide-list').innerHTML = matches.map(g=>`<details class="method-card"><summary>${esc(g.title)}</summary>${guideHtml(g)}</details>`).join('') || '<p class="empty">No matching methods.</p>';
}
$('guide-search').oninput = showGuides;
function showTraining() {
  const q = $('training-search').value.trim().toLowerCase(), group = $('training-group').value;
  const groups = training.groups.filter(g=>!group || g.id===group).map(g=>({...g,topics:g.topics.filter(t=>[g.title,...t].join(' ').toLowerCase().includes(q))})).filter(g=>g.topics.length);
  $('training-results').textContent = `${groups.reduce((n,g)=>n+g.topics.length,0)} matching topic entries in ${groups.length} groups`;
  $('training-list').innerHTML = groups.map(g=>`<details class="training-card training-group-card"><summary>${esc(g.title)} · ${g.topics.length} topics</summary><article class="method-guide"><p>${esc(g.goal)}</p><h3>Group procedure · start here</h3>${commandHtml(g.commands)}<h3>Verify and interpret</h3>${stepsHtml(g.verify)}<h3>Fix / prevent</h3>${stepsHtml(g.fix)}<h3>Retest</h3>${stepsHtml(g.retest)}<h3>Detection evidence</h3><p>${esc(g.detection)}</p><h3>Outcome branches</h3><ul><li>Missing authority/prerequisite/evidence → not tested or coverage gap.</li><li>Expected deny fails → record the exact boundary, stop expansion and escalate to its owner.</li><li>Expected event missing → distinguish source, collection, rule and response failures using the offline pipeline lab.</li><li>Expected observations match → report the specific control and test mode, not universal attack resistance.</li></ul><h3>Topic-specific reference</h3>${g.topics.map(([title,meaning,evidence,prevention,exercise])=>`<details class="training-topic"><summary>${esc(title)}</summary><h3>Understand the behavior</h3><p>${esc(meaning)}</p><h3>Find / assess evidence</h3><p>${esc(evidence)}</p><h3>Prevent / remediate</h3><p>${esc(prevention)}</p><h3>Safe exercise</h3><p>${esc(exercise)}</p><p>Use the group procedure above and relevant hands-on lab below. This entry is not an exploit implementation.</p></details>`).join('')}</article></details>`).join('') || '<p class="empty">No matching topics. Clear the search or choose another group.</p>';
  $('training-labs').innerHTML = training.labs.filter(l=>!group || l.groups.includes(group)).map(l=>`<details class="training-card training-lab" id="lab-${esc(l.id)}"><summary>${esc(l.title)}</summary><article class="method-guide"><h3>Prerequisites</h3><p>${esc(l.prerequisites)}</p>${commandHtml(l.commands)}<h3>Operator and defender walkthrough</h3>${stepsHtml(l.steps)}<h3>Expected result</h3><p>${esc(l.expected)}</p><div class="warning">What this does not prove: ${esc(l.limits)}</div></article></details>`).join('');
}
$('training-search').oninput = showTraining;
$('training-group').oninput = showTraining;
function selectCve(id) {
  selected = catalog.find(r=>r.cveID===id); if (!selected) return;
  const r = selected, c = r.curated;
  const methods = r.guideIds.map(id=>guides.find(g=>g.id===id)).filter(Boolean);
  const phase = key => c ? stepsHtml(c[key]) : methods.map(g=>`<h3>${esc(g.title)}</h3>${stepsHtml(g[key])}`).join('');
  $('detail').innerHTML = `<div class="identifier">${r.cveID} &nbsp; / &nbsp; ${esc(r.cwes || 'CWE not supplied')}</div><h2>${esc(r.vulnerabilityName.trim())}</h2><p class="description">${esc(c?.summary || r.shortDescription)}</p><div class="warning">${esc(r.coverage)}. These guides establish defensive evidence, not automatic exploit verification.</div><div class="steps"><span>01 FIND</span><span>02 VERIFY</span><span>03 DEFEND</span><span>04 RETEST</span></div>
  <details open><summary>Affected builds and access prerequisites</summary><p>${esc(c?.affected || r.nvdDescription || 'No English applicability summary in this NVD record.')}</p>${r.accessMetrics.slice(0,2).map(m=>`<p>CVSS ${esc(m.version)} (${esc(m.source)}, ${esc(m.type)}): ${esc(m.attackVector || 'unknown')} access · Privileges: ${esc(m.privilegesRequired || 'unknown')} · User interaction: ${esc(m.userInteraction || 'unknown')}. Metrics are not a substitute for effective configuration evidence.</p>`).join('')}<details><summary>Structured NVD version/environment conditions</summary><p>Preserved AND/OR and environment constraints; this is not a flattened version verdict. Vendor backports and configuration matter.</p><pre>${esc(r.versionConditions || 'No conditions in this snapshot.')}</pre><p>Snapshot ${esc(r.nvdTimestamp)} · ${esc(r.nvdStatus)} · record modified ${esc(r.nvdModified)}</p></details></details>
  <details open><summary>01 &nbsp; Find the product and deployed build</summary>${c ? commandHtml(c.discover) : `<p>Identify ${esc(r.vendorProject)} / ${esc(r.product)} in the actual deployment. Suggested platform inventory: ${esc(r.playbook)}; adapt to the host rather than assuming this heuristic is a CVE test.</p><pre>${esc(commands[r.playbook][1])}</pre>`}<p>Optional offline product correlation (PowerShell, from assessment folder):</p><pre>..\\.tools\\python\\python.exe check.py --cve ${r.cveID} --inventory inventory.json</pre></details>
  <details><summary>02 &nbsp; Verify applicability and interpret the result</summary>${phase('verify')}<h3>Decision branches</h3><ul>${methods.flatMap(g=>g.branches).map(b=>`<li><strong>If ${esc(b.condition)}:</strong> ${esc(b.outcome)}</li>`).join('')}</ul><p>A failed test is inconclusive unless the specific unaffected conditions are independently established. No snapshot/reset dependency or bulk exploit payloads are included.</p></details>
  <details><summary>03 &nbsp; Remediate, prevent and retest</summary><h3>Fix / prevent</h3>${phase('fix')}<h3>Retest</h3>${phase('retest')}<h3>Catalog action</h3><p>${esc(r.requiredAction)}</p><p>Catalog due: ${esc(r.dueDate)} · Forensic triage: ${esc(r.forensicTriage)} · Ransomware use: ${esc(r.knownRansomwareCampaignUse)}. Catalog deadlines are not automatically your organization's deadlines.</p></details>
  <details><summary>04 &nbsp; Validate intrusion detection and containment</summary><p>For this test, record the attacker vantage point and ground-truth start time, expected sensor/rule, alert ID/time and verified containment time. Compare authorized control activity, unauthorized identities, low-volume ordinary activity and encrypted-service visibility. Check whether the action occurred → sensor saw it → telemetry was retained → expected alert fired → response actually stopped access.</p><p>An IDS cannot infer all authorization from packets alone. Correlate identity, endpoint and application evidence. Log detection findings separately from vulnerability proof; a reproduced CVE is not automatically a detected intrusion.</p><p>${link('/guides/detection','Open the complete detection-validation matrix and scoring guide ↗')}</p></details>
  <details><summary>GitHub defensive code / upstream fixes (${r.codeLinks.length})</summary>${r.codeLinks.length ? r.codeLinks.map(code=>`<p>${link(code.url,code.kind)}<br>${esc(code.note)}</p>`).join('') : '<p>No curated upstream GitHub patch/source link in this snapshot. This does not mean no code exists. Exploit repositories are not included.</p>'}</details>
  <details><summary>Self-contained methods behind this guide</summary><p>Read the complete synthesized methods here—no book lookup required. The mapping is by weakness family, not a claim that each generic method reproduces this CVE.</p>${methods.map(guideHtml).join('')}</details>
  <details><summary>Optional source provenance / advisories</summary><p>NVD was fetched for the catalog. Only vendor-reviewed guides were individually checked against vendor/source documentation. Other reference URLs have not all been validated.</p><ul>${[...new Set([...(c?.sources || []),...r.references])].map(u=>`<li>${link(u,u)}</li>`).join('')}</ul><button id="related-books">Search optional source archive →</button></details>
  <form id="assessment-form" class="assessment-form"><h3>Record an asset assessment</h3><p class="description">One record per asset + CVE. Saving updates that pair; export before overwriting evidence you need to retain.</p><div class="form-grid"><label>Asset / lab ID<input name="asset" required placeholder="e.g. lab-dns-01"></label><label>Observed version / build<input name="version" placeholder="Exact deployed build"></label><label>Product present?<select name="present">${options(yn)}</select></label><label>Vendor applicability confirmed?<select name="affected">${options(yn)}</select></label><label>Lab test reproduced expected result?<select name="test">${options(yn)}</select></label><label>Vendor fix applied?<select name="fixed">${options(yn)}</select></label><label>Post-fix retest passed?<select name="retest">${options(yn)}</select></label><label>Advisory / test procedure reference<input name="advisory" placeholder="URL, diagnostic or procedure ID"></label></div><label>Evidence, attacker vantage point, configuration and test result<textarea name="evidence" placeholder="Required access, expected vs. observed result, logs, scanner/plugin version, before/after builds…"></textarea></label><div id="verdict" class="verdict">Needs inventory evidence</div><button type="submit">Save assessment →</button></form>`;
  const form = $('assessment-form');
  form.oninput = () => $('verdict').textContent = assessmentStatus(Object.fromEntries(new FormData(form)));
  form.onsubmit = e => {
    e.preventDefault(); const f = Object.fromEntries(new FormData(form)); f.asset = f.asset.trim();
    if (!f.asset) {notice('Enter an asset ID.'); return;}
    const record = {...f,cve:r.cveID,status:assessmentStatus(f),updated:new Date().toISOString()};
    const next = records.filter(x=>!(x.asset===f.asset && x.cve===r.cveID)).concat(record);
    try { localStorage.setItem(storageKey,JSON.stringify(next)); records=next; notice(`Saved ${r.cveID} for ${f.asset}. Export a backup to retain it outside this browser.`); } catch { notice('Browser storage unavailable or full. Record was not saved.'); }
  };
  $('related-books').onclick = () => {tab('library'); $('doc-query').value=r.product; $('doc-form').requestSubmit();};
  showRows();
}
function showRecords() {
  $('records').innerHTML = records.map((r,i)=>`<article class="record"><h3>${esc(r.asset)} / ${esc(r.cve)}</h3><div>${esc(r.status)}</div><p>Version: ${esc(r.version || 'Not recorded')} · Updated: ${esc(r.updated)}</p><pre>${esc(r.evidence || 'No evidence recorded')}</pre><div class="actions"><button data-edit="${i}">Review / edit</button><button data-delete="${i}">Delete record</button></div></article>`).join('') || '<div class="empty">No assessments yet. Select a CVE in the catalog and record an asset assessment.</div>';
  document.querySelectorAll('[data-edit]').forEach(e=>e.onclick=()=>{const r=records[Number(e.dataset.edit)]; tab('catalog'); selectCve(r.cve); const f=$('assessment-form'); for (const [k,v] of Object.entries(r)) if (f.elements.namedItem(k)) f.elements.namedItem(k).value=v; f.dispatchEvent(new Event('input')); f.scrollIntoView({behavior:'smooth'});});
  document.querySelectorAll('[data-delete]').forEach(e=>e.onclick=()=>{if(!confirm('Delete this local assessment? Export a backup first if needed.'))return; const next=records.filter((_,i)=>i!==Number(e.dataset.delete)); try{localStorage.setItem(storageKey,JSON.stringify(next));records=next;showRecords();}catch{notice('Could not save deletion.');}});
}
function download(name,text,type) {const u=URL.createObjectURL(new Blob([text],{type})); const a=document.createElement('a'); a.href=u;a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(u),1000);}
document.querySelectorAll('nav button').forEach(e=>e.onclick=()=>tab(e.dataset.tab));
for (const id of ['search','family','ransom']) $(id).oninput=()=>{page=0;showRows();};
$('prev').onclick=()=>{page--;showRows();};$('next').onclick=()=>{page++;showRows();};
let searchSequence=0;
$('doc-form').onsubmit=async e=>{e.preventDefault();const seq=++searchSequence; $('doc-results').textContent='Searching all extracted pages…';try{const response=await fetch('/api/search-docs?q='+encodeURIComponent($('doc-query').value));if(!response.ok)throw Error();const data=await response.json();if(seq!==searchSequence)return;$('doc-results').innerHTML=`<p>${data.total} matching pages; showing up to 60. PDF page numbers may differ from printed page numbers.</p>`+data.hits.map(h=>`<article class="hit"><h3>${link(`/sources/${h.source}#page=${h.page}`,`${h.name} — PDF page ${h.page}`)}</h3><p>${esc(h.snippet)}</p></article>`).join('');}catch{$('doc-results').textContent='Search unavailable. Check that the local server is running.';}};
$('export-json').onclick=()=>download('assessment-backup.json',JSON.stringify({schema:1,records},null,2),'application/json');
$('export-md').onclick=()=>download('Lab Assessments.md', '# Lab Assessments\n\nAnalyst-recorded findings, not automatic verification.\n\n'+records.map(r=>`## ${r.asset.replace(/[\r\n]/g,' ')} — [[${r.cve}]]\n\n- Status: ${r.status}\n- Version: ${r.version}\n- Updated: ${r.updated}\n- Advisory / procedure: ${r.advisory}\n\nEvidence:\n\n${r.evidence.split('\n').map(line=>'> '+line).join('\n')}\n`).join('\n'),'text/markdown');
function validateBackup(data){return data?.schema===1 && Array.isArray(data.records) && data.records.length<=20000 && data.records.every(r=>r && typeof r==='object' && catalog.some(c=>c.cveID===r.cve) && ['asset','version','present','affected','test','fixed','retest','advisory','evidence','updated'].every(k=>typeof r[k]==='string') && r.asset.trim() && ['present','affected','test','fixed','retest'].every(k=>['yes','no','unknown'].includes(r[k])));}
$('import').onchange=async e=>{const file=e.target.files[0];if(!file)return;try{if(file.size>10000000)throw Error();const data=JSON.parse(await file.text());if(!validateBackup(data))throw Error();const merged=new Map(records.map(r=>[JSON.stringify([r.asset,r.cve]),r]));for(const r of data.records)merged.set(JSON.stringify([r.asset,r.cve]),{...r,status:assessmentStatus(r)});const next=[...merged.values()];localStorage.setItem(storageKey,JSON.stringify(next));records=next;showRecords();notice('Backup imported; matching asset/CVE pairs were updated.');}catch{notice('Import failed: invalid backup, unknown CVE, oversized file or unavailable browser storage.');}e.target.value='';};
async function init(){try{
  const load=async name=>{const res=await fetch('/data/'+name+'.json');if(!res.ok)throw Error();return res.json();};
  const [rows,stats,sources,cmds]=await Promise.all(['catalog','coverage','sources','commands'].map(load));catalog=rows;commands=cmds;guides=cmds._guides;showGuides();
  training=cmds._training;
  $('training-count').textContent=`${stats.trainingGroups} groups · ${stats.trainingTopics} topic entries · ${stats.trainingLabs} hands-on labs`;
  $('training-scope').textContent=training.scope;
  $('training-taxonomy').textContent=training.taxonomy;
  $('training-sources').innerHTML=training.sources.map(u=>`<p>${link(u,u)}</p>`).join('');
  $('training-group').innerHTML='<option value="">All groups</option>'+training.groups.map(g=>`<option value="${esc(g.id)}">${esc(g.title)}</option>`).join('');
  showTraining();
  try{const saved=JSON.parse(localStorage.getItem(storageKey)||'[]');if(!validateBackup({schema:1,records:saved}))throw Error();records=saved.map(r=>({...r,status:assessmentStatus(r)}));}catch{notice('Saved evidence could not be read. Import an exported backup if needed.');}
  $('stats').innerHTML=`<div><strong>${stats.cves.toLocaleString()}</strong><span>CVEs · ${stats.nvdEnriched.toLocaleString()} NVD-enriched</span></div><div><strong>${stats.guides}</strong><span>Self-contained assessment methods</span></div><div><strong>${stats.vendorReviewed}</strong><span>Vendor-reviewed CVE guides</span></div><div><strong>${stats.withGithubCode}</strong><span>CVEs with upstream GitHub code links</span></div>`;
  $('sources').innerHTML=sources.map(s=>`<article class="source-card"><h3>${esc(s.name)}</h3><p>${s.pages} pages · ${s.lowTextPages.length} low-text pages</p>${link('/sources/'+s.id,'Open original PDF ↗')}</article>`).join('');
  selectCve(catalog[0].cveID);
}catch{notice('Could not load local data. Run build.py, then launch Start Assessment.cmd.');}}
init();
