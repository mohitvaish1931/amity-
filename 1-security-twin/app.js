// Sentinel X — Part 1: Security Twin builder. FULLY DATA-DRIVEN: no hardcoded identities/permissions/ownership.
// Spec parsing and the API/security model come from src/ (typed, tested). This file builds the twin,
// inferences and laws on top of that model and renders them. All rendering goes through html``/setHtml,
// which escape every interpolated value.
import { analyzeSpecText } from "../src/model/index";
import { generateSecurityConstitution, toLegacyLaws } from "../src/constitution/index";
import { fillPath, lastPathParam } from "../src/paths/index";
import { deriveTargetAuthorization } from "../src/target/authorization";
import { html, joinHtml, setHtml } from "../src/ui/safe-html";
import { mountSecurityTwinGraph } from "../src/twin/mount";

const $ = (id) => document.getElementById(id);
const LEVELS = ["PUBLIC", "PERSONAL", "INTERNAL", "SENSITIVE"];
let STATE = { specText:"", apiModel:null, constitution:null, baseUrl:"", endpoints:[], resources:{}, laws:[], twin:null, model:null, warnings:[], specInfo:{}, sandbox:{status:"idle"}, inferences:[], overrides:{}, dashboard:null,
  config:{ identities:[], permissions:{}, ownership:{} } };

// ---------- config-driven helpers (no hardcoded roles/names) ----------
function cfgIdentities(){ return STATE.config.identities||[]; }
function cfgPermissions(){ return STATE.config.permissions||{}; }
function cfgOwnership(){ return STATE.config.ownership||{}; }
function idToName(id){ const f=cfgIdentities().find(i=>i.id===id); return f?f.name:id; }
function distinctRoles(){ return [...new Set(cfgIdentities().map(i=>i.role).filter(Boolean))]; }
function detectAdminRole(){
  const roles = distinctRoles();
  const byName = roles.find(r=>/admin/i.test(r));
  if(byName) return byName;
  return null; // no admin surface unless spec + config say so
}
function baseRoles(){ const a=detectAdminRole(); return distinctRoles().filter(r=>r!==a); }
function privilegedActions(){
  const perms = cfgPermissions(); const roles = Object.keys(perms);
  const actions = [...new Set(roles.flatMap(r=>Object.keys(perms[r]||{})))];
  return actions.filter(act=>{ const vals = roles.map(r=>(perms[r]||{})[act]); return vals.includes(true)&&vals.includes(false); });
}
function ownershipSample(n=3){ return Object.entries(cfgOwnership()).slice(0,n).map(([o,c])=>`${o}→${idToName(c)}`).join("; ")||"none configured"; }
/** Display only: the object id fills the last path parameter (the addressed object); parent parameters stay as {name}. */
function fillObjectId(path, id){
  const last = lastPathParam(path);
  return last ? fillPath(path, { [last]: String(id) }, { onMissing:"keep" }) : path;
}
/** Authorization state for the configured target, derived from real data only (no confirmation source exists yet). */
function targetAuthorization(){ return deriveTargetAuthorization($("baseUrl").value, null); }
function renderTargetAuth(){
  const a = targetAuthorization();
  const box = $("targetAuthState");
  box.dataset.state = a.state;
  const cls = a.state==="CONFIRMED" ? "ok" : a.state==="CONFIGURED" ? "sub" : "warn";
  const icon = a.state==="CONFIRMED" ? "✅" : a.state==="CONFIGURED" ? "ℹ" : "⚠";
  setHtml(box, html`<span class="${cls}">${icon} ${a.label}</span><span class="sub" style="margin:0 0 0 8px">${a.detail}</span>`);
}
function isIdGet(e){ return e.method==="GET"&&/\{.+\}/.test(e.path); }
function authLabel(e){ return e.authMode==="required"?"Required":e.authMode==="optional"?"Optional":"Open"; }

// ---------- fully data-driven twin ----------
function buildTwin(endpoints, resources){
  const byResource = {};
  Object.keys(resources).forEach(r=>{
    const sens = {}; Object.values(resources[r].fields).forEach(f=>{ sens[f.sensitivity]=(sens[f.sensitivity]||0)+1; });
    byResource[r]={ endpoints:resources[r].endpoints, fieldCount:Object.keys(resources[r].fields).length, sensitivity:sens, ownershipField:resources[r].ownershipField||null, relations:resources[r].relations };
  });
  const adminRole = detectAdminRole();
  const adminEps = endpoints.filter(e=>e.action==="AdminAction"||e.resource==="Admin").map(e=>e.id);
  const idGetEps = endpoints.filter(isIdGet).map(e=>e.id);
  const perms = cfgPermissions();
  const roles = {};
  distinctRoles().forEach(role=>{
    const mp = perms[role]||{};
    roles[role]={ identities:cfgIdentities().filter(i=>i.role===role),
      allowed:Object.keys(mp).filter(k=>mp[k]===true), denied:Object.keys(mp).filter(k=>mp[k]===false),
      ownership: role===adminRole? {} : cfgOwnership(),
      adminEndpoints: role===adminRole? adminEps : [] };
  });
  return { auth:{ required:endpoints.filter(e=>e.auth).map(e=>e.id), open:endpoints.filter(e=>!e.auth).map(e=>e.id) },
    roles, adminRole, baseRoles:baseRoles(), adminEndpoints:adminEps,
    resources:byResource, bolaCandidates:idGetEps,
    nodeSchema:["Identity","Role","Resource","Ownership","Endpoint","Sensitivity","AllowedActions"] };
}

function buildInferences(endpoints, resources){
  const inf=[];
  const idGets = endpoints.filter(isIdGet);
  const owned = Object.keys(resources).filter(r=>resources[r].ownershipField);
  const roles = distinctRoles();
  inf.push({ id:"INF-01", claim:"ID-parameterised reads are BOLA candidates",
    evidence:idGets.length? idGets.map(e=>`${e.id} ${e.method} ${e.path}`) : ["none found"],
    confidence: owned.length?"HIGH":"MEDIUM", score: owned.length?90:60,
    needed: owned.length?`Sandbox proof: cross-owner GET must DENY (owners: ${ownershipSample()})`:"Find ownership field (e.g. ownerId/customerId) or confirm via sandbox" });
  inf.push({ id:"INF-02", claim:"Ownership links identities to objects",
    evidence: owned.length? owned.map(r=>`${r}.${resources[r].ownershipField} + map ${ownershipSample()}`) : [`no ownership field in spec — using configured map: ${ownershipSample()}`],
    confidence: owned.length&&Object.keys(cfgOwnership()).length?"HIGH":"MEDIUM", score: owned.length&&Object.keys(cfgOwnership()).length?90:55,
    needed:"Confirm owner(o) at runtime; if mismatch, law stays candidate" });
  const sensN = Object.values(resources).reduce((a,r)=>a+Object.values(r.fields).filter(f=>f.sensitivity==="PERSONAL"||f.sensitivity==="SENSITIVE").length,0);
  inf.push({ id:"INF-03", claim:"Private/sensitive fields identified",
    evidence:[sensN+" PERSONAL/SENSITIVE fields (including nested and array fields)"], confidence:"MEDIUM", score:60,
    needed:"Runtime check: does foreign GET leak them? If yes → vuln, else RISK only" });
  const prot = endpoints.filter(e=>e.auth).length, open = endpoints.filter(e=>!e.auth).length;
  const undeclared = endpoints.filter(e=>e.authInferred).length;
  inf.push({ id:"INF-04", claim:"Auth boundary mapped",
    evidence:[`${prot} protected, ${open} open${undeclared?` (${undeclared} with no security declared)`:""}`], confidence: undeclared?"MEDIUM":"HIGH", score: undeclared?65:90,
    needed:"Anonymous probe in Part 2 to confirm 401/403" });
  const adm = endpoints.filter(e=>e.action==="AdminAction").length;
  const adminRole = detectAdminRole();
  inf.push({ id:"INF-05", claim:"Admin role boundary exists",
    evidence: adm&&adminRole? [adm+` admin endpoints, admin role='${adminRole}', roles=[${roles.join(", ")}]`] : ["no admin endpoints or no admin role in config"],
    confidence: adm&&adminRole?"HIGH":"LOW", score: adm&&adminRole?90:30,
    needed: adm&&adminRole?`Non-admin (${baseRoles().join(", ")||"others"}) invoking admin endpoints must DENY`:"N/A — no admin surface" });
  return inf;
}

// representative fixtures derived from config + spec (no hardcoded ids/paths)
function bolaTarget(){
  const idGets = STATE.endpoints.filter(isIdGet);
  if(!idGets.length) return null;
  const owned = Object.keys(STATE.resources).filter(r=>STATE.resources[r].ownershipField);
  const covered = owned.filter(r=> (STATE.resources[r].endpoints||[]).some(e=>idGets.some(g=>g.id===e)));
  const rank = (r)=> (STATE.resources[r].endpoints||[]).length*10 + Object.values(STATE.resources[r].fields||{}).filter(f=>f.sensitivity==="PERSONAL"||f.sensitivity==="SENSITIVE").length;
  const pool = (covered.length?covered:owned.length?owned:[idGets[0].resource]).slice().sort((a,b)=>rank(b)-rank(a));
  const target = pool[0];
  return { target, idGet: idGets.find(e=>e.resource===target)||idGets[0], ownershipField: STATE.resources[target]&&STATE.resources[target].ownershipField };
}
function fixtures(){
  const ids = cfgIdentities(); const own = Object.entries(cfgOwnership());
  const adminRole = detectAdminRole(); const bases = baseRoles();
  const baseId = ids.find(i=>bases.includes(i.role)) || ids[0] || {id:"actor_1",name:"actor_1",role:bases[0]||"role_1"};
  const adminId = (adminRole&&ids.find(i=>i.role===adminRole)) || null;
  let ownPair=null, foreignPair=null;
  const mine = own.find(([,c])=>c===baseId.id);
  if(mine) ownPair = { id:mine[0], owner:mine[1] };
  const foreign = own.find(([,c])=>c!==baseId.id);
  if(foreign) foreignPair = { id:foreign[0], owner:foreign[1] };
  if(!ownPair&&own.length) ownPair = { id:own[0][0], owner:own[0][1] };
  const bt = bolaTarget();
  const idGet = (bt&&bt.idGet) || STATE.endpoints.find(isIdGet);
  const adminEp = STATE.endpoints.find(e=>e.action==="AdminAction"||e.resource==="Admin");
  const protEp = STATE.endpoints.find(e=>e.auth);
  return { baseId, adminId, ownPair, foreignPair, idGet, adminEp, protEp };
}

function lawTestsFor(law){
  const f = fixtures();
  const ownWhen = (f.idGet&&f.ownPair)? `${f.idGet.method} ${fillObjectId(f.idGet.path,f.ownPair.id)} (own, owner=${f.ownPair.owner})` : "GET own object";
  const forWhen = (f.idGet&&f.foreignPair)? `${f.idGet.method} ${fillObjectId(f.idGet.path,f.foreignPair.id)} (foreign, owner=${f.foreignPair.owner})` : "GET foreign object";
  if(law.category==="BOLA") return [
    { given:`authenticated as ${f.baseId.id} (${idToName(f.baseId.id)})`, when:ownWhen, expect:"ALLOW + own data only" },
    { given:`authenticated as ${f.baseId.id} (${idToName(f.baseId.id)})`, when:forWhen, expect:"DENY (401/403/404 without leakage) — violation = BOLA" },
    { given:"unauthenticated", when:f.idGet?`${f.idGet.method} ${fillObjectId(f.idGet.path,(f.ownPair||{id:"1"}).id)}`:"GET object", expect:"DENY (auth)" }];
  if(law.category==="ADMIN"){
    const admWhen = f.adminEp? `${f.adminEp.method} ${f.adminEp.path}` : "admin endpoint";
    return [
      { given:`authenticated as ${f.baseId.id} (non-admin)`, when:admWhen, expect:"DENY (403) — violation = broken access control" },
      ...(f.adminId?[{ given:`authenticated as ${f.adminId.id} (${f.adminId.role})`, when:admWhen, expect:"ALLOW" }]:[])];
  }
  if(law.category==="DATA") return [
    { given:`authenticated as ${f.baseId.id}`, when:forWhen, expect:"MUST NOT contain PERSONAL/SENSITIVE of another owner — leak = excessive exposure" }];
  if(law.category==="POLICY") return [];
  if(law.category==="AUTHN") return [{ given:"no token", when:f.protEp?`${f.protEp.method} ${f.protEp.path}`:"protected endpoint", expect:"DENY 401" }];
  const priv = privilegedActions();
  return [{ given:`roles=[${distinctRoles().join(", ")}]`, when:`invoke privileged action (${priv.slice(0,3).join(", ")||"restricted"})`, expect:`ALLOW ⟺ role has permission` }];
}

/** Configuration in the typed shape the Constitution engine expects. The admin role comes from a name heuristic, recorded as such. */
function constitutionConfig(){
  const adminRole = detectAdminRole(); const perms = cfgPermissions();
  const roleNames = [...new Set([...distinctRoles(), ...Object.keys(perms)])];
  return {
    identities: cfgIdentities().map(i=>({ id:String(i.id), name:String(i.name??i.id), role:String(i.role??"") })),
    roles: roleNames.map(r=>({ name:r, permissions: perms[r]&&typeof perms[r]==="object"?perms[r]:{}, privileged: r===adminRole,
      ...(r===adminRole?{ privilegeEvidence:`role name "${r}" contains "admin" (name heuristic)` }:{}) })),
    ownership: Object.entries(cfgOwnership()).map(([objectId,ownerId])=>({ objectId, ownerId:String(ownerId) })),
    sensitivityOverrides: { ...STATE.overrides },
  };
}
/** Step 2 contract: one legacy law per legacy category, derived from the constitution, with Given/When/Expect tests. */
function buildLegacyLaws(constitution){ return toLegacyLaws(constitution).map(l=>({ ...l, tests: lawTestsFor(l) })); }

function buildDashboard(){
  const eps = STATE.endpoints, res = STATE.resources;
  const prot = eps.filter(e=>e.auth).length, open = eps.length-prot;
  const fields = Object.values(res).reduce((a,r)=>a+Object.keys(r.fields).length,0);
  const sens = Object.values(res).reduce((a,r)=>a+Object.values(r.fields).filter(f=>f.sensitivity==="PERSONAL"||f.sensitivity==="SENSITIVE").length,0);
  const laws = STATE.constitution ? STATE.constitution.laws : [];
  const high = laws.filter(l=>l.confidence==="HIGH").length, med = laws.filter(l=>l.confidence==="MEDIUM").length, low = laws.filter(l=>l.confidence==="LOW").length;
  const owned = Object.keys(res).filter(r=>res[r].ownershipField).length;
  const readiness = eps.length? Math.round(100*(0.3*Math.min(1,Object.keys(res).length/3)+0.3*(prot/eps.length)+0.2*(owned/Math.max(1,Object.keys(res).length))+0.2*Math.min(1,laws.length/5))) : 0;
  return { endpoints:eps.length, resources:Object.keys(res).length, protected:prot, open, fields, sens, high, med, low, owned, readiness, sandbox:STATE.sandbox.status,
    authorization:targetAuthorization().label, roles:distinctRoles(), adminRole:detectAdminRole(), identities:cfgIdentities().length };
}

function buildTestableModel(){
  const auth = deriveTargetAuthorization(STATE.baseUrl, null);
  return { version:"part1-v5-typed", sandboxOnly:true, sandboxBaseUrl:STATE.baseUrl,
    targetAuthorization:{ state:auth.state, label:auth.label, detail:auth.detail },
    sandboxCheck:STATE.sandbox, specInfo:STATE.specInfo, warnings:STATE.warnings,
    testIdentities:cfgIdentities(), permissions:cfgPermissions(),
    ownership:Object.entries(cfgOwnership()).map(([objectId,ownerId])=>({objectId,ownerId,ownerName:idToName(ownerId)})),
    endpoints:STATE.endpoints, resources:STATE.resources, twin:STATE.twin, constitution:STATE.constitution, laws:STATE.laws, inferences:STATE.inferences,
    expectedBehavior: STATE.laws.flatMap(l=> (l.tests||[]).map(t=>({ law:l.id, category:l.category, ...t }))) };
}

// ---------- render ----------
function setSteps(n){ ["s1","s2","s3","s4","s5"].forEach((id,i)=> $(id).classList.toggle("done", i<n)); }
function renderAll(){ renderDashboard(); renderDiscovery(); renderModel(); renderIdentity(); renderSens(); renderTwin(); renderInferences(); renderConstitution(); renderLawTests(); renderOutputs(); setSteps(5); }

function renderDashboard(){
  const d = STATE.dashboard; if(!d){ $("dashboard").textContent="—"; return; }
  setHtml($("dashboard"), html`<div class="tiles">
    <div class="tile"><b>${d.endpoints}</b><span class="sub">endpoints</span></div>
    <div class="tile"><b>${d.resources}</b><span class="sub">resources</span></div>
    <div class="tile"><b>${d.protected}/${d.open}</b><span class="sub">protected/open</span></div>
    <div class="tile"><b>${d.fields}</b><span class="sub">fields (${d.sens} sens)</span></div>
    <div class="tile"><b>${d.high}H/${d.med}M/${d.low}L</b><span class="sub">constitution laws</span></div>
    <div class="tile"><b>${d.identities}</b><span class="sub">identities (${d.roles.join(", ")||"—"})</span></div></div>
    <p class="sub">Part-2 readiness: <b>${d.readiness}%</b> · sandbox: ${d.sandbox} · target: ${d.authorization} · admin role: ${d.adminRole||"none"} ${STATE.warnings.length?`· ⚠ ${STATE.warnings.length} warnings`:""}</p>
    <div class="bar"><i style="width:${d.readiness}%"></i></div>`);
}
function renderDiscovery(){
  const info = STATE.specInfo;
  const rows = STATE.endpoints.map(e=>html`<tr><td><code>${e.id}</code></td><td><code>${e.method}</code></td><td><code>${e.path}</code></td>
    <td>${authLabel(e)}<br><span class="sub">${e.authDetail}</span></td><td>${e.resource}</td><td>${e.action}</td>
    <td class="sub">${e.params.map(p=>`${p.name}(${p.in})`).join(", ")||"—"}${e.bodySchemaName?html`<br>body:${e.bodySchemaName}`:""}${e.respSchemaName?html`<br>resp:${e.respSchemaName}`:""}${e.bodyContentTypes.length?html`<br>consumes:${e.bodyContentTypes.join(", ")}`:""}</td></tr>`);
  setHtml($("discovery"), html`<p class="sub">${info.title?`${info.title} · `:""}${info.version||""} · ${STATE.endpoints.length} endpoints · servers: ${(info.servers||[]).join(", ")||"—"}</p>
    ${STATE.endpoints.length? html`<table><tr><th>ID</th><th>Method</th><th>Path</th><th>Auth</th><th>Resource</th><th>Action</th><th>Params/Body</th></tr>${rows}</table>` : html`<p class="sub">No endpoints yet.</p>`}
    ${STATE.warnings.length? html`<div class="note">⚠ ${joinHtml(STATE.warnings, html`<br>`)}</div>`:""}`);
  $("invCount").textContent = STATE.endpoints.length + " endpoints";
}
function renderModel(){
  const blocks = Object.keys(STATE.resources).map(r=>{
    const R = STATE.resources[r];
    const f = Object.entries(R.fields).map(([n,v])=>html`  ├── ${n} <span class="badge b-${v.sensitivity}">${v.sensitivity}</span> <span class="sub">${v.reason||""}</span>`);
    const rel = R.relations.length? html`<br>  ↳ relations: ${R.relations.join("; ")}`:"";
    const own = R.ownershipField? html`<br>  🔑 ownershipField: <code>${R.ownershipField}</code> (inferred from spec)` : html`<br>  <span class="sub">no ownership field — BOLA stays MEDIUM</span>`;
    return html`<div><b>├── ${r}</b> <span class="sub">[${R.endpoints.join(", ")||"—"}]</span><br>${f.length?joinHtml(f, html`<br>`):"  ├── (no schema fields)"}${rel}${own}</div>`;
  });
  if(blocks.length) setHtml($("apimodel"), joinHtml(blocks, html`<br>`)); else $("apimodel").textContent = "—";
}
function renderIdentity(){
  const perms = cfgPermissions();
  const permRows = Object.keys(perms).map(role=>{
    const entries = perms[role]&&typeof perms[role]==="object" ? Object.entries(perms[role]) : [];
    return html`<tr><td><b>${role}</b></td><td>${entries.length? joinHtml(entries.map(([k,v])=>html`${v?"✅":"❌"} ${k}`), html`<br>`) : html`<span class="sub">—</span>`}</td></tr>`;
  });
  const ownEntries = Object.entries(cfgOwnership()).map(([o,c])=>`${o}→${idToName(c)}`).join(" · ")||"none configured";
  const ownFields = Object.keys(STATE.resources).map(r=>STATE.resources[r].ownershipField?`${r}.${STATE.resources[r].ownershipField}`:null).filter(Boolean).join(", ")||"none";
  setHtml($("identitymodel"), html`<table><tr><th>Role (from config)</th><th>Permissions (from config)</th></tr>${permRows.length?permRows:html`<tr><td colspan="2" class="sub">No permissions configured</td></tr>`}</table>
    <p class="sub">Identities (from config): ${cfgIdentities().map(i=>`${i.name} (${i.id}, ${i.role})`).join(" · ")||"none"}</p>
    <p class="sub">Ownership (from config): ${ownEntries}</p>
    <p class="sub">Ownership fields (inferred from spec): ${ownFields}</p>`);
  const chips = cfgIdentities().map(i=>html`<span class="chip on">[ ${i.name} · ${i.id} · ${i.role} ]</span>`);
  setHtml($("identityChips"), chips.length? html`${chips}` : html`<span class="sub">No identities — configure below + Load Demo.</span>`);
}
function renderSens(){
  const rows=[];
  Object.keys(STATE.resources).forEach(r=>Object.keys(STATE.resources[r].fields).forEach(f=>{
    const v = STATE.resources[r].fields[f];
    const current = STATE.overrides[r+"."+f];
    rows.push(html`<tr><td><code>${r+"."+f}</code></td><td><span class="badge b-${v.sensitivity}">${v.sensitivity}</span></td><td class="sub">${v.reason}</td>
    <td><select data-r="${r}" data-f="${f}"><option value="">auto</option>${LEVELS.map(o=>html`<option value="${o}"${o===current?html` selected`:""}>${o}</option>`)}</select></td></tr>`);
  }));
  if(!rows.length){ $("sensTable").textContent="—"; return; }
  setHtml($("sensTable"), html`<table><tr><th>Field</th><th>Level</th><th>Why</th><th>Override</th></tr>${rows}</table><div class="row"><button class="ghost" id="applySens">Apply overrides → rebuild</button></div>`);
  $("applySens").onclick=()=>{
    document.querySelectorAll("#sensTable select").forEach(s=>{ const k=s.dataset.r+"."+s.dataset.f; if(s.value) STATE.overrides[k]=s.value; else delete STATE.overrides[k]; });
    rebuild(); };
}
let twinView = null;
/** Graph input built only from the typed model, configuration and generated laws. */
function twinGraphInput(){
  if(!STATE.apiModel) return null;
  const cfg = constitutionConfig();
  return {
    endpoints: STATE.apiModel.endpoints,
    resources: STATE.apiModel.resources,
    identities: cfg.identities,
    roles: cfg.roles,
    laws: STATE.constitution ? STATE.constitution.laws : [],
    ownership: cfg.ownership,
    privilegedEndpoints: detectAdminRole() && STATE.twin ? STATE.twin.adminEndpoints : [],
    sensitivityOverrides: cfg.sensitivityOverrides,
  };
}
function renderTwin(){
  if(!twinView) twinView = mountSecurityTwinGraph($("twinGraph"));
  twinView.render(twinGraphInput());
  $("twinJson").textContent = STATE.twin ? JSON.stringify(STATE.twin,null,2) : "—";
}
function renderInferences(){
  setHtml($("inferences"), html`${STATE.inferences.map(i=>html`<div class="law"><h3>${i.id} <span class="badge b-${i.confidence}">${i.confidence} ${i.score}</span></h3>
    <div>${i.claim}</div><div class="sub">Evidence: ${i.evidence.join(" · ")}</div><div class="sub">To raise confidence: ${i.needed}</div></div>`)}`);
}
const CATEGORY_LABEL = { OBJECT_AUTHORIZATION:"Object authorization", FUNCTION_AUTHORIZATION:"Function authorization", DATA_EXPOSURE:"Data exposure",
  AUTHENTICATION:"Authentication", STATE_TRANSITION:"State transition", SECURITY_CONFIGURATION:"Security configuration" };
function endpointLabel(id){ const e=STATE.endpoints.find(x=>x.id===id); return e?`${id} ${e.method} ${e.path}`:id; }
function renderConstitution(){
  const c = STATE.constitution;
  if(!c){ $("laws").textContent="—"; return; }
  const counts = Object.keys(CATEGORY_LABEL).map(k=>[k, c.laws.filter(l=>l.category===k).length]).filter(([,n])=>n);
  const scopeRow = (label, items)=> items.length ? html`<div><b>${label}:</b> ${items.join(" · ")}</div>` : "";
  const cards = c.laws.map(l=>html`<details class="law const-law" data-law="${l.id}">
    <summary><b>${l.id}</b> <span class="badge">${CATEGORY_LABEL[l.category]||l.category}</span> <span class="badge">${l.severity}</span>
      <span class="badge b-${l.confidence}">${l.confidence} · ${l.confidenceRationale.score}% of signals</span>
      <div class="const-statement">${l.statement}</div></summary>
    <div class="const-body">
      <h4>Machine rule</h4><div class="inv">${l.invariant}</div>
      <details><summary class="sub">rule JSON</summary><pre class="out">${JSON.stringify(l.rule,null,2)}</pre></details>
      <h4>Scope</h4>
      ${scopeRow("Endpoints", l.appliesTo.endpoints.map(endpointLabel))}${scopeRow("Resources", l.appliesTo.resources)}${scopeRow("Fields", l.appliesTo.fields)}
      ${scopeRow("Roles", l.appliesTo.roles)}${scopeRow("Identities", l.appliesTo.identities.map(id=>`${idToName(id)} (${id})`))}
      <h4>Provenance (${l.provenance.length})</h4><ul>${l.provenance.map(p=>html`<li><code>${p.ref}</code> — ${p.detail}</li>`)}</ul>
      <h4>Confidence: ${l.confidence}</h4><p class="sub">${l.confidenceRationale.rule}</p>
      <ul>${l.confidenceRationale.signals.map(s=>html`<li>${s.present?"✅":"❌"} ${s.description}</li>`)}</ul>
      <h4>Test strategy <span class="sub">(${l.testStrategy.kind} · specification only, not executed)</span></h4>
      ${l.testStrategy.preconditions.length?html`<div class="sub">Preconditions: ${l.testStrategy.preconditions.join(" · ")}</div>`:""}
      <ol>${l.testStrategy.steps.map(st=>html`<li>${st}</li>`)}</ol><div><b>Expected:</b> ${l.testStrategy.expected}</div>
      <div class="row"><button class="ghost" type="button" data-focus-law="${l.id}">Highlight scope in graph</button></div>
    </div></details>`);
  setHtml($("laws"), html`<p class="sub">${c.laws.length} laws · ${counts.map(([k,n])=>`${n} ${CATEGORY_LABEL[k].toLowerCase()}`).join(" · ")}</p>${cards}
    ${c.notes.length?html`<div class="note">${joinHtml(c.notes, html`<br>`)}</div>`:""}
    <div class="note">Laws are derived from the spec model and configuration. Confidence is computed from the listed evidence signals; test strategies are specifications, not executed tests.</div>`);
  document.querySelectorAll("#laws [data-focus-law]").forEach(b=>b.onclick=()=>focusLaw(b.dataset.focusLaw));
}
function focusLaw(id){
  document.querySelectorAll("#laws details.const-law").forEach(d=>d.classList.toggle("is-focused", d.dataset.law===id));
  if(twinView) twinView.focusLaw(id);
  const g=$("twinGraph"); if(g&&g.scrollIntoView) g.scrollIntoView({ behavior:"smooth", block:"center" });
}
function renderLawTests(){
  setHtml($("lawTests"), html`${STATE.laws.map(l=>html`<div class="law"><h3>${l.id} tests</h3>${(l.tests||[]).map(t=>html`<div>· <b>Given</b> ${t.given} <b>When</b> <code>${t.when}</code> <b>Expect</b> ${t.expect}</div>`)}</div>`)}`);
}
function renderOutputs(){
  const m = buildTestableModel(); STATE.model = m;
  $("out1").textContent = JSON.stringify({version:STATE.specInfo.version, servers:STATE.specInfo.servers, count:STATE.endpoints.length, endpoints:STATE.endpoints},null,2);
  $("out2").textContent = JSON.stringify({resources:STATE.resources, twin:STATE.twin, ownership:cfgOwnership(), identities:cfgIdentities()},null,2);
  $("out3").textContent = JSON.stringify(STATE.constitution,null,2);
  $("out4").textContent = JSON.stringify(m,null,2);
}

function parseConfigEditors(){
  const idTxt = $("identitiesEditor").value.trim(), pmTxt = $("permissionsEditor").value.trim(), ownTxt = $("ownershipEditor").value.trim();
  if(!idTxt||!pmTxt||!ownTxt) throw new Error("Fill identities + permissions + ownership config (or Load Demo).");
  const identities = JSON.parse(idTxt), permissions = JSON.parse(pmTxt), ownership = JSON.parse(ownTxt);
  if(!Array.isArray(identities)||!identities.length) throw new Error("identities must be a non-empty array [{name,role,id}].");
  if(!identities.every(i=>i&&typeof i==="object"&&typeof i.id==="string")) throw new Error("every identity needs a string id.");
  if(!permissions||typeof permissions!=="object"||Array.isArray(permissions)) throw new Error("permissions must be an object {role:{action:bool}}.");
  if(!ownership||typeof ownership!=="object"||Array.isArray(ownership)) throw new Error("ownership must be an object {objectId:ownerId}.");
  return { identities, permissions, ownership };
}

function rebuild(){
  const r = analyzeSpecText(STATE.specText, STATE.overrides);
  if(!r.ok){ alert("Invalid spec:\n"+r.errors.join("\n")); return; }
  STATE.apiModel = r.model;
  STATE.endpoints = r.view.endpoints;
  STATE.resources = r.view.resources;
  STATE.specInfo = r.view.specInfo;
  STATE.warnings = [...r.view.warnings]; // fresh each rebuild; laws may append below
  STATE.twin = buildTwin(STATE.endpoints, STATE.resources);
  STATE.inferences = buildInferences(STATE.endpoints, STATE.resources);
  STATE.constitution = generateSecurityConstitution(STATE.apiModel, constitutionConfig());
  STATE.laws = buildLegacyLaws(STATE.constitution);
  STATE.dashboard = buildDashboard();
  renderAll();
}
function build(){
  const txt = $("swaggerText").value.trim();
  STATE.baseUrl = $("baseUrl").value.trim();
  if(!txt){ alert("Paste an OpenAPI 3.x / Swagger 2.0 spec (JSON or YAML), or Upload / Load demo first."); return; }
  const check = analyzeSpecText(txt);
  if(!check.ok){ alert("Invalid spec:\n"+check.errors.join("\n")); return; }
  try{ STATE.config = parseConfigEditors(); }catch(e){ alert("Bad config: "+e.message); return; }
  STATE.specText = txt;
  rebuild();
}
function download(name, text){ const a=document.createElement("a"); a.href=URL.createObjectURL(new Blob([text],{type:"application/json"})); a.download=name; a.click(); }
function isSandboxLike(url){ return /(sandbox|localhost|127\.|10\.|192\.168|staging|test|example|mock)/i.test(url); }
async function testSandbox(){
  const url = $("baseUrl").value.trim();
  const box = $("sandboxStatus");
  if(!url){ setHtml(box, html`<span class="warn">Enter Sandbox Base URL first.</span>`); return; }
  const prefix = isSandboxLike(url)
    ? html``
    : html`<span class="warn">⚠ URL does not look like a sandbox. Only use a sandbox you are authorized to test.</span><br>`;
  setHtml(box, html`${prefix}Testing…`);
  const t0 = performance.now();
  try{
    const ctl = new AbortController(); const to = setTimeout(()=>ctl.abort(), 8000);
    const r = await fetch(url, { method:"GET", signal:ctl.signal, mode:"cors" });
    clearTimeout(to);
    const ms = Math.round(performance.now()-t0);
    STATE.sandbox = { status: r.ok?"reachable":"http-"+r.status, ms, url };
    setHtml(box, html`${prefix}<span class="ok">● Sandbox: HTTP ${r.status} in ${ms}ms</span><br><span class="sub">Safe GET only.</span>`);
  }catch(e){
    const ms = Math.round(performance.now()-t0);
    STATE.sandbox = { status:"unreachable:"+String(e.name||e.message), ms, url };
    setHtml(box, html`${prefix}<span class="warn">● Unreachable or blocked by CORS (${e.name||"error"}) in ${ms}ms. Twin still builds from spec.</span>`);
  }
  if(STATE.dashboard){ STATE.dashboard = buildDashboard(); renderDashboard(); renderOutputs(); }
}

window.addEventListener("DOMContentLoaded", ()=>{
  $("buildBtn").onclick = build;
  $("testBtn").onclick = testSandbox;
  $("applyConfig").onclick = ()=>{ try{ STATE.config = parseConfigEditors(); }catch(e){ alert("Bad config: "+e.message); return; } if(!STATE.endpoints.length){ alert("Build first, then apply."); return; } rebuild(); };
  $("demoBtn").onclick = async ()=>{
    const r = await fetch("samples/sample-swagger.json"); $("swaggerText").value = await r.text();
    const c = await fetch("samples/sample-config.json"); const cfg = await c.json();
    $("identitiesEditor").value = JSON.stringify(cfg.identities,null,2);
    $("permissionsEditor").value = JSON.stringify(cfg.permissions,null,2);
    $("ownershipEditor").value = JSON.stringify(cfg.ownership,null,2);
    if(!$("baseUrl").value) $("baseUrl").value="https://sandbox-api.example.com";
    renderTargetAuth();
  };
  $("baseUrl").addEventListener("input", ()=>{
    renderTargetAuth();
    if(STATE.dashboard){ STATE.dashboard = buildDashboard(); renderDashboard(); }
  });
  renderTargetAuth();
  $("fileInput").addEventListener("change", e=>{ const f=e.target.files[0]; if(!f) return; const rd=new FileReader(); rd.onload=()=>{ $("swaggerText").value=rd.result; }; rd.readAsText(f); });
  $("dl4").onclick=()=>download("testable-security-model.json",$("out4").textContent);
  $("copy4").onclick=()=>{ navigator.clipboard.writeText($("out4").textContent); alert("Testable Security Model copied — paste into Part 2."); };
});
