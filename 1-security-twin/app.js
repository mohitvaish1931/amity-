// Sentinel X — Part 1: Security Twin builder. FULLY DATA-DRIVEN: no hardcoded identities/permissions/ownership.
// Spec parsing and the API/security model come from src/ (typed, tested). This file builds the twin,
// inferences and laws on top of that model and renders them. All rendering goes through html``/setHtml,
// which escape every interpolated value.
import { analyzeSpecText } from "../src/model/index";
import { exportConstitutionJson, exportConstitutionMarkdown, filterLaws, generateSecurityConstitution, renderConstitutionReport, toLegacyLaws } from "../src/constitution/index";
import { fillPath, lastPathParam } from "../src/paths/index";
import { deriveTargetAuthorization } from "../src/target/authorization";
import { assessTargetHost } from "../src/target/policy";
import "../src/ui/theme.css";
import { html, joinHtml, setHtml } from "../src/ui/safe-html";
import { copyText, fetchText, showStatus } from "../src/ui/status";
import { createWorkspaceStore } from "../src/ui/persist";
import { createLazyTwinView } from "../src/twin/lazy";
import "../src/twin/styles";

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

/** Score = share of evidence signals present; level from each inference's explicit rule. No fixed numbers. */
function rated(signals, level){ const present=new Set(signals.filter(x=>x.present).map(x=>x.id)); return { signals, score: Math.round(100*present.size/Math.max(1,signals.length)), confidence: level(present) }; }
const sig = (id, description, present) => ({ id, description, present: !!present });
function buildInferences(endpoints, resources){
  const inf=[];
  const idGets = endpoints.filter(isIdGet);
  const owned = Object.keys(resources).filter(r=>resources[r].ownershipField);
  const ownerIds = [...new Set(Object.values(cfgOwnership()).map(String))];
  const knownOwners = ownerIds.filter(id=>cfgIdentities().some(i=>i.id===id));
  const roles = distinctRoles(); const adminRole = detectAdminRole();
  inf.push({ id:"INF-01", claim:"ID-parameterised endpoints are object-authorization candidates",
    evidence: idGets.length? idGets.map(e=>`${e.id} ${e.method} ${e.path}`) : ["none found"],
    ...rated([sig("id-endpoints", `${idGets.length} endpoint(s) take an object identifier`, idGets.length), sig("ownership-field", owned.length?`ownership field on ${owned.join(", ")}`:"no ownership field in the spec", owned.length), sig("two-owners", `${knownOwners.length} configured owner identit${knownOwners.length===1?"y":"ies"}`, knownOwners.length>=2)],
      p=> p.has("id-endpoints")&&p.has("ownership-field")&&p.has("two-owners") ? "HIGH" : p.has("id-endpoints")&&p.has("ownership-field") ? "MEDIUM" : "LOW"),
    needed: owned.length? "Runtime proof that cross-owner access is denied" : "An ownership field in the schema, or the ownership rule" });
  inf.push({ id:"INF-02", claim:"Ownership links identities to objects",
    evidence: owned.length? owned.map(r=>`${r}.${resources[r].ownershipField} + map ${ownershipSample()}`) : [`no ownership field in spec; configured map: ${ownershipSample()}`],
    ...rated([sig("ownership-field", "ownership field in the schema", owned.length), sig("ownership-map", `${Object.keys(cfgOwnership()).length} object(s) in the ownership map`, Object.keys(cfgOwnership()).length), sig("owners-known", "every owner is a configured identity", ownerIds.length && knownOwners.length===ownerIds.length)],
      p=> p.size===3 ? "HIGH" : p.has("ownership-field")||p.has("ownership-map") ? "MEDIUM" : "LOW"),
    needed: "Confirm owner(o) at runtime; until then laws stay hypotheses" });
  const sensFieldsAll = Object.entries(resources).flatMap(([r,R])=>Object.entries(R.fields).filter(([,f])=>f.sensitivity==="PERSONAL"||f.sensitivity==="SENSITIVE").map(([p,f])=>({ ref:`${r}.${p}`, level:f.sensitivity, override:!!STATE.overrides[`${r}.${p}`] })));
  inf.push({ id:"INF-03", claim:"Private/sensitive fields identified",
    evidence:[`${sensFieldsAll.length} PERSONAL/SENSITIVE field(s), including nested and array fields`],
    ...rated([sig("found", `${sensFieldsAll.length} field(s) classified`, sensFieldsAll.length), sig("secret-level", "at least one SENSITIVE (credential/payment/secret) field", sensFieldsAll.some(f=>f.level==="SENSITIVE")), sig("analyst", "an analyst confirmed a classification", sensFieldsAll.some(f=>f.override))],
      p=> p.has("found")&&p.has("analyst") ? "HIGH" : p.has("found") ? "MEDIUM" : "LOW"),
    needed: "Analyst review of the name-based classification; runtime check that other identities cannot read them" });
  const prot = endpoints.filter(e=>e.auth).length, open = endpoints.length-prot, undeclared = endpoints.filter(e=>e.authInferred).length;
  const unknownSchemes = STATE.apiModel ? STATE.apiModel.endpoints.some(e=>e.auth.alternatives.some(a=>a.schemes.some(x=>!x.known))) : false;
  inf.push({ id:"INF-04", claim:"Authentication boundary mapped",
    evidence:[`${prot} protected, ${open} open${undeclared?` (${undeclared} with no security declared)`:""}`],
    ...rated([sig("endpoints", `${endpoints.length} endpoint(s)`, endpoints.length), sig("declared", "every endpoint declares its security", endpoints.length&&!undeclared), sig("schemes", "every referenced scheme is declared", endpoints.length&&!unknownSchemes)],
      p=> p.size===3 ? "HIGH" : p.has("endpoints") ? "MEDIUM" : "LOW"),
    needed: "Anonymous requests in Part 2 to confirm 401/403" });
  const adm = endpoints.filter(e=>e.action==="AdminAction").length;
  inf.push({ id:"INF-05", claim:"Admin role boundary exists",
    evidence: adm&&adminRole? [`${adm} admin endpoint(s), admin role '${adminRole}', roles [${roles.join(", ")}]`] : ["no admin endpoints or no admin role in the configuration"],
    ...rated([sig("admin-endpoints", `${adm} administrative endpoint(s)`, adm), sig("privileged-role", adminRole?`privileged role '${adminRole}' (name heuristic)`:"no privileged role", adminRole), sig("other-roles", `${baseRoles().length} non-privileged role(s)`, baseRoles().length)],
      p=> p.size===3 ? "HIGH" : p.has("admin-endpoints")&&p.has("privileged-role") ? "MEDIUM" : "LOW"),
    needed: adm&&adminRole? `Non-admin roles (${baseRoles().join(", ")||"none"}) must be denied on admin endpoints` : "N/A: no admin surface" });
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
  const baseId = ids.find(i=>bases.includes(i.role)) || ids[0] || { id:"(no identity configured)", name:"(no identity configured)", role:"" };
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
    { given:"unauthenticated", when:f.idGet?`${f.idGet.method} ${f.ownPair?fillObjectId(f.idGet.path,f.ownPair.id):f.idGet.path}`:"GET object", expect:"DENY (auth)" }];
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
  const owners = new Set(Object.values(cfgOwnership()).map(String));
  const adminEps = eps.filter(e=>e.action==="AdminAction");
  const checks = [
    { label:"Endpoints parsed from the spec", ok: eps.length>0, detail:`${eps.length} endpoint(s)` },
    { label:"Every endpoint declares a security requirement", ok: eps.length>0 && eps.every(e=>!e.authInferred), detail:`${eps.filter(e=>e.authInferred).length} without` },
    { label:"A resource has an ownership field", ok: owned>0, detail:`${owned} resource(s)` },
    { label:"Objects of at least two identities are configured", ok: owners.size>=2, detail:`${owners.size} owner(s)` },
    { label:"A privileged role exists for administrative endpoints", ok: !adminEps.length || !!detectAdminRole(), detail: adminEps.length ? (detectAdminRole()||"none configured") : "no admin endpoints" },
    { label:"Security laws generated", ok: laws.length>0, detail:`${laws.length} law(s)` },
  ];
  const readiness = Math.round(100*checks.filter(c=>c.ok).length/checks.length);
  return { endpoints:eps.length, resources:Object.keys(res).length, protected:prot, open, fields, sens, high, med, low, owned, readiness, checks, sandbox:STATE.sandbox.status,
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
    <p class="sub">Part-2 readiness: <b>${d.checks.filter(c=>c.ok).length}/${d.checks.length} checks (${d.readiness}%)</b> · sandbox: ${d.sandbox} · target: ${d.authorization} · admin role: ${d.adminRole||"none"} ${STATE.warnings.length?`· ⚠ ${STATE.warnings.length} warnings`:""}</p>
    <div class="bar"><i style="width:${d.readiness}%"></i></div>
    <ul class="sub readiness" data-testid="readiness-checks">${d.checks.map(c=>html`<li>${c.ok?"✅":"❌"} ${c.label} <span class="sub">(${c.detail})</span></li>`)}</ul>`);
}
function renderDiscovery(){
  const info = STATE.specInfo;
  const rows = STATE.endpoints.map(e=>html`<tr><td><code>${e.id}</code></td><td><code>${e.method}</code></td><td><code>${e.path}</code></td>
    <td>${authLabel(e)}<br><span class="sub">${e.authDetail}</span></td><td>${e.resource}</td><td>${e.action}</td>
    <td class="sub">${e.params.map(p=>`${p.name}(${p.in})`).join(", ")||"—"}${e.bodySchemaName?html`<br>body:${e.bodySchemaName}`:""}${e.respSchemaName?html`<br>resp:${e.respSchemaName}`:""}${e.bodyContentTypes.length?html`<br>consumes:${e.bodyContentTypes.join(", ")}`:""}</td></tr>`);
  setHtml($("discovery"), html`<p class="sub">${info.title?`${info.title} · `:""}${info.version||""} · ${STATE.endpoints.length} endpoints · servers: ${(info.servers||[]).join(", ")||"—"}</p>
    ${STATE.endpoints.length? html`<table><tr><th scope="col">ID</th><th scope="col">Method</th><th scope="col">Path</th><th scope="col">Auth</th><th scope="col">Resource</th><th scope="col">Action</th><th scope="col">Params/Body</th></tr>${rows}</table>` : html`<p class="sub">No endpoints yet.</p>`}
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
  setHtml($("identitymodel"), html`<table><tr><th scope="col">Role (from config)</th><th scope="col">Permissions (from config)</th></tr>${permRows.length?permRows:html`<tr><td colspan="2" class="sub">No permissions configured</td></tr>`}</table>
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
    <td><select data-r="${r}" data-f="${f}" aria-label="Sensitivity override for ${r+"."+f}"><option value="">auto</option>${LEVELS.map(o=>html`<option value="${o}"${o===current?html` selected`:""}>${o}</option>`)}</select></td></tr>`);
  }));
  if(!rows.length){ $("sensTable").textContent="—"; return; }
  setHtml($("sensTable"), html`<table><tr><th scope="col">Field</th><th scope="col">Level</th><th scope="col">Why</th><th scope="col">Override</th></tr>${rows}</table><div class="row"><button class="ghost" type="button" id="applySens">Apply overrides → rebuild</button></div>`);
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
  if(!twinView) twinView = createLazyTwinView($("twinGraph"));
  twinView.render(twinGraphInput());
  $("twinJson").textContent = STATE.twin ? JSON.stringify(STATE.twin,null,2) : "—";
}
function renderInferences(){
  setHtml($("inferences"), html`${STATE.inferences.map(i=>html`<div class="law"><h3>${i.id} <span class="badge b-${i.confidence}">${i.confidence} · ${i.score}% of signals</span></h3>
    <div>${i.claim}</div><div class="sub">Evidence: ${i.evidence.join(" · ")}</div><ul class="sub">${i.signals.map(x=>html`<li>${x.present?"✅":"❌"} ${x.description}</li>`)}</ul><div class="sub">To raise confidence: ${i.needed}</div></div>`)}`);
}
const CATEGORY_LABEL = { OBJECT_AUTHORIZATION:"Object authorization", FUNCTION_AUTHORIZATION:"Function authorization", DATA_EXPOSURE:"Data exposure",
  AUTHENTICATION:"Authentication", STATE_TRANSITION:"State transition", SECURITY_CONFIGURATION:"Security configuration" };
function endpointLabel(id){ const e=STATE.endpoints.find(x=>x.id===id); return e?`${id} ${e.method} ${e.path}`:id; }
function renderConstitution(){
  const c = STATE.constitution;
  if(!c){ $("laws").textContent="—"; return; }
  const counts = Object.keys(CATEGORY_LABEL).map(k=>[k, c.laws.filter(l=>l.category===k).length]).filter(([,n])=>n);
  const scopeRow = (label, items)=> items.length ? html`<div><b>${label}:</b> ${items.join(" · ")}</div>` : "";
  const cards = c.laws.map(l=>html`<details class="law const-law" data-testid="law-card" data-law="${l.id}">
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
      <div class="row"><button class="ghost" type="button" data-testid="law-focus" data-focus-law="${l.id}">Highlight scope in graph</button></div>
    </div></details>`);
  setHtml($("laws"), html`<p class="sub">${c.laws.length} laws · ${counts.map(([k,n])=>`${n} ${CATEGORY_LABEL[k].toLowerCase()}`).join(" · ")}</p>${cards}
    ${c.notes.length?html`<div class="note">${joinHtml(c.notes, html`<br>`)}</div>`:""}
    <div class="note">Laws are derived from the spec model and configuration. Confidence is computed from the listed evidence signals; test strategies are specifications, not executed tests.</div>`);
  document.querySelectorAll("#laws [data-focus-law]").forEach(b=>b.onclick=()=>focusLaw(b.dataset.focusLaw));
  renderLawFilters();
}
// ---------- Constitution Explorer: filter options come from the laws present; exports contain what is shown ----------
const LAW_FILTERS = [["lawCategory","category",l=>CATEGORY_LABEL[l]||l],["lawSeverity","severity",l=>l],["lawConfidence","confidence",l=>l]];
const LAW_CONTROLS = ["lawCategory","lawSeverity","lawConfidence","lawSearch","lawExportJson","lawExportMd","lawPrintPdf"];
function renderLawFilters(){
  const laws = STATE.constitution ? STATE.constitution.laws : [];
  for(const [id,key,label] of LAW_FILTERS){
    const sel=$(id), keep=sel.value, first=sel.options[0].textContent;
    const values=[...new Set(laws.map(l=>l[key]))];
    setHtml(sel, html`<option value="">${first}</option>${values.map(v=>html`<option value="${v}">${label(v)} (${laws.filter(l=>l[key]===v).length})</option>`)}`);
    sel.value = values.includes(keep) ? keep : "";
  }
  LAW_CONTROLS.forEach(id=>{ $(id).disabled = !laws.length; });
  applyLawFilter();
}
function currentLawFilter(){
  const one = id => $(id).value ? [$(id).value] : [];
  const f = { categories:one("lawCategory"), severities:one("lawSeverity"), confidences:one("lawConfidence"), text:$("lawSearch").value.trim() };
  return Object.fromEntries(Object.entries(f).filter(([,v])=>v.length));
}
function shownLaws(){ return STATE.constitution ? filterLaws(STATE.constitution.laws, currentLawFilter()) : []; }
function applyLawFilter(){
  const c = STATE.constitution;
  if(!c){ $("lawCount").textContent=""; return; }
  const shown = new Set(shownLaws().map(l=>l.id));
  document.querySelectorAll("#laws details.const-law").forEach(d=>{ d.hidden = !shown.has(d.dataset.law); });
  $("lawCount").textContent = shown.size===c.laws.length ? `Showing all ${c.laws.length} laws.` : `Showing ${shown.size} of ${c.laws.length} laws${shown.size?"":" (no law matches the filter)"}.`;
}
function exportLaws(format){
  const c = STATE.constitution; if(!c) return;
  const ctx = { specTitle: STATE.specInfo.title||null, specVersion: STATE.specInfo.version||null, generatedAt: new Date().toISOString(), filter: currentLawFilter() };
  if(format==="json") download("security-constitution.json", JSON.stringify(exportConstitutionJson(c, shownLaws(), ctx),null,2));
  else download("security-constitution.md", exportConstitutionMarkdown(c, shownLaws(), ctx), "text/markdown");
}
/** Everything the printable report needs, taken from the current model, configuration and explorer filter. */
function reportInput(){
  const c = STATE.constitution, d = STATE.dashboard, a = targetAuthorization();
  return { specTitle: STATE.specInfo.title||null, specVersion: STATE.specInfo.version||null, generatedAt: new Date().toISOString(),
    target: { label: a.label, detail: a.detail },
    summary: { endpoints: d.endpoints, resources: d.resources, fields: d.fields, sensitiveFields: d.sens, identities: d.identities, roles: d.roles },
    readiness: d.checks, laws: shownLaws(), totalLaws: c.laws.length, filter: currentLawFilter(), notes: c.notes, warnings: STATE.warnings };
}
function printReport(){
  if(!STATE.constitution||!STATE.dashboard){ showStatus($("reportStatus"), "empty", "Build the Security Twin first: the report is generated from the constitution."); return; }
  setHtml($("printReport"), renderConstitutionReport(reportInput()));
  document.body.classList.add("printing");
  showStatus($("reportStatus"), "success", `Report ready (${shownLaws().length} of ${STATE.constitution.laws.length} laws). Choose "Save as PDF" as the printer to get a PDF.`);
  try{ window.print(); }catch(e){ showStatus($("reportStatus"), "error", `Printing is not available here (${e.message}).`); }
}
function focusLaw(id){
  document.querySelectorAll("#laws details.const-law").forEach(d=>d.classList.toggle("is-focused", d.dataset.law===id));
  if(twinView) twinView.focusLaw(id);
  const g=$("twinGraph"); if(g&&g.scrollIntoView) g.scrollIntoView({ behavior: window.matchMedia&&window.matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth", block:"center" });
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
  if(!r.ok){ showStatus($("buildStatus"), "error", "Invalid spec: the model could not be rebuilt.", { details:r.errors }); return; }
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
  persistWorkspace();
}
function build(){
  const txt = $("swaggerText").value.trim();
  STATE.baseUrl = $("baseUrl").value.trim();
  if(!txt){ showStatus($("buildStatus"), "empty", "No spec yet: paste an OpenAPI 3.x / Swagger 2.0 spec (JSON or YAML), upload one, or load the demo."); return; }
  const check = analyzeSpecText(txt);
  if(!check.ok){ showStatus($("buildStatus"), "error", STATE.constitution ? "Invalid spec: not rebuilt. The results below are from the previous successful build." : "Invalid spec: nothing was built.", { details:check.errors }); return; }
  try{ STATE.config = parseConfigEditors(); }catch(e){ showStatus($("buildStatus"), "error", `Invalid configuration: ${e.message}`); return; }
  STATE.specText = txt;
  rebuild();
  if(STATE.constitution) showStatus($("buildStatus"), "success", builtSummary());
}
/** One line describing what the last build produced, for the status area. */
function builtSummary(){ return `Built from the spec: ${STATE.endpoints.length} endpoints, ${Object.keys(STATE.resources).length} resources, ${STATE.constitution.laws.length} laws${STATE.warnings.length?`, ${STATE.warnings.length} warning(s)`:""}.`; }
function download(name, text, type="application/json"){ const a=document.createElement("a"); a.href=URL.createObjectURL(new Blob([text],{type})); a.download=name; a.click(); setTimeout(()=>URL.revokeObjectURL(a.href), 0); }
// Connectivity check: one GET, only to hosts the target policy accepts (never public internet hosts).
async function testSandbox(){
  const url = $("baseUrl").value.trim();
  const box = $("sandboxStatus");
  if(!url){ setHtml(box, html`<span class="warn">Enter Sandbox Base URL first.</span>`); return; }
  const a = assessTargetHost(url);
  if(!a.registrable){
    STATE.sandbox = { status:"refused", url };
    setHtml(box, html`<span class="warn" role="alert" data-testid="connection-refused">● Not tested: ${a.reason}</span>`);
    if(STATE.dashboard){ STATE.dashboard = buildDashboard(); renderDashboard(); renderOutputs(); }
    return;
  }
  setHtml(box, html`<span role="status">Testing ${a.baseUrl}…</span>`);
  const t0 = performance.now();
  try{
    const ctl = new AbortController(); const to = setTimeout(()=>ctl.abort(), 8000);
    const r = await fetch(a.baseUrl, { method:"GET", signal:ctl.signal, mode:"cors", credentials:"omit", redirect:"error" });
    clearTimeout(to);
    const ms = Math.round(performance.now()-t0);
    STATE.sandbox = { status: r.ok?"reachable":"http-"+r.status, ms, url:a.baseUrl };
    setHtml(box, html`<span class="ok">● Sandbox (${a.hostClass}): HTTP ${r.status} in ${ms}ms</span><br><span class="sub">One GET, no credentials, redirects refused. Reachability is not authorization.</span>`);
  }catch(e){
    const ms = Math.round(performance.now()-t0);
    STATE.sandbox = { status:"unreachable:"+String(e.name||e.message), ms, url:a.baseUrl };
    setHtml(box, html`<span class="warn" role="alert">● Unreachable, redirected or blocked by CORS (${e.name||"error"}) in ${ms}ms. The twin still builds from the spec.</span> <button class="ghost" type="button" id="retryConn">Retry</button>`);
    $("retryConn").onclick = testSandbox;
  }
  if(STATE.dashboard){ STATE.dashboard = buildDashboard(); renderDashboard(); renderOutputs(); }
}

async function loadDemo(){
  const box = $("buildStatus");
  showStatus(box, "loading", "Loading the demo spec and configuration…");
  try{
    const [spec, cfgText] = await Promise.all([fetchText("samples/sample-swagger.json"), fetchText("samples/sample-config.json")]);
    const cfg = JSON.parse(cfgText);
    $("swaggerText").value = spec;
    $("identitiesEditor").value = JSON.stringify(cfg.identities,null,2);
    $("permissionsEditor").value = JSON.stringify(cfg.permissions,null,2);
    $("ownershipEditor").value = JSON.stringify(cfg.ownership,null,2);
    if(!$("baseUrl").value){ const a=analyzeSpecText(spec); if(a.ok&&a.view.specInfo.servers[0]) $("baseUrl").value=a.view.specInfo.servers[0]; }
    renderTargetAuth();
    showStatus(box, "success", "Demo spec and configuration loaded. Next: BUILD SECURITY TWIN.");
  }catch(e){
    showStatus(box, "error", `Could not load the demo: ${e.message}`, { retry: loadDemo });
  }
}

// ---------- opt-in persistence (this browser only; spec, configuration, URL and overrides; never credentials) ----------
const workspaceStore = createWorkspaceStore(()=>window.localStorage);
function currentWorkspace(){
  return { specText:$("swaggerText").value, identities:$("identitiesEditor").value, permissions:$("permissionsEditor").value,
    ownership:$("ownershipEditor").value, baseUrl:$("baseUrl").value.trim(), overrides:{ ...STATE.overrides } };
}
function persistWorkspace(){
  if(!$("rememberChk").checked) return;
  const r = workspaceStore.save(currentWorkspace(), new Date().toISOString());
  if(r.ok) showStatus($("persistStatus"), "success", `Saved in this browser at ${r.savedAt}.`);
  else showStatus($("persistStatus"), "error", `Not saved: ${r.message}.`);
}
function restoreWorkspace(){
  if(!workspaceStore.remembered()) return;
  $("rememberChk").checked = true;
  const r = workspaceStore.load();
  if(r.ok){
    const d = r.data;
    $("swaggerText").value = d.specText; $("identitiesEditor").value = d.identities; $("permissionsEditor").value = d.permissions;
    $("ownershipEditor").value = d.ownership; $("baseUrl").value = d.baseUrl; STATE.overrides = { ...d.overrides };
    showStatus($("persistStatus"), "success", `Restored the spec and configuration saved in this browser at ${d.savedAt}. Next: BUILD SECURITY TWIN.`);
  } else if(r.reason==="corrupt"){
    workspaceStore.clear(); $("rememberChk").checked = false;
    showStatus($("persistStatus"), "error", "The saved data could not be read and was removed.");
  } else if(r.reason==="unavailable"){
    showStatus($("persistStatus"), "info", "Browser storage is not available here; nothing was restored.");
  }
}

window.addEventListener("DOMContentLoaded", ()=>{
  $("buildBtn").onclick = build;
  $("testBtn").onclick = testSandbox;
  $("applyConfig").onclick = ()=>{
    try{ STATE.config = parseConfigEditors(); }catch(e){ showStatus($("applyStatus"), "error", `Invalid configuration: ${e.message}`); return; }
    if(!STATE.endpoints.length){ showStatus($("applyStatus"), "empty", "Nothing to apply yet: build the Security Twin first."); return; }
    rebuild();
    if(STATE.constitution) showStatus($("applyStatus"), "success", `Configuration applied. ${builtSummary()}`);
  };
  $("demoBtn").onclick = loadDemo;
  $("baseUrl").addEventListener("input", ()=>{
    renderTargetAuth();
    if(STATE.dashboard){ STATE.dashboard = buildDashboard(); renderDashboard(); }
  });
  restoreWorkspace();
  renderTargetAuth();
  $("rememberChk").addEventListener("change", e=>{
    if(e.target.checked) persistWorkspace();
    else { workspaceStore.clear(); showStatus($("persistStatus"), "info", "Saved data removed from this browser; nothing will be remembered."); }
  });
  $("clearSaved").onclick = ()=>{ workspaceStore.clear(); $("rememberChk").checked = false; showStatus($("persistStatus"), "success", "Saved data removed from this browser."); };
  $("uploadBtn").onclick = ()=>$("fileInput").click();
  $("fileInput").addEventListener("change", e=>{
    const f=e.target.files[0]; if(!f) return;
    const rd=new FileReader();
    showStatus($("buildStatus"), "loading", `Reading ${f.name}…`);
    rd.onload=()=>{ $("swaggerText").value=rd.result; showStatus($("buildStatus"), "success", `Loaded ${f.name} (${(f.size/1024).toFixed(1)} KiB). Next: BUILD SECURITY TWIN.`); };
    rd.onerror=()=>showStatus($("buildStatus"), "error", `Could not read ${f.name}: ${rd.error?rd.error.message:"unknown error"}`);
    rd.readAsText(f);
  });
  ["lawCategory","lawSeverity","lawConfidence"].forEach(id=>$(id).addEventListener("change", applyLawFilter));
  $("lawSearch").addEventListener("input", applyLawFilter);
  $("lawExportJson").onclick=()=>exportLaws("json");
  $("lawExportMd").onclick=()=>exportLaws("md");
  $("lawPrintPdf").onclick = printReport;
  window.addEventListener("afterprint", ()=>document.body.classList.remove("printing"));
  $("dl4").onclick=()=>download("testable-security-model.json",$("out4").textContent);
  $("copy4").onclick=async()=>{
    try{ await copyText($("out4").textContent); showStatus($("exportStatus"), "success", "Testable Security Model copied. Paste it into Part 2."); }
    catch(e){ showStatus($("exportStatus"), "error", `Copy failed (${e.message}). Use Download JSON instead.`); }
  };
});
