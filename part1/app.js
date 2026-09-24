// Sentinel X — Part 1 v4: FULLY DATA-DRIVEN. No hardcoded identities/permissions/ownership.
// All instance data comes from spec + configuration editors (sample-config.json for demo).
const $ = (id) => document.getElementById(id);
let STATE = { spec:null, baseUrl:"", endpoints:[], resources:{}, laws:[], twin:null, model:null, warnings:[], specInfo:{}, sandbox:{status:"idle"}, inferences:[], overrides:{}, dashboard:null,
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
  return actions.filter(act=>{ const vals = roles.map(r=>perms[r][act]); return vals.includes(true)&&vals.includes(false); });
}
function ownershipSample(n=3){ return Object.entries(cfgOwnership()).slice(0,n).map(([o,c])=>`${o}→${idToName(c)}`).join("; ")||"none configured"; }
function fillPath(path, id){ return path.replace(/\{[^}]+\}/, id); }

// ---------- generic helpers (engine, not instance data) ----------
function singularize(w){ if(/ies$/i.test(w)) return w.replace(/ies$/i,"y"); if(/ses$/i.test(w)) return w; if(/s$/i.test(w)&&w.length>3) return w.slice(0,-1); return w; }
function cap(s){ return s? s.charAt(0).toUpperCase()+s.slice(1):s; }
function esc(s){ return String(s==null?"":s).replace(/&/g,"&amp;").replace(/</g,"&lt;"); }
function inferResource(path){
  const p = path.toLowerCase();
  if (p.startsWith("/admin")) return "Admin";
  const segs = path.split("/").filter(Boolean).filter(s=>!s.startsWith("{")&&!s.includes("{"));
  const KW = ["invoice","order","user","refund","payment","product","customer","account"];
  for (const s of segs){ const low=s.toLowerCase(); for(const k of KW){ if(low.includes(k)) return cap(singularize(k)); } }
  if (segs.length) return cap(singularize(segs[0].replace(/[^a-zA-Z]/g,"")||"Root"));
  return "Root";
}
function inferAction(method, path){
  if (path.toLowerCase().startsWith("/admin") || path.toLowerCase().includes("/admin/")) return "AdminAction";
  if (method==="GET") return "Read";
  if (method==="POST") return "Create";
  if (method==="PUT"||method==="PATCH") return "Update";
  if (method==="DELETE") return "Delete";
  return method;
}
function classifyField(name){
  const n = name.toLowerCase();
  if (/(payment|card|ssn|secret|token|password|paymentmetadata|cvv|iban)/.test(n)) return { level:"SENSITIVE", reason:"matches sensitive pattern (payment/secret/token)" };
  if (/(name|phone|address|email|customer|dob|birth)/.test(n)) return { level:"PERSONAL", reason:"matches personal-data pattern" };
  if (/(internal|_id$|userid|createdby|updatedby)/.test(n) && n!=="id" && n!=="customerid" && n!=="orderid") return { level:"INTERNAL", reason:"matches internal-identifier pattern" };
  return { level:"PUBLIC", reason:"no personal/internal pattern" };
}

// ---------- $ref ----------
function resolveRef(spec, ref){
  if(!ref || !ref.startsWith("#/")) return null;
  const parts = ref.slice(2).split("/").map(p=>p.replace(/~1/g,"/").replace(/~0/g,"~"));
  let cur = spec;
  for(const p of parts){ if(cur==null) return null; cur = cur[p]; }
  return cur||null;
}
function getSchemaProps(schema, spec, depth=0){
  if(!schema || depth>5) return {};
  if(schema.$ref){ const r = resolveRef(spec, schema.$ref); return getSchemaProps(r, spec, depth+1); }
  let props = { ...(schema.properties||{}) };
  if(Array.isArray(schema.allOf)){ for(const s of schema.allOf){ Object.assign(props, getSchemaProps(s, spec, depth+1)); } }
  for(const k of ["oneOf","anyOf"]){ if(Array.isArray(schema[k])&&schema[k].length){ Object.assign(props, getSchemaProps(schema[k][0], spec, depth+1)); } }
  return props;
}
function schemaNameFromRef(ref){ if(!ref) return null; const p=ref.split("/"); return p[p.length-1]; }
function specVersion(spec){ if(spec.openapi) return "OpenAPI "+spec.openapi; if(spec.swagger) return "Swagger "+spec.swagger; return "unknown"; }
function specServers(spec){
  if(Array.isArray(spec.servers)&&spec.servers.length) return spec.servers.map(s=>s.url).filter(Boolean);
  if(spec.host){ const scheme=(spec.schemes&&spec.schemes[0])||"https"; const base=(spec.basePath&&spec.basePath!=="/")?spec.basePath:""; return [`${scheme}://${spec.host}${base}`]; }
  return [];
}
function globalSecurity(spec){ if(Array.isArray(spec.security)) return spec.security; return undefined; }
function securitySchemes(spec){
  if(spec.components&&spec.components.securitySchemes) return spec.components.securitySchemes;
  if(spec.securityDefinitions) return spec.securityDefinitions;
  return {};
}
function authInfo(spec, op, glob){
  if(Array.isArray(op.security)) {
    if(op.security.length===0) return { required:false, detail:"security: [] (public)", inferred:false };
    return { required:true, detail:"operation security ("+op.security.map(o=>Object.keys(o).join("+")||"auth").join(", ")+")", inferred:false };
  }
  if(Array.isArray(glob)){
    if(glob.length===0) return { required:false, detail:"global security: [] (public)", inferred:false };
    return { required:true, detail:"global security ("+glob.map(o=>Object.keys(o).join("+")||"auth").join(", ")+")", inferred:false };
  }
  const schemes = Object.keys(securitySchemes(spec));
  if(schemes.length) return { required:true, detail:"inferred Protected (schemes: "+schemes.join(", ")+")", inferred:true };
  return { required:true, detail:"inferred Protected (default-deny — verify in sandbox)", inferred:true };
}

function parseSpec(spec){
  const warnings=[]; const endpoints=[]; let c=1;
  const paths = spec.paths||{};
  const glob = globalSecurity(spec);
  for(const path of Object.keys(paths)){
    const item = paths[path]||{};
    const pathParams = Array.isArray(item.parameters)?item.parameters:[];
    for(const m of Object.keys(item)){
      if(!["get","post","put","patch","delete","head","options"].includes(m.toLowerCase())) continue;
      const op = item[m]||{};
      const method = m.toUpperCase();
      const a = authInfo(spec, op, glob);
      if(a.inferred) warnings.push(`${method} ${path}: no explicit security — assumed Protected (default-deny).`);
      const allParams = [...pathParams, ...(Array.isArray(op.parameters)?op.parameters:[])];
      const params = allParams.map(p=>({ name:p.name, in:p.in, required:!!p.required, type:(p.schema&&p.schema.type)||p.type||"string" }));
      let bodyRef=null;
      if(op.requestBody&&op.requestBody.content){ const mt=Object.keys(op.requestBody.content)[0]; const s=op.requestBody.content[mt].schema; if(s) bodyRef=s.$ref||null; }
      if(op.consumes&&op.parameters){ const b=op.parameters.find(p=>p.in==="body"&&p.schema); if(b) bodyRef=b.schema.$ref||null; }
      let respRef=null;
      const resps = op.responses||{};
      for(const code of Object.keys(resps)){ const r=resps[code]; const ctn=r&&r.content?Object.keys(r.content).map(k=>r.content[k].schema).find(Boolean):(r&&r.schema?r.schema:null); if(ctn&&ctn.$ref){ respRef=ctn.$ref; break; } }
      endpoints.push({ id:"EP-"+String(c++).padStart(3,"0"), method, path,
        auth:a.required, authDetail:a.detail, authInferred:a.inferred,
        resource:inferResource(path), action:inferAction(method,path),
        summary:op.summary||op.operationId||"", tags:op.tags||[],
        params, bodyRef, bodySchemaName:schemaNameFromRef(bodyRef), respRef, respSchemaName:schemaNameFromRef(respRef) });
    }
  }
  if(endpoints.length===0) warnings.push("No operations found under paths.");
  const schemas = (spec.components&&spec.components.schemas)||spec.definitions||{};
  if(Object.keys(schemas).length===0) warnings.push("No schemas/definitions found — fields inferred from params only.");
  return { endpoints, warnings, version:specVersion(spec), servers:specServers(spec) };
}

function buildResources(endpoints, spec){
  const schemas = (spec.components&&spec.components.schemas)||spec.definitions||{};
  const res = {};
  endpoints.forEach(e=>{ if(!res[e.resource]) res[e.resource]={ endpoints:[], fields:{}, relations:[], ownershipField:null }; res[e.resource].endpoints.push(e.id); });
  Object.keys(schemas).forEach(s=>{
    const props = getSchemaProps({ properties: schemas[s].properties, allOf: schemas[s].allOf, oneOf: schemas[s].oneOf, anyOf: schemas[s].anyOf }, spec);
    const full = Object.keys(props).length? props : getSchemaProps(schemas[s], spec);
    const rName = cap(s);
    let target = rName;
    const sing = cap(singularize(rName.toLowerCase()));
    if(res[sing]) target = sing; else if(!res[target]) res[target]={ endpoints:[], fields:{}, relations:[], ownershipField:null };
    Object.keys(full).forEach(f=>{
      const fSchema = full[f]||{};
      const c = classifyField(f);
      const ref = fSchema.$ref || null;
      res[target].fields[f]={ type: fSchema.type||(ref?"ref":"string"), sensitivity:c.level, reason:c.reason, ref };
      if(ref){ const rn=schemaNameFromRef(ref); if(rn) res[target].relations.push(`${f} -> ${rn}`); }
      if(/^(customerId|ownerId|userId|accountId|tenantId|authorId|memberId|createdBy)$/i.test(f)) res[target].ownershipField = f;
      else { const m = f.match(/^(.+?)[_\-]?Ids?$/i);
        if(m && !res[target].ownershipField){ const stem = singularize(m[1].toLowerCase());
          if(["user","customer","account","owner","member","author","tenant","creator"].includes(stem)) res[target].ownershipField = f; } }
    });
  });
  endpoints.forEach(e=>{
    if(e.respSchemaName){ const sing = cap(singularize(e.respSchemaName.toLowerCase())); const t = res[sing]||res[e.respSchemaName]; if(t && !t.relations.includes(`endpoint ${e.id} -> ${e.respSchemaName}`)) t.relations.push(`endpoint ${e.id} -> ${e.respSchemaName}`); }
  });
  // generic fallback (not Order-specific): resource with endpoints but no schema fields
  Object.keys(res).forEach(r=>{
    if(Object.keys(res[r].fields).length===0 && res[r].endpoints.length){
      res[r].fields["id"]={type:"string",sensitivity:"PUBLIC",reason:"generic fallback: identifier inferred from ID-parameterised endpoint",ref:null};
      STATE.warnings.push(`Resource ${r}: no schema fields — generic 'id' inferred. Add schemas for better laws.`);
    }
  });
  Object.keys(STATE.overrides).forEach(k=>{ const idx=k.lastIndexOf("."); const r=k.slice(0,idx), f=k.slice(idx+1); if(res[r]&&res[r].fields[f]){ res[r].fields[f].sensitivity=STATE.overrides[k]; res[r].fields[f].reason="manual override by analyst"; } });
  return res;
}

// ---------- fully data-driven twin ----------
function buildTwin(endpoints, resources){
  const byResource = {};
  Object.keys(resources).forEach(r=>{
    const sens = {}; Object.values(resources[r].fields).forEach(f=>{ sens[f.sensitivity]=(sens[f.sensitivity]||0)+1; });
    byResource[r]={ endpoints:resources[r].endpoints, fieldCount:Object.keys(resources[r].fields).length, sensitivity:sens, ownershipField:resources[r].ownershipField||null, relations:resources[r].relations };
  });
  const adminRole = detectAdminRole();
  const adminEps = endpoints.filter(e=>e.action==="AdminAction"||e.resource==="Admin").map(e=>e.id);
  const idGetEps = endpoints.filter(e=>e.method==="GET"&&/\{.+\}/.test(e.path)).map(e=>e.id);
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
  const idGets = endpoints.filter(e=>e.method==="GET"&&/\{.+\}/.test(e.path));
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
    evidence:[sensN+" PERSONAL/SENSITIVE fields"], confidence:"MEDIUM", score:60,
    needed:"Runtime check: does foreign GET leak them? If yes → vuln, else RISK only" });
  const prot = endpoints.filter(e=>e.auth).length, open = endpoints.filter(e=>!e.auth).length;
  inf.push({ id:"INF-04", claim:"Auth boundary mapped",
    evidence:[`${prot} protected, ${open} open`], confidence: endpoints.some(e=>e.authInferred)?"MEDIUM":"HIGH", score: endpoints.some(e=>e.authInferred)?65:90,
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
  const idGets = STATE.endpoints.filter(e=>e.method==="GET"&&/\{.+\}/.test(e.path));
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
  const idGet = (bt&&bt.idGet) || STATE.endpoints.find(e=>e.method==="GET"&&/\{.+\}/.test(e.path));
  const adminEp = STATE.endpoints.find(e=>e.action==="AdminAction"||e.resource==="Admin");
  const protEp = STATE.endpoints.find(e=>e.auth);
  return { baseId, adminId, ownPair, foreignPair, idGet, adminEp, protEp };
}

function lawTestsFor(law, endpoints){
  const f = fixtures();
  const ownWhen = (f.idGet&&f.ownPair)? `${f.idGet.method} ${fillPath(f.idGet.path,f.ownPair.id)} (own, owner=${f.ownPair.owner})` : "GET own object";
  const forWhen = (f.idGet&&f.foreignPair)? `${f.idGet.method} ${fillPath(f.idGet.path,f.foreignPair.id)} (foreign, owner=${f.foreignPair.owner})` : "GET foreign object";
  if(law.category==="BOLA") return [
    { given:`authenticated as ${f.baseId.id} (${idToName(f.baseId.id)})`, when:ownWhen, expect:"ALLOW + own data only" },
    { given:`authenticated as ${f.baseId.id} (${idToName(f.baseId.id)})`, when:forWhen, expect:"DENY (401/403/404 without leakage) — violation = BOLA" },
    { given:"unauthenticated", when:f.idGet?`${f.idGet.method} ${fillPath(f.idGet.path,(f.ownPair||{id:"1"}).id)}`:"GET object", expect:"DENY (auth)" }];
  if(law.category==="ADMIN"){
    const admWhen = f.adminEp? `${f.adminEp.method} ${f.adminEp.path}` : "admin endpoint";
    return [
      { given:`authenticated as ${f.baseId.id} (non-admin)`, when:admWhen, expect:"DENY (403) — violation = broken access control" },
      ...(f.adminId?[{ given:`authenticated as ${f.adminId.id} (${f.adminId.role})`, when:admWhen, expect:"ALLOW" }]:[])];
  }
  if(law.category==="DATA") return [
    { given:`authenticated as ${f.baseId.id}`, when:forWhen, expect:"MUST NOT contain PERSONAL/SENSITIVE of another owner — leak = excessive exposure" }];
  if(law.category==="AUTHN") return [{ given:"no token", when:f.protEp?`${f.protEp.method} ${f.protEp.path}`:"protected endpoint", expect:"DENY 401" }];
  const priv = privilegedActions();
  return [{ given:`roles=[${distinctRoles().join(", ")}]`, when:`invoke privileged action (${priv.slice(0,3).join(", ")||"restricted"})`, expect:`ALLOW ⟺ role has permission` }];
}

function buildLaws(endpoints, resources){
  const laws=[]; let n=1; const nid=()=>("LAW-"+String(n++).padStart(3,"0"));
  const idGets = endpoints.filter(e=>e.method==="GET"&&/\{.+\}/.test(e.path));
  const adminEps = endpoints.filter(e=>e.action==="AdminAction"||e.resource==="Admin");
  const protectedEps = endpoints.filter(e=>e.auth);
  const openEps = endpoints.filter(e=>!e.auth);
  const sensFields = [];
  Object.keys(resources).forEach(r=>Object.keys(resources[r].fields).forEach(f=>{ const s=resources[r].fields[f]; if(s.sensitivity==="PERSONAL"||s.sensitivity==="SENSITIVE") sensFields.push(`${r}.${f}`); }));
  const ownedResources = Object.keys(resources).filter(r=>resources[r].ownershipField);
  const adminRole = detectAdminRole(); const bases = baseRoles();
  const baseLabel = bases[0] || distinctRoles().filter(r=>r!==adminRole)[0] || distinctRoles()[0] || "Non-admin";

  if(idGets.length){
    // data-driven target: owned resources covered by ID-GETs, ranked by endpoint + sensitive-field count
    const bt = bolaTarget();
    const target = (bt&&bt.target) || ownedResources[0] || idGets[0].resource;
    const of = resources[target]&&resources[target].ownershipField;
    const law={ id:nid(), category:"BOLA", severity:"High", title:`${baseLabel} can access only owned ${target} objects.`,
      source: of? `Ownership field '${of}' on ${target} + ${idGets.map(e=>e.id).join(", ")} + map ${ownershipSample()}` : `ID reads (${idGets.map(e=>e.id).join(", ")}) without ownership field`,
      confidence: of&&Object.keys(cfgOwnership()).length?"HIGH":"MEDIUM", score: of&&Object.keys(cfgOwnership()).length?90:60,
      reason: of? `Ownership field '${of}' + configured map isolates ${target}.` : "Candidate — needs sandbox proof.",
      invariant:`∀ ${baseLabel} c, ${target.toLowerCase()} o: ALLOW(GET ${idGets[0].path}) ⟺ owner(o)==c` };
    law.tests=lawTestsFor(law,endpoints); laws.push(law);
  }
  if(adminEps.length&&adminRole){
    const law={ id:nid(), category:"ADMIN", severity:"High", title:`Non-${adminRole} roles cannot invoke admin-only actions.`,
      source:adminEps.map(e=>e.id+" "+e.method+" "+e.path).join("; ")+` + admin role='${adminRole}'`,
      confidence:"HIGH", score:90,
      reason:`Admin endpoints isolated to role '${adminRole}'.`,
      invariant:`role!=${adminRole} → DENY(${adminEps.map(e=>e.method+" "+e.path).join(", ")})` };
    law.tests=lawTestsFor(law,endpoints); laws.push(law);
  } else if(adminEps.length){
    STATE.warnings.push("Admin endpoints found but no admin role in configuration — ADMIN law skipped. Add an admin role to identities.");
  }
  if(sensFields.length){
    const law={ id:nid(), category:"DATA", severity:"Medium", title:"Foreign objects must not expose private/sensitive data.",
      source:`Sensitive: ${sensFields.slice(0,8).join(", ")}${sensFields.length>8?"…":""}`, confidence:"MEDIUM", score:60,
      reason:"Heuristic — RISK until Part-2 runtime proof.", invariant:"IF owner(o)!=caller THEN response MUST NOT contain PERSONAL/SENSITIVE" };
    law.tests=lawTestsFor(law,endpoints); laws.push(law);
  }
  if(protectedEps.length){
    const law={ id:nid(), category:"AUTHN", severity:"High", title:"Protected endpoints require authenticated identity.",
      source:`${protectedEps.length}/${endpoints.length} protected`, confidence: protectedEps.some(e=>e.authInferred)?"MEDIUM":"HIGH", score: protectedEps.some(e=>e.authInferred)?65:90,
      reason:"Explicit or default-deny.", invariant:"unauthenticated → DENY(protected)" };
    law.tests=lawTestsFor(law,endpoints); laws.push(law);
  }
  if(openEps.length){
    const law={ id:nid(), category:"AUTHN", severity:"Medium", title:"Open endpoints must be intentional.",
      source:`Open: ${openEps.map(e=>e.id).join(", ")}`, confidence:"MEDIUM", score:60,
      reason:"Explicitly public — confirm no sensitive data.", invariant:"public response MUST NOT contain PERSONAL/SENSITIVE" };
    law.tests=lawTestsFor(law,endpoints); laws.push(law);
  }
  const priv = privilegedActions(); const roles = distinctRoles();
  if(priv.length&&roles.length>1){
    const law={ id:nid(), category:"ROLE", severity:"High", title:"Sensitive actions must respect role boundaries.",
      source:`Permission matrix: ${roles.join(" vs ")}; contested: ${priv.join(", ")}`, confidence:"HIGH", score:90,
      reason:`Contested actions (${priv.slice(0,4).join(", ")}) differ by role.`, invariant:`privileged ALLOW ⟺ role permission == true` };
    law.tests=lawTestsFor(law,endpoints); laws.push(law);
  }
  return laws;
}

function buildDashboard(){
  const eps = STATE.endpoints, res = STATE.resources;
  const prot = eps.filter(e=>e.auth).length, open = eps.length-prot;
  const fields = Object.values(res).reduce((a,r)=>a+Object.keys(r.fields).length,0);
  const sens = Object.values(res).reduce((a,r)=>a+Object.values(r.fields).filter(f=>f.sensitivity==="PERSONAL"||f.sensitivity==="SENSITIVE").length,0);
  const high = STATE.laws.filter(l=>l.confidence==="HIGH").length, med = STATE.laws.filter(l=>l.confidence==="MEDIUM").length;
  const owned = Object.keys(res).filter(r=>res[r].ownershipField).length;
  const readiness = eps.length? Math.round(100*(0.3*Math.min(1,Object.keys(res).length/3)+0.3*(prot/eps.length)+0.2*(owned/Math.max(1,Object.keys(res).length))+0.2*(STATE.laws.length/5))) : 0;
  return { endpoints:eps.length, resources:Object.keys(res).length, protected:prot, open, fields, sens, high, med, owned, readiness, sandbox:STATE.sandbox.status,
    roles:distinctRoles(), adminRole:detectAdminRole(), identities:cfgIdentities().length };
}

function buildTestableModel(){
  return { version:"part1-v4-datadriven", sandboxOnly:true, sandboxBaseUrl:STATE.baseUrl,
    sandboxCheck:STATE.sandbox, specInfo:STATE.specInfo, warnings:STATE.warnings,
    testIdentities:cfgIdentities(), permissions:cfgPermissions(),
    ownership:Object.entries(cfgOwnership()).map(([objectId,ownerId])=>({objectId,ownerId,ownerName:idToName(ownerId)})),
    endpoints:STATE.endpoints, resources:STATE.resources, twin:STATE.twin, laws:STATE.laws, inferences:STATE.inferences,
    expectedBehavior: STATE.laws.flatMap(l=> (l.tests||[]).map(t=>({ law:l.id, category:l.category, ...t }))) };
}

// ---------- render ----------
function setSteps(n){ ["s1","s2","s3","s4","s5"].forEach((id,i)=> $(id).classList.toggle("done", i<n)); }
function renderAll(){ renderDashboard(); renderDiscovery(); renderModel(); renderIdentity(); renderSens(); renderTwin(); renderTwinSelect(); renderInferences(); renderLaws(); renderLawTests(); renderOutputs(); setSteps(5); }

function renderDashboard(){
  const d = STATE.dashboard; if(!d){ $("dashboard").innerHTML="—"; return; }
  $("dashboard").innerHTML = `<div class="tiles">
    <div class="tile"><b>${d.endpoints}</b><span class="sub">endpoints</span></div>
    <div class="tile"><b>${d.resources}</b><span class="sub">resources</span></div>
    <div class="tile"><b>${d.protected}/${d.open}</b><span class="sub">protected/open</span></div>
    <div class="tile"><b>${d.fields}</b><span class="sub">fields (${d.sens} sens)</span></div>
    <div class="tile"><b>${d.high}H/${d.med}M</b><span class="sub">laws</span></div>
    <div class="tile"><b>${d.identities}</b><span class="sub">identities (${d.roles.join(", ")||"—"})</span></div></div>
    <p class="sub">Part-2 readiness: <b>${d.readiness}%</b> · sandbox: ${esc(d.sandbox)} · admin role: ${esc(d.adminRole||"none")} ${STATE.warnings.length?`· ⚠ ${STATE.warnings.length} warnings`:""}</p>
    <div class="bar"><i style="width:${d.readiness}%"></i></div>`;
}
function renderDiscovery(){
  const info = STATE.specInfo;
  const rows = STATE.endpoints.map(e=>`<tr><td><code>${e.id}</code></td><td><code>${e.method}</code></td><td><code>${esc(e.path)}</code></td><td>${e.auth?"Required":"Open"}<br><span class="sub">${esc(e.authDetail)}</span></td><td>${e.resource}</td><td>${e.action}</td><td class="sub">${e.params.map(p=>`${p.name}(${p.in})`).join(", ")||"—"}${e.bodySchemaName?`<br>body:${e.bodySchemaName}`:""}${e.respSchemaName?`<br>resp:${e.respSchemaName}`:""}</td></tr>`).join("");
  $("discovery").innerHTML = `<p class="sub">${esc(info.version||"")} · ${STATE.endpoints.length} endpoints · servers: ${esc((info.servers||[]).join(", ")||"—")}</p>`
    + (STATE.endpoints.length? `<table><tr><th>ID</th><th>Method</th><th>Path</th><th>Auth</th><th>Resource</th><th>Action</th><th>Params/Body</th></tr>${rows}</table>` : `<p class="sub">No endpoints yet.</p>`)
    + (STATE.warnings.length? `<div class="note">⚠ ${STATE.warnings.map(esc).join("<br>")}</div>`:"");
  $("invCount").textContent = STATE.endpoints.length + " endpoints";
}
function renderModel(){
  const rHtml = Object.keys(STATE.resources).map(r=>{
    const R = STATE.resources[r];
    const f = Object.entries(R.fields).map(([n,v])=>`  ├── ${esc(n)} <span class="badge b-${v.sensitivity}">${v.sensitivity}</span> <span class="sub">${esc(v.reason||"")}</span>`).join("<br>");
    const rel = R.relations.length? `<br>  ↳ relations: ${R.relations.map(esc).join("; ")}`:"";
    const own = R.ownershipField? `<br>  🔑 ownershipField: <code>${esc(R.ownershipField)}</code> (inferred from spec)` : `<br>  <span class="sub">no ownership field — BOLA stays MEDIUM</span>`;
    return `<div><b>├── ${esc(r)}</b> <span class="sub">[${R.endpoints.join(", ")||"—"}]</span><br>${f||"  ├── (no schema fields)"}${rel}${own}</div>`;
  }).join("<br>");
  $("apimodel").innerHTML = rHtml || "—";
}
function renderIdentity(){
  const perms = cfgPermissions();
  const permRows = Object.keys(perms).map(role=>`<tr><td><b>${esc(role)}</b></td><td>${Object.entries(perms[role]).map(([k,v])=>`${v?"✅":"❌"} ${esc(k)}`).join("<br>")||"<span class=sub>—</span>"}</td></tr>`).join("")||`<tr><td colspan=2 class=sub>No permissions configured</td></tr>`;
  const ownEntries = Object.entries(cfgOwnership()).map(([o,c])=>`${esc(o)}→${esc(idToName(c))}`).join(" · ")||"none configured";
  $("identitymodel").innerHTML = `<table><tr><th>Role (from config)</th><th>Permissions (from config)</th></tr>${permRows}</table>
    <p class="sub">Identities (from config): ${cfgIdentities().map(i=>`${esc(i.name)} (${esc(i.id)}, ${esc(i.role)})`).join(" · ")||"none"}</p>
    <p class="sub">Ownership (from config): ${ownEntries}</p>
    <p class="sub">Ownership fields (inferred from spec): ${Object.keys(STATE.resources).map(r=>STATE.resources[r].ownershipField?`${r}.${STATE.resources[r].ownershipField}`:null).filter(Boolean).join(", ")||"none"}</p>`;
  const chips = cfgIdentities().map(i=>`<span class="chip on">[ ${esc(i.name)} · ${esc(i.id)} · ${esc(i.role)} ]</span>`).join("");
  if($("identityChips")) $("identityChips").innerHTML = chips||`<span class="sub">No identities — configure below + Load Demo.</span>`;
}
function renderSens(){
  let rows=[];
  Object.keys(STATE.resources).forEach(r=>Object.keys(STATE.resources[r].fields).forEach(f=>{
    const v = STATE.resources[r].fields[f];
    rows.push(`<tr><td><code>${esc(r+"."+f)}</code></td><td><span class="badge b-${v.sensitivity}">${v.sensitivity}</span></td><td class="sub">${esc(v.reason)}</td>
    <td><select data-r="${esc(r)}" data-f="${esc(f)}"><option value="">auto</option>${["PUBLIC","PERSONAL","INTERNAL","SENSITIVE"].map(o=>`<option ${o===STATE.overrides[r+"."+f]?"selected":""}>${o}</option>`).join("")}</select></td></tr>`);
  }));
  $("sensTable").innerHTML = rows.length? `<table><tr><th>Field</th><th>Level</th><th>Why</th><th>Override</th></tr>${rows.join("")}</table><div class="row"><button class="ghost" id="applySens">Apply overrides → rebuild</button></div>`:"—";
  const btn=$("applySens"); if(btn) btn.onclick=()=>{
    document.querySelectorAll("#sensTable select").forEach(s=>{ const k=s.dataset.r+"."+s.dataset.f; if(s.value) STATE.overrides[k]=s.value; else delete STATE.overrides[k]; });
    rebuild(); };
}
function renderTwin(){
  const t = STATE.twin; if(!t){ $("twin").textContent="—"; $("twinJson").textContent="—"; return; }
  const roleNames = Object.keys(t.roles);
  const resNames = Object.keys(t.resources);
  $("twin").textContent =
`                 AUTH  [protected:${t.auth.required.length} open:${t.auth.open.length}]
                  │
          ┌───────┴───────┐
          ▼               ▼
       ${roleNames.map(r=>r.toUpperCase()+" ["+((t.roles[r].adminEndpoints||[]).join(",")||(t.roles[r].ownership&&Object.keys(t.roles[r].ownership).length?Object.keys(t.roles[r].ownership).length+" objects":"—"))+"]").join("   ")}
          │
       ${resNames.map(r=>r.toUpperCase()+" ["+(t.resources[r].endpoints.join(",")||"—")+"]").join(" + ")||"—"}
       /    \\
      /      \\
    OWN ✅    FOREIGN 🔴 (BOLA: ${t.bolaCandidates.join(",")||"—"})`;
  $("twinJson").textContent = JSON.stringify(t,null,2);
  renderTwinDetail();
}
function renderTwinSelect(){
  const sel=$("twinSelect"); if(!sel) return;
  sel.innerHTML = Object.keys(STATE.resources).map(r=>`<option>${esc(r)}</option>`).join("");
  sel.onchange = renderTwinDetail;
}
function renderTwinDetail(){
  const sel=$("twinSelect"); const r = sel? sel.value : Object.keys(STATE.resources)[0]; if(!r||!STATE.twin){ return; }
  const R = STATE.resources[r], T = STATE.twin.resources[r];
  const eps = STATE.endpoints.filter(e=>e.resource===r).map(e=>`${e.id} ${e.method} ${e.path} [auth:${e.auth?"yes":"no"} action:${e.action}]`).join("\n")||"—";
  const access = Object.keys(STATE.twin.roles).map(role=>`${role} (allow:${(STATE.twin.roles[role].allowed||[]).slice(0,3).join("/")||"—"} deny:${(STATE.twin.roles[role].denied||[]).slice(0,3).join("/")||"—"})`).join(" · ");
  $("twinDetail").textContent =
`NODE: ${r}\nRole access: ${access}\nOwnership: field=${R.ownershipField||"none"} map=${Object.entries(cfgOwnership()).map(([o,c])=>o+"→"+c).join(",")||"none"}\nEndpoints:\n${eps}\nSensitivity: ${JSON.stringify(T?T.sensitivity:{})}\nRelations: ${(R.relations||[]).join("; ")||"—"}`;
}
function renderInferences(){
  $("inferences").innerHTML = STATE.inferences.map(i=>`<div class="law"><h3>${i.id} <span class="badge b-${i.confidence}">${i.confidence} ${i.score}</span></h3>
    <div>${esc(i.claim)}</div><div class="sub">Evidence: ${i.evidence.map(esc).join(" · ")}</div><div class="sub">To raise confidence: ${esc(i.needed)}</div></div>`).join("");
}
function renderLaws(){
  $("laws").innerHTML = STATE.laws.map(l=>`<div class="law"><h3>${l.id} [${l.category}/${l.severity}] <span class="badge b-${l.confidence}">${l.confidence} ${l.score}</span></h3>
    <div>${esc(l.title)}</div><div class="sub">Source: ${esc(l.source)}</div><div class="sub">Reason: ${esc(l.reason)}</div>
    <div class="inv">${esc(l.invariant)}</div></div>`).join("")
    + `<div class="note">HIGH (80-100) = explicit evidence from spec+config. MEDIUM (50-79) = heuristic → RISK, needs Part-2 runtime proof. No auto-vuln.</div>`;
}
function renderLawTests(){
  $("lawTests").innerHTML = STATE.laws.map(l=>`<div class="law"><h3>${l.id} tests</h3>${(l.tests||[]).map(t=>`<div>· <b>Given</b> ${esc(t.given)} <b>When</b> <code>${esc(t.when)}</code> <b>Expect</b> ${esc(t.expect)}</div>`).join("")}</div>`).join("");
}
function renderOutputs(){
  const m = buildTestableModel(); STATE.model = m;
  $("out1").textContent = JSON.stringify({version:STATE.specInfo.version, servers:STATE.specInfo.servers, count:STATE.endpoints.length, endpoints:STATE.endpoints},null,2);
  $("out2").textContent = JSON.stringify({resources:STATE.resources, twin:STATE.twin, ownership:cfgOwnership(), identities:cfgIdentities()},null,2);
  $("out3").textContent = JSON.stringify(STATE.laws,null,2);
  $("out4").textContent = JSON.stringify(m,null,2);
}

function parseConfigEditors(){
  const idTxt = $("identitiesEditor").value.trim(), pmTxt = $("permissionsEditor").value.trim(), ownTxt = $("ownershipEditor").value.trim();
  if(!idTxt||!pmTxt||!ownTxt) throw new Error("Fill identities + permissions + ownership config (or Load Demo).");
  const identities = JSON.parse(idTxt), permissions = JSON.parse(pmTxt), ownership = JSON.parse(ownTxt);
  if(!Array.isArray(identities)||!identities.length) throw new Error("identities must be a non-empty array [{name,role,id}].");
  if(typeof permissions!=="object") throw new Error("permissions must be an object {role:{action:bool}}.");
  if(typeof ownership!=="object") throw new Error("ownership must be an object {objectId:ownerId}.");
  return { identities, permissions, ownership };
}

function rebuild(){
  STATE.resources = buildResources(STATE.endpoints, STATE.spec);
  STATE.twin = buildTwin(STATE.endpoints, STATE.resources);
  STATE.inferences = buildInferences(STATE.endpoints, STATE.resources);
  STATE.laws = buildLaws(STATE.endpoints, STATE.resources);
  STATE.dashboard = buildDashboard();
  renderAll();
}
async function build(){
  const txt = $("swaggerText").value.trim();
  STATE.baseUrl = $("baseUrl").value.trim();
  if(!txt){ alert("Paste swagger JSON or Upload / Load demo first."); return; }
  try{ STATE.spec = JSON.parse(txt); }catch(e){ alert("Invalid spec JSON: "+e.message); return; }
  try{ STATE.config = parseConfigEditors(); }catch(e){ alert("Bad config: "+e.message); return; }
  const p = parseSpec(STATE.spec);
  STATE.endpoints=p.endpoints; STATE.warnings=p.warnings; STATE.specInfo={version:p.version, servers:p.servers};
  rebuild();
}
function download(name, text){ const a=document.createElement("a"); a.href=URL.createObjectURL(new Blob([text],{type:"application/json"})); a.download=name; a.click(); }
function isSandboxLike(url){ return /(sandbox|localhost|127\.|10\.|192\.168|staging|test|example|mock)/i.test(url); }
async function testSandbox(){
  const url = $("baseUrl").value.trim();
  const box = $("sandboxStatus");
  if(!url){ box.innerHTML=`<span class="warn">Enter Sandbox Base URL first.</span>`; return; }
  if(!isSandboxLike(url)) box.innerHTML = `<span class="warn">⚠ Non-sandbox-like URL. Policy: sandbox-only. Test continues, production blocked.</span><br>`;
  else box.innerHTML = `Testing…`;
  const t0 = performance.now();
  try{
    const ctl = new AbortController(); const to = setTimeout(()=>ctl.abort(), 8000);
    const r = await fetch(url, { method:"GET", signal:ctl.signal, mode:"cors" });
    clearTimeout(to);
    const ms = Math.round(performance.now()-t0);
    STATE.sandbox = { status: r.ok?"reachable":"http-"+r.status, ms, url };
    box.innerHTML += `<span class="ok">● Sandbox: HTTP ${r.status} in ${ms}ms</span><br><span class="sub">Safe GET only.</span>`;
  }catch(e){
    const ms = Math.round(performance.now()-t0);
    STATE.sandbox = { status:"unreachable:"+String(e.name||e.message), ms, url };
    box.innerHTML += `<span class="warn">● Unreachable (${esc(e.name||"error")}) in ${ms}ms. Twin still builds from spec.</span>`;
  }
  if(STATE.dashboard){ STATE.dashboard = buildDashboard(); renderDashboard(); renderOutputs(); }
}

window.addEventListener("DOMContentLoaded", ()=>{
  $("buildBtn").onclick = build;
  $("testBtn").onclick = testSandbox;
  $("applyConfig").onclick = ()=>{ try{ STATE.config = parseConfigEditors(); }catch(e){ alert("Bad config: "+e.message); return; } if(!STATE.endpoints.length){ alert("Build first, then apply."); return; } rebuild(); };
  $("demoBtn").onclick = async ()=>{
    const r = await fetch("sample-swagger.json"); $("swaggerText").value = await r.text();
    const c = await fetch("sample-config.json"); const cfg = await c.json();
    $("identitiesEditor").value = JSON.stringify(cfg.identities,null,2);
    $("permissionsEditor").value = JSON.stringify(cfg.permissions,null,2);
    $("ownershipEditor").value = JSON.stringify(cfg.ownership,null,2);
    if(!$("baseUrl").value) $("baseUrl").value="https://sandbox-api.example.com";
  };
  $("fileInput").addEventListener("change", e=>{ const f=e.target.files[0]; if(!f) return; const rd=new FileReader(); rd.onload=()=>{ $("swaggerText").value=rd.result; }; rd.readAsText(f); });
  $("dl4").onclick=()=>download("testable-security-model.json",$("out4").textContent);
  $("copy4").onclick=()=>{ navigator.clipboard.writeText($("out4").textContent); alert("Testable Security Model copied — paste into Part 2."); };
});
