// Sentinel X — Part 2: Test Lab (heuristic planner). Consumes Part 1 testable-security-model.json. Fully data-driven.
// Auth: per-identity credentials supplied by user (Bearer/API-key/Cookie). The lab never invents auth.
// Sandbox gate: the exact URL must be registered as a Target (src/target/policy.ts): loopback, private-network or
// reserved names only, with the user's explicit statement of authorization. Every live request stays inside it.
// Hypotheses: heuristic planner by default; optional user-provided LLM endpoint only enhances wording.
import "../src/ui/theme.css";
import { html, joinHtml, setHtml } from "../src/ui/safe-html";
import { copyText, fetchText, showStatus } from "../src/ui/status";
import { PathParameterError, fillPath, lastPathParam, pathParamNames } from "../src/paths/index";
import { assessTargetHost, findTarget, registerTarget, resolveRequestUrl } from "../src/target/policy";
const $ = (id) => document.getElementById(id);
let S = { model:null, tests:[], results:{}, findings:[], running:false, sel:null, execMode:"mock", mockMode:"vulnerable", sandboxUrl:"",
  auth:{ scheme:"bearer", apiKeyName:"X-API-Key", cookieName:"session", creds:{} }, cookieAck:false,
  targets:[], llm:{ endpoint:"", key:"", model:"", enabled:false }, llmIdeas:[] };

function log(m){ const c=$("console"); const t=new Date().toLocaleTimeString(); c.appendChild(document.createTextNode(`\n[${t}] ${m}`)); c.scrollTop=c.scrollHeight; }
function isAuthorized(url){ return !!findTarget(S.targets, url); }
// Pure + testable: real auth headers from user-supplied per-identity credentials. Never invents tokens.
// NOTE: browsers forbid scripts from setting the Cookie header, so pasted cookie VALUES
// cannot be sent cross-origin. The cookie scheme therefore uses the browser jar
// (credentials:include) and requires a prior login in this browser — see cookieNote.
function isCookieScheme(){ return S.auth.scheme==="cookie"||S.auth.scheme==="cookieJar"; }
function buildAuthHeaders(test){
  if(!test.identityId) return { headers:{}, credentialProvided:false };
  if(isCookieScheme()) return { headers:{}, credentialProvided:false, jar:true };
  const tok=(S.auth.creds||{})[test.identityId];
  if(!tok) return { headers:{}, credentialProvided:false };
  if(S.auth.scheme==="bearer") return { headers:{Authorization:"Bearer "+tok}, credentialProvided:true };
  if(S.auth.scheme==="apiKey") return { headers:{[(S.auth.apiKeyName||"X-API-Key")]:tok}, credentialProvided:true };
  return { headers:{}, credentialProvided:false };
}
function authnHeaderPreview(test){
  if(!test.identityId) return "(none — anonymous test)";
  if(isCookieScheme()) return "Cookie: browser jar via credentials:include — log in to the sandbox in this browser first (pasted values cannot be sent cross-origin)";
  const provided=!!(S.auth.creds||{})[test.identityId];
  if(!provided) return "(no credential configured for this identity — will be sent unauthenticated)";
  if(S.auth.scheme==="bearer") return "Authorization: Bearer <token-for-"+test.identityId+">";
  if(S.auth.scheme==="apiKey") return (S.auth.apiKeyName||"X-API-Key")+": <key-for-"+test.identityId+">";
  return "(scheme none)";
}
// Path building goes through src/paths (fillPath). Unknown path values are never invented:
// an object id fills only the last parameter (the addressed object); anything else throws MissingPathParameterError.
function objectPath(template, objectId){ const last=lastPathParam(template); return fillPath(template, last?{[last]:objectId}:{}); }
/** Anonymous-access probes: every parameter gets the same documented placeholder value. */
function placeholderPath(template, value){ return fillPath(template, Object.fromEntries(pathParamNames(template).map(n=>[n,value]))); }
/** Display only (matrix): unfilled parameters stay as {name}. */
function displayObjectPath(template, objectId){ const last=lastPathParam(template); return fillPath(template, last?{[last]:objectId}:{}, {onMissing:"keep"}); }
function nameOf(id){ const f=(S.model.testIdentities||[]).find(i=>i.id===id); return f?(f.name||id):id; }
function ownerOf(objId){ const f=(S.model.ownership||[]).find(o=>String(o.objectId)===String(objId)); return f?f.ownerId:null; }
function sensFields(){ const out=[]; const R=S.model.resources||{}; Object.keys(R).forEach(rn=>Object.keys((R[rn]||{fields:{}}).fields||{}).forEach(f=>{ const v=R[rn].fields[f]; if(v.sensitivity==="PERSONAL"||v.sensitivity==="SENSITIVE") out.push(rn+"."+f); })); return out; }
function adminRole(){ return S.model.twin&&S.model.twin.adminRole||null; }
function baseIdentity(){ const ids=S.model.testIdentities||[]; const br=(S.model.twin&&S.model.twin.baseRoles)||[]; return ids.find(i=>br.includes(i.role))||ids[0]; }
function adminIdentity(){ const ar=adminRole(); if(!ar) return null; return (S.model.testIdentities||[]).find(i=>i.role===ar)||null; }

// ---------- import ----------
function loadModel(obj){
  if(!obj||!Array.isArray(obj.endpoints)||!Array.isArray(obj.laws)) throw new Error("Not a testable-security-model (need endpoints[] + laws[]).");
  S.model=obj; S.tests=[]; S.results={}; S.findings=[]; S.sel=null;
  // The model only suggests a target: a URL the user already entered is never replaced (audit BUG-11).
  if(!$("sandboxUrl").value.trim()) $("sandboxUrl").value=obj.sandboxBaseUrl||"";
  S.sandboxUrl=$("sandboxUrl").value.trim();
  $("modelInfo").textContent=`${obj.version||"?"} · ${obj.endpoints.length} endpoints · ${obj.laws.length} laws · ${(obj.testIdentities||[]).length} identities`;
}

// ---------- planner ----------
// Heuristic planner: deterministic, explainable hypothesis templates from model data.
// NOT an LLM agent. An optional user-provided LLM endpoint (see llmEnhance) may reword these;
// without it, hypotheses are labelled heuristic.
function heuristicHypothesis(kind, ctx){
  if(kind==="BOLA_BASE") return `Baseline: ${ctx.actor} requests own object ${ctx.obj} via ${ctx.ep} to confirm normal behavior before boundary testing.`;
  if(kind==="BOLA") return `Endpoint ${ctx.ep} accepts an object ID and the model identifies '${ctx.ofield}' as a likely ownership field. Testing cross-owner access from ${ctx.actor} to object ${ctx.obj} (owner ${ctx.owner}). Heuristic proposes, sandbox proves.`;
  if(kind==="ADMIN") return `Endpoint ${ctx.ep} is admin-only and model assigns it to role '${ctx.adminRole}'. Testing whether non-admin ${ctx.actor} is denied.`;
  if(kind==="DATA") return `Response of ${ctx.ep} for foreign object ${ctx.obj} must not contain PERSONAL/SENSITIVE fields (${ctx.sensN} flagged in model). Testing for excessive exposure.`;
  if(kind==="AUTHN") return `Endpoint ${ctx.ep} requires authentication. Testing that anonymous access is denied.`;
  if(kind==="SEQUENCE") return `Sequence on ${ctx.ep}: legitimate access as ${ctx.actor}, then context switch and reuse of object ID. Authorization must be re-evaluated per step.`;
  return `Policy check derived from permission matrix.`;
}
function allIdGets(){ return (S.model.endpoints||[]).filter(e=>e.method==="GET"&&/\{.+\}/.test(e.path)); }
function allAdminEps(){ return (S.model.endpoints||[]).filter(e=>e.action==="AdminAction"||/^\/admin/i.test(e.path)); }
function H(kind,ctx){ return { text:heuristicHypothesis(kind,ctx), source:"heuristic" }; }
function planTests(){
  const M=S.model; const tests=[]; let n=1; const tid=()=>"T-"+String(n++).padStart(3,"0");
  S.planWarnings=[];
  // Paths are built before an endpoint's cases are created, so an endpoint is either fully planned or skipped with a reason.
  const skip=(cat,ep,e)=>{ if(!(e instanceof PathParameterError)) throw e; S.planWarnings.push(`${cat}: skipped ${ep.method} ${ep.path} (${e.message})`); };
  const ownEntries=M.ownership||[];
  const base=baseIdentity(), adm=adminIdentity();
  const idGets=allIdGets(), adminEps=allAdminEps(); // ALL eligible endpoints, not just the first
  const prot=(M.endpoints||[]).filter(e=>e.auth);
  // The template object {text, source} is flattened into a string + source (spread last so it wins over o.hypothesis).
  const mk=(o)=>{ const h=o.hypothesis; return {...o, hypothesisSource:(h&&h.source)||"heuristic", hypothesis:(h&&h.text)||h}; };
  for(const law of M.laws){
    const cat=law.category||"POLICY";
    if(cat==="BOLA"){
      for(const idGet of idGets){
        const mine=ownEntries.find(o=>base&&o.ownerId===base.id)||ownEntries[0];
        const foreign=ownEntries.find(o=>mine&&o.ownerId!==mine.ownerId);
        const of=(M.twin.resources[idGet.resource]||{}).ownershipField||"ownership field";
        let P; try{ P={ mine:mine&&objectPath(idGet.path,mine.objectId), foreign:foreign&&objectPath(idGet.path,foreign.objectId), anon:objectPath(idGet.path,(mine||{objectId:"1"}).objectId) }; }catch(e){ skip(cat,idGet,e); continue; }
        if(mine) tests.push(mk({id:tid(),lawId:law.id,category:cat,kind:"BOLA_BASE",priority:1,
          hypothesis:H("BOLA_BASE",{actor:base.id,obj:mine.objectId,ep:`${idGet.method} ${idGet.path}`}),
          given:`authenticated as ${base.id} (${nameOf(base.id)})`,whenText:`${idGet.method} ${P.mine} (own)`,expectText:"ALLOW",
          target:{method:idGet.method,pathTemplate:idGet.path,path:P.mine,resource:idGet.resource},
          identityId:base.id,mutation:{type:"none",reason:"baseline legitimate access"},expectedDeny:false,objectId:mine.objectId}));
        if(mine&&foreign) tests.push(mk({id:tid(),lawId:law.id,category:cat,kind:"BOLA",priority:1,
          hypothesis:H("BOLA",{actor:base.id,obj:foreign.objectId,owner:foreign.ownerId,ofield:of,ep:`${idGet.method} ${idGet.path}`}),
          given:`authenticated as ${base.id} (${nameOf(base.id)})`,whenText:`${idGet.method} ${P.foreign} (foreign, owner=${foreign.ownerId})`,expectText:"DENY 403/404",
          target:{method:idGet.method,pathTemplate:idGet.path,path:P.foreign,resource:idGet.resource},
          identityId:base.id,mutation:{type:"ownership",field:lastPathParam(idGet.path),from:mine.objectId,to:foreign.objectId,reason:`object ${foreign.objectId} owned by ${foreign.ownerId} (${nameOf(foreign.ownerId)})`},expectedDeny:true,objectId:foreign.objectId,baseObjectId:mine.objectId}));
        tests.push(mk({id:tid(),lawId:law.id,category:cat,kind:"AUTHN",priority:2,
          hypothesis:H("AUTHN",{ep:`${idGet.method} ${idGet.path}`}),given:"unauthenticated",whenText:`${idGet.method} ${P.anon}`,expectText:"DENY 401",
          target:{method:idGet.method,pathTemplate:idGet.path,path:P.anon,resource:idGet.resource},
          identityId:null,mutation:{type:"auth-strip",from:base?base.id:"identity",to:"anonymous",reason:"no credential sent"},expectedDeny:true,objectId:(mine||{objectId:"1"}).objectId}));
        if(mine&&foreign) tests.push(mk({id:tid(),lawId:law.id,category:cat,kind:"SEQUENCE",priority:2,
          hypothesis:H("SEQUENCE",{actor:base.id,ep:`${idGet.method} ${idGet.path}`}),given:`authenticated as ${base.id}, then context switch`,whenText:`GET own ${mine.objectId} → reuse foreign ${foreign.objectId}`,expectText:"step1 ALLOW, step2 DENY",
          target:{method:idGet.method,pathTemplate:idGet.path,path:P.foreign,resource:idGet.resource},
          identityId:base.id,mutation:{type:"sequence",steps:[`1. ${idGet.method} ${P.mine} as ${base.id} → expect ALLOW`,`2. ${idGet.method} ${P.foreign} as ${base.id} → expect DENY`],reason:"authorization must be re-evaluated per object"},expectedDeny:true,objectId:foreign.objectId,baseObjectId:mine.objectId,
          steps:[{label:"step 1 — legitimate access (own)",path:P.mine,objectId:mine.objectId,expectedDeny:false},{label:"step 2 — context switch, reuse foreign id",path:P.foreign,objectId:foreign.objectId,expectedDeny:true}]}));
      }
    }
    if(cat==="ADMIN"&&adminEps.length&&base){
      for(const adminEp of adminEps){
        let adminPath; try{ adminPath=fillPath(adminEp.path,{}); }catch(e){ skip(cat,adminEp,e); continue; }
        tests.push(mk({id:tid(),lawId:law.id,category:cat,kind:"ADMIN",priority:1,
          hypothesis:H("ADMIN",{adminRole:adminRole(),actor:base.id,ep:`${adminEp.method} ${adminEp.path}`}),
          given:`authenticated as ${base.id} (${base.role}, non-admin)`,whenText:`${adminEp.method} ${adminEp.path}`,expectText:"DENY 403",
          target:{method:adminEp.method,pathTemplate:adminEp.path,path:adminPath,resource:adminEp.resource},
          identityId:base.id,mutation:{type:"role",from:base.role,to:`${adminEp.method} ${adminEp.path}`,reason:`admin-only action invoked by ${base.role}`},expectedDeny:true}));
        if(adm) tests.push(mk({id:tid(),lawId:law.id,category:cat,kind:"ADMIN",priority:2,
          hypothesis:{text:`Positive control: ${adm.id} (${adm.role}) invokes ${adminEp.method} ${adminEp.path} — must ALLOW.`,source:"heuristic"},
          given:`authenticated as ${adm.id} (${adm.role})`,whenText:`${adminEp.method} ${adminEp.path}`,expectText:"ALLOW",
          target:{method:adminEp.method,pathTemplate:adminEp.path,path:adminPath,resource:adminEp.resource},
          identityId:adm.id,mutation:{type:"none",reason:"positive control"},expectedDeny:false}));
      }
    }
    if(cat==="DATA"){
      for(const idGet of idGets){
        const foreign=ownEntries.find((o,i,arr)=>arr[0]&&o.ownerId!==arr[0].ownerId)||ownEntries[1]||ownEntries[0];
        const actor=base||(S.model.testIdentities||[])[0];
        let P; try{ P={ foreign:foreign&&objectPath(idGet.path,foreign.objectId) }; }catch(e){ skip(cat,idGet,e); continue; }
        if(foreign&&actor) tests.push(mk({id:tid(),lawId:law.id,category:cat,kind:"DATA",priority:2,
          hypothesis:H("DATA",{obj:foreign.objectId,sensN:sensFields().length,ep:`${idGet.method} ${idGet.path}`}),
          given:`authenticated as ${actor.id}`,whenText:`${idGet.method} ${P.foreign} (foreign)`,expectText:"MUST NOT contain PERSONAL/SENSITIVE",
          target:{method:idGet.method,pathTemplate:idGet.path,path:P.foreign,resource:idGet.resource},
          identityId:actor.id,mutation:{type:"ownership",field:lastPathParam(idGet.path),from:"own",to:foreign.objectId,reason:`check field leak on foreign object (owner ${foreign.ownerId})`},expectedDeny:true,objectId:foreign.objectId,leakCheck:true}));
      }
    }
    if(cat==="AUTHN"){
      prot.slice(0,15).forEach(e=>{ tests.push(mk({id:tid(),lawId:law.id,category:cat,kind:"AUTHN",priority:2,
        hypothesis:H("AUTHN",{ep:`${e.method} ${e.path}`}),given:"no token",whenText:`${e.method} ${e.path}`,expectText:"DENY 401",
        target:{method:e.method,pathTemplate:e.path,path:placeholderPath(e.path,"1"),resource:e.resource},
        identityId:null,mutation:{type:"auth-strip",from:"identity",to:"anonymous",reason:"no credential sent"},expectedDeny:true})); });
      if(prot.length>15) S.planWarnings.push(`AUTHN expanded to first 15 of ${prot.length} protected endpoints.`);
    }
    if(cat==="ROLE"){
      if(adminEps.length&&base) adminEps.forEach(adminEp=>{ let adminPath; try{ adminPath=fillPath(adminEp.path,{}); }catch(e){ skip(cat,adminEp,e); return; } tests.push(mk({id:tid(),lawId:law.id,category:cat,kind:"ADMIN",priority:2,
        hypothesis:{text:`Role boundary: ${base.role} vs ${adminRole()||"privileged"} on ${adminEp.method} ${adminEp.path}.`,source:"heuristic"},given:`authenticated as ${base.id}`,whenText:`${adminEp.method} ${adminEp.path}`,expectText:"DENY unless permitted",
        target:{method:adminEp.method,pathTemplate:adminEp.path,path:adminPath,resource:adminEp.resource},
        identityId:base.id,mutation:{type:"role",from:base.role,to:adminEp.path,reason:"cross-role invocation"},expectedDeny:true})); });
      else tests.push(mk({id:tid(),lawId:law.id,category:cat,kind:"POLICY",priority:3,
        hypothesis:H("POLICY",{}),given:"permission matrix",whenText:"review contested actions",expectText:"ALLOW ⟺ permission",
        target:{method:"—",pathTemplate:"—",path:"—",resource:"—"},identityId:base?base.id:null,mutation:{type:"none",reason:"no executable endpoint — manual policy review"},expectedDeny:false,skip:true}));
    }
  }
  S.tests=tests;
  return tests;
}

// ---------- mock sandbox (data-driven, no hardcoded paths) ----------
function mockBody(resource, objectId){
  const fields=((S.model.resources||{})[resource]||{fields:{}}).fields;
  const body={};
  Object.keys(fields).forEach(f=>{ body[f]=f.toLowerCase()==="id"?objectId:`${f}_value`; });
  if(!body.id&&objectId) body.id=objectId;
  const of=((S.model.resources||{})[resource]||{}).ownershipField;
  if(of) body[of]=ownerOf(objectId)||`${of}_value`;
  return body;
}
function sleep(ms){ return new Promise(r=>setTimeout(r,ms)); }
async function mockRequest(test, overridePath){
  const t0=performance.now();
  await sleep(60+Math.random()*120);
  const path=overridePath||test.target.path;
  const ident=(S.model.testIdentities||[]).find(i=>i.id===test.identityId);
  const role=ident?ident.role:null;
  const isAdminEp=/^\/admin/i.test(test.target.pathTemplate||"")||test.target.resource==="Admin"||test.kind==="ADMIN";
  const idGet=/\{[^}]+\}/.test(test.target.pathTemplate||"")||test.objectId;
  let status, body;
  if(!ident){ status=401; body={error:"unauthorized"}; }
  else if(isAdminEp){
    if(role===adminRole()){ status=200; body={result:"ok",admin:true}; }
    else if(S.mockMode==="vulnerable"){ status=200; body={result:"ok",admin:true,leaked:true}; }
    else { status=403; body={error:"forbidden"}; }
  }
  else if(idGet&&test.objectId){
    const owner=ownerOf(test.objectId);
    if(!owner){ status=404; body={error:"not found"}; }
    else if(owner===test.identityId){ status=200; body=mockBody(test.target.resource,test.objectId); }
    else if(S.mockMode==="vulnerable"){ status=200; body=mockBody(test.target.resource,test.objectId); }
    else { status=403; body={error:"forbidden"}; }
  }
  else { status=200; body={result:"ok"}; }
  const ms=Math.round(performance.now()-t0);
  return { status, headers:{"content-type":"application/json"}, body, ms, url:(S.sandboxUrl||"mock")+path,
    request:{method:test.target.method,path,identity:test.identityId,auth:"simulated-identity (mock only)"}, mock:true, mode:S.mockMode };
}
async function liveRequest(test){
  // Gate: THIS exact URL must be a registered sandbox target, and the request must stay inside it.
  const target=findTarget(S.targets, S.sandboxUrl);
  if(!target) throw new Error("Live run blocked: this sandbox URL is not a registered target. Register it first (loopback, private-network or reserved hosts only).");
  const url=resolveRequestUrl(target, test.target.path);
  // Cookie jar only runs if the user confirms the sandbox actually supports credentialed requests.
  if(isCookieScheme()&&!S.cookieAck) throw new Error("Live cookie run blocked: confirm your sandbox supports CORS credentials (exact origin, no wildcard) and that you are logged in — tick the cookie checkbox first.");
  const ctl=new AbortController(); const to=setTimeout(()=>ctl.abort(),10000);
  const t0=performance.now();
  const { headers:authH, credentialProvided } = buildAuthHeaders(test);
  if(test.identityId&&!credentialProvided&&!isCookieScheme()) throw new Error(`Live run blocked: no credential configured for identity ${test.identityId}. Add it in Authentication first (or run this case in Mock mode).`);
  const headers=Object.assign({"Content-Type":"application/json","X-Sentinel-Test":test.id+"/"+test.lawId},authH);
  // redirect:"error": a redirect could lead outside the registered target, so it fails the request instead.
  const opts={method:test.target.method,headers,signal:ctl.signal,mode:"cors",redirect:"error"};
  if(isCookieScheme()) opts.credentials=test.identityId?"include":"omit"; // jar only for identity tests; anonymous stays anonymous
  else opts.credentials="omit";
  if(test.target.method!=="GET") opts.body=JSON.stringify({id:test.objectId||"1"});
  const r=await fetch(url,opts); clearTimeout(to);
  const ms=Math.round(performance.now()-t0);
  const txt=await r.text();
  let body; try{ body=JSON.parse(txt); }catch(e){ body={raw:String(txt).slice(0,4000)}; }
  return { status:r.status, headers:{"content-type":r.headers.get("content-type")}, body, ms, url,
    request:{method:test.target.method,path:test.target.path,identity:test.identityId,auth:S.auth.scheme+" (credential redacted)"}, live:true,
    auth:{scheme:S.auth.scheme,credentialProvided} };
}
async function execTest(test, overridePath){
  if(test.skip) return {skipped:true};
  if(S.execMode==="live") return liveRequest(test);
  return mockRequest(test, overridePath);
}
// Real multi-step execution: every step is sent in order, each with its own
// request/response/analysis. Step 1 doubles as the baseline for step 2.
async function execSequence(test){
  const out=[];
  for(const s of (test.steps||[])){
    const t2=Object.assign({},test,{target:Object.assign({},test.target,{path:s.path}),objectId:s.objectId});
    const resp = S.execMode==="live" ? await liveRequest(t2) : await mockRequest(t2, s.path);
    const an = analyze(Object.assign({},test,{expectedDeny:s.expectedDeny,objectId:s.objectId}), resp, out.length?out[0].resp:null);
    out.push({label:s.label,path:s.path,objectId:s.objectId,expectedDeny:s.expectedDeny,resp,analysis:an});
  }
  return out;
}

// ---------- analyzer + confirmation ----------
function bodyKeys(b){ if(!b||typeof b!=="object") return []; return Object.keys(b); }
function analyze(test, resp, baseline){
  const sens=sensFields().map(s=>s.split(".").pop());
  const keys=bodyKeys(resp.body);
  const sensFound=[...new Set(keys.filter(k=>sens.includes(k)))];
  const owner=test.objectId?ownerOf(test.objectId):null;
  const rel=test.objectId?(owner===test.identityId?"own":owner?"foreign":"unknown"):"n/a";
  const actualAllow=resp.status===200||resp.status===201;
  const actualDeny=[401,403,404].includes(resp.status);
  let sim=null;
  if(baseline&&baseline.body&&typeof baseline.body==="object"){
    const a=new Set(bodyKeys(baseline.body)), b=new Set(keys);
    const inter=[...a].filter(k=>b.has(k)).length, union=new Set([...a,...b]).size;
    sim=union?Math.round(100*inter/union):null;
  }
  let verdict, reason;
  if(test.expectedDeny&&actualAllow){
    if((test.kind==="BOLA"||test.kind==="DATA"||test.kind==="SEQUENCE")&&rel==="foreign"&&(sensFound.length||resp.status===200)){ verdict="POSSIBLE_VIOLATION"; reason=`foreign object returned 200 with ${sensFound.length?("sensitive: "+sensFound.slice(0,4).join(", ")):"object data"}`; }
    else if(test.kind==="ADMIN"){ verdict="POSSIBLE_VIOLATION"; reason="non-admin received 200 on admin action"; }
    else if(test.identityId===null&&actualAllow){ verdict="POSSIBLE_VIOLATION"; reason="anonymous received 2xx on protected endpoint"; }
    else { verdict="POSSIBLE_VIOLATION"; reason=`expected DENY, got ${resp.status}`; }
  }
  else if(test.expectedDeny&&actualDeny){ verdict="PASS"; reason=`denied as expected (${resp.status})`; }
  else if(!test.expectedDeny&&actualAllow){ verdict="PASS"; reason=`allowed as expected (${resp.status})`; }
  else {
    verdict="POSSIBLE_VIOLATION"; reason=`expected ALLOW, got ${resp.status}`;
    if(resp.live&&isCookieScheme()&&resp.status===401) reason+=` — possibly missing browser cookie, not app behavior: confirm sandbox login happened in this browser and CORS allows credentials before treating as a finding`;
  }
  return { sensFound, rel, owner, sim, verdict, reason };
}
async function confirm(test, resp, analysis){
  const steps=[`initial: ${resp.status} → ${analysis.verdict} (${analysis.reason})`];
  if(analysis.verdict==="PASS") return {status:"PASS",steps,confirmed:false};
  let r2; try{ r2=await execTest(test); }catch(e){ steps.push(`repeat failed: ${e.message} → REJECTED (no proof)`); return {status:"REJECTED",steps,confirmed:false}; }
  steps.push(`repeat: ${r2.status} (${r2.mock?"mock-"+r2.mode:"live"})`);
  if(r2.status!==resp.status){ steps.push("flaky (status changed) → REJECTED as false positive"); return {status:"REJECTED",steps,confirmed:false,repeat:r2}; }
  if(test.objectId){ const o=ownerOf(test.objectId); steps.push(o?`ownership: object ${test.objectId} owner=${o}, requester=${test.identityId} → ${o===test.identityId?"own":"FOREIGN confirmed"}`:"ownership: unknown object → REJECTED"); if(!o||o===test.identityId){ steps.push("not foreign → REJECTED"); return {status:"REJECTED",steps,confirmed:false,repeat:r2}; } }
  if(test.kind==="BOLA"||test.kind==="DATA"||test.kind==="SEQUENCE"){
    if(analysis.sensFound.length) steps.push(`${S.execMode==="mock"?"sensitive fields present in the simulated response":"sensitive data confirmed"}: ${analysis.sensFound.slice(0,5).join(", ")}`);
    else if(r2.status===200) steps.push("object data returned cross-owner (no flagged fields, still boundary failure)");
    else { steps.push("no data returned → REJECTED"); return {status:"REJECTED",steps,confirmed:false,repeat:r2}; }
  }
  // A mock run only simulates the sandbox: its reasoning trail must not claim a confirmation.
  steps.push(S.execMode==="mock"?"SIMULATED (a live sandbox run would be needed to confirm)":"CONFIRMED");
  return {status:"CONFIRMED",steps,confirmed:true,repeat:r2};
}

// ---------- runner ----------
async function runOne(id){
  const t=S.tests.find(x=>x.id===id); if(!t||S.running) return;
  S.running=true;
  try{
    log(`${t.id} ${t.lawId} ${t.kind} → ${t.target.method} ${t.target.path} as ${t.identityId||"anonymous"} (expect ${t.expectText})`);
    if(t.skip){ S.results[t.id]={status:"SKIPPED",reason:"policy review — no executable endpoint",test:t}; renderAll(); return; }
    let baseline=null, stepResults=null, resp, an;
    if(t.kind==="SEQUENCE"&&t.steps){
      stepResults=await execSequence(t);
      baseline=stepResults.length?stepResults[0].resp:null;
      resp=stepResults.length?stepResults[stepResults.length-1].resp:null;
      an=analyze(t,resp,baseline);
    } else {
      if((t.kind==="BOLA"||t.kind==="DATA")&&t.baseObjectId){ try{ baseline=await execTest({...t,target:{...t.target,path:objectPath(t.target.pathTemplate,t.baseObjectId)},objectId:t.baseObjectId,identityId:t.identityId}); }catch(e){ baseline=null; } }
      resp=await execTest(t);
      an=analyze(t,resp,baseline);
    }
    const cf=await confirm(t,resp,an);
    S.results[t.id]={status:cf.status==="CONFIRMED"?"VIOLATION":cf.status,test:t,resp,repeat:cf.repeat||null,baseline,stepResults,analysis:an,steps:cf.steps,reason:cf.status==="PASS"?an.reason:cf.steps.join(" → ")};
    log(`${t.id} = ${S.results[t.id].status} (${resp.status}${cf.repeat?"/"+cf.repeat.status:""})`);
    if(cf.status==="CONFIRMED") buildFindings();
    renderAll();
  } catch(e){ S.results[t.id]={status:"ERROR",reason:String(e.message||e),test:t}; log(`${t.id} ERROR ${e.message}`); renderAll(); }
  finally { S.running=false; updateBtns(); }
}
async function runAll(){
  if(S.running||!S.tests.length) return;
  S.running=true;
  try{
    for(const t of S.tests){
      if(t.skip){ S.results[t.id]={status:"SKIPPED",reason:"policy review",test:t}; continue; }
      log(`${t.id} ${t.lawId} ${t.kind} → ${t.target.method} ${t.target.path} as ${t.identityId||"anonymous"}`);
      try{
        let baseline=null, stepResults=null, resp, an;
        if(t.kind==="SEQUENCE"&&t.steps){
          stepResults=await execSequence(t);
          baseline=stepResults.length?stepResults[0].resp:null;
          resp=stepResults.length?stepResults[stepResults.length-1].resp:null;
          an=analyze(t,resp,baseline);
        } else {
          if((t.kind==="BOLA"||t.kind==="DATA")&&t.baseObjectId){ try{ baseline=await execTest({...t,target:{...t.target,path:objectPath(t.target.pathTemplate,t.baseObjectId)},objectId:t.baseObjectId,identityId:t.identityId}); }catch(e){} }
          resp=await execTest(t);
          an=analyze(t,resp,baseline);
        }
        const cf=await confirm(t,resp,an);
        S.results[t.id]={status:cf.status==="CONFIRMED"?"VIOLATION":cf.status,test:t,resp,repeat:cf.repeat||null,baseline,stepResults,analysis:an,steps:cf.steps,reason:cf.status==="PASS"?an.reason:cf.steps.join(" → ")};
        log(`${t.id} = ${S.results[t.id].status}`);
      }catch(e){ S.results[t.id]={status:"ERROR",reason:String(e.message||e),test:t}; log(`${t.id} ERROR ${e.message}`); }
      renderAll();
      await sleep(120);
    }
    buildFindings();
    renderAll();
    log(`done: ${Object.values(S.results).filter(r=>r.status==="PASS").length} pass, ${Object.values(S.results).filter(r=>r.status==="VIOLATION").length} violations, ${Object.values(S.results).filter(r=>r.status==="REJECTED").length} rejected`);
  } finally { S.running=false; updateBtns(); }
}

// ---------- findings + evidence ----------
const TYPE_LABEL={BOLA:"BOLA / IDOR",ADMIN:"Broken Function-Level Authorization",DATA:"Excessive Data Exposure",AUTHN:"Authentication",ROLE:"Role Boundary",SEQUENCE:"Sequence / Context-Reuse",POLICY:"Policy"};
function buildFindings(){
  const out=[]; let n=1;
  for(const id of Object.keys(S.results)){
    const r=S.results[id]; if(r.status!=="VIOLATION") continue;
    const law=(S.model.laws||[]).find(l=>l.id===r.test.lawId)||{};
    // No fabricated percentages: report the law's own confidence level. Mock runs are simulations, never confirmations.
    const conf=law.confidence||"UNRATED";
    const simulated=S.execMode==="mock";
    const curlAuth = r.test.identityId ? (isCookieScheme()?` -b "<cookies-from-sandbox-login>"`:` -H "${authnHeaderPreview(r.test)}"`): "";
    out.push({ id:"FINDING-"+String(n++).padStart(3,"0"), type:TYPE_LABEL[r.test.kind]||r.test.kind,
      law:r.test.lawId, endpoint:`${r.test.target.method} ${r.test.target.pathTemplate}`, severity:law.severity||"Medium",
      identity:r.test.identityId, identityName:nameOf(r.test.identityId),
      ownResource:r.test.baseObjectId||null, foreignResource:r.test.objectId||null,
      expected:r.test.expectText, observed:`HTTP ${r.resp.status}`,
      sensitiveData:r.analysis.sensFound||[], confidence:conf, status:simulated?"SIMULATED":"CONFIRMED", simulated,
      mutation:r.test.mutation, hypothesis:r.test.hypothesis, hypothesisSource:r.test.hypothesisSource||"heuristic",
      authScheme:S.execMode==="live"?S.auth.scheme:"simulated-identity (mock)",
      sequenceProof:(r.stepResults||[]).map(s=>({label:s.label,expected:s.expectedDeny?"DENY":"ALLOW",
        request:s.resp.request||{method:r.test.target.method,path:s.path,identity:r.test.identityId},
        response:{status:s.resp.status,body:s.resp.body,ms:s.resp.ms},
        ownership:s.analysis.rel,owner:s.analysis.owner,sensitive:s.analysis.sensFound,stepVerdict:s.analysis.verdict})),
      reproduction:{ steps:[`Authenticate as ${r.test.identityId} with the configured ${S.execMode==="live"?S.auth.scheme:"mock"} credential`,`Send ${r.test.target.method} ${(S.sandboxUrl||"")}${r.test.target.path}`,`Observe HTTP ${r.resp.status} and compare to expected ${r.test.expectText}`],
        curl:`curl -X ${r.test.target.method} "${(S.sandboxUrl||"")}${r.test.target.path}"${curlAuth}` },
      evidence:{ request:r.resp.request, response:{status:r.resp.status,body:r.resp.body,ms:r.resp.ms}, baseline:r.baseline?{status:r.baseline.status,body:r.baseline.body}:null, repeat:r.repeat?{status:r.repeat.status}:null, confirmation:r.steps } });
  }
  S.findings=out;
}
function evidencePackage(){
  return { version:"part2-v2-evidence", sandboxOnly:true, sandboxUrl:S.sandboxUrl,
    targets:S.targets.map(t=>({...t, note:"authorization stated by the user at registration; not independently verified"})),
    executor:S.execMode, mockMode:S.execMode==="mock"?S.mockMode:null,
    auth:{scheme:S.execMode==="live"?S.auth.scheme:"simulated-identity (mock)",credentialsConfigured:Object.keys(S.auth.creds||{}).length,secretValues:"never exported",
      cookieLimitation:isCookieScheme()?"cookie scheme = browser jar via credentials:include, only if sandbox supports CORS credentials; pasted cookie values unsupported cross-origin (forbidden header); needs prior browser login + explicit support acknowledgement":null,
      cookieSupportAcknowledged:isCookieScheme()?!!S.cookieAck:null},
    planner:"heuristic (deterministic templates); LLM wording/ideas only if user-supplied endpoint was used — see hypothesisSource per test and llmIdeas (never executed)",
    llmIdeas:{source:"llm",executed:false,items:S.llmIdeas},
    modelRef:{ version:S.model.version, laws:(S.model.laws||[]).map(l=>l.id), endpoints:(S.model.endpoints||[]).length },
    summary:{ total:S.tests.length, pass:Object.values(S.results).filter(r=>r.status==="PASS").length, violations:Object.values(S.results).filter(r=>r.status==="VIOLATION").length, rejected:Object.values(S.results).filter(r=>r.status==="REJECTED").length },
    findings:S.findings,
    results:Object.keys(S.results).map(id=>({ test:id, law:S.results[id].test.lawId, kind:S.results[id].test.kind, status:S.results[id].status, hypothesisSource:S.results[id].test.hypothesisSource||"heuristic", request:S.results[id].resp?S.results[id].resp.request:undefined, response:S.results[id].resp?{status:S.results[id].resp.status,body:S.results[id].resp.body}:undefined, sequenceProof:(S.results[id].stepResults||[]).map(s=>({label:s.label,expected:s.expectedDeny?"DENY":"ALLOW",request:s.resp.request||{method:S.results[id].test.target.method,path:s.path,identity:S.results[id].test.identityId},response:{status:s.resp.status,body:s.resp.body,ms:s.resp.ms},ownership:s.analysis.rel,owner:s.analysis.owner,sensitive:s.analysis.sensFound,stepVerdict:s.analysis.verdict,stepReason:s.analysis.reason})), steps:S.results[id].steps||undefined })) };
}

// ---------- render (all output goes through html``/setHtml, which escape every interpolated value) ----------
function renderAll(){ renderPlanner(); renderTargets(); renderTests(); renderPreview(); renderResults(); renderMatrix(); renderFindings(); updateBtns(); }
function updateBtns(){ renderTargetBar(); $("runAllBtn").disabled=!S.tests.length||S.running; $("resetBtn").disabled=!Object.keys(S.results).length; $("dlEvidence").disabled=!S.findings.length; $("copyEvidence").disabled=!S.findings.length; }
function renderPlanner(){
  if(!S.model){ $("planner").textContent="—"; return; }
  const cond=S.model.laws.length, cases=S.tests.length;
  setHtml($("planner"), html`<div class="tiles"><div class="tile"><b>${S.model.laws.length}</b><span class="sub">laws</span></div>
  <div class="tile"><b>${cond}</b><span class="sub">conditions</span></div><div class="tile"><b>${cases}</b><span class="sub">cases</span></div>
  <div class="tile"><b>${(S.model.testIdentities||[]).length}</b><span class="sub">identities</span></div></div>
  <table><tr><th scope="col">Law</th><th scope="col">Category</th><th scope="col">Cases</th><th scope="col">Priority</th></tr>${S.model.laws.map(l=>{ const ts=S.tests.filter(t=>t.lawId===l.id); return html`<tr><td><code>${l.id}</code> ${l.title||""}</td><td>${l.category}</td><td>${ts.length}</td><td>${ts.length?Math.min(...ts.map(t=>t.priority)):"—"}</td></tr>`; })}</table>${(S.planWarnings||[]).length?html`<div class="note">${joinHtml(S.planWarnings, html`<br>`)}</div>`:""}`);
}
function targetReason(e){
  const r=[]; if(/\{.+\}/.test(e.path)) r.push("object-ID"); if(/^\/admin/i.test(e.path)||e.action==="AdminAction") r.push("admin"); if(e.method!=="GET") r.push("write"); if(e.auth) r.push("auth-required");
  const sens=Object.keys(((S.model.resources||{})[e.resource]||{fields:{}}).fields||{}).filter(f=>{ const v=((S.model.resources||{})[e.resource]||{fields:{}}).fields[f]; return v.sensitivity==="PERSONAL"||v.sensitivity==="SENSITIVE"; });
  if(sens.length) r.push(`${sens.length}-sensitive`);
  return r.join(" · ")||"—";
}
function renderTargets(){
  if(!S.tests.length){ $("targets").textContent="—"; return; }
  const g={}; S.tests.forEach(t=>{ const k=t.target.method+" "+t.target.pathTemplate; g[k]=g[k]||{ep:k,n:0,prio:9,res:t.target.resource}; g[k].n++; g[k].prio=Math.min(g[k].prio,t.priority); });
  const rows=Object.values(g).sort((a,b)=>a.prio-b.prio).map(x=>{ const e=(S.model.endpoints||[]).find(e=>(e.method+" "+e.path)===x.ep); return html`<tr><td><code>${x.ep}</code></td><td>${x.n}</td><td>P${x.prio}</td><td class="sub">${e?targetReason(e):""}</td></tr>`; });
  setHtml($("targets"), html`<table><tr><th scope="col">Endpoint</th><th scope="col">Cases</th><th scope="col">Prio</th><th scope="col">Why selected</th></tr>${rows}</table>`);
}
function renderTests(){
  if(!S.tests.length){ $("tests").textContent="—"; return; }
  setHtml($("tests"), html`${S.tests.map(t=>{ const r=S.results[t.id]; const st=r?r.status:(t.skip?"SKIPPED":"PENDING");
    return html`<div class="test ${S.sel===t.id?"sel":""}" data-t="${t.id}" role="button" tabindex="0" aria-pressed="${S.sel===t.id?"true":"false"}"><h3>${t.id} · ${t.lawId} · ${t.kind} <span class="badge b-${st}">${st}</span> <span class="sub">P${t.priority}</span></h3><div class="sub">[${t.hypothesisSource||"heuristic"}] ${t.hypothesis}</div><div><code>${t.target.method}</code> <code>${t.target.path}</code> as <code>${t.identityId||"anonymous"}</code> → expect ${t.expectText}</div></div>`; })}`);
  const select=d=>{ S.sel=d.dataset.t; renderTests(); renderPreview(); const again=[...document.querySelectorAll("#tests .test")].find(x=>x.dataset.t===S.sel); if(again) again.focus(); };
  document.querySelectorAll("#tests .test").forEach(d=>{ d.onclick=()=>select(d); d.onkeydown=e=>{ if(e.key==="Enter"||e.key===" "){ e.preventDefault(); select(d); } }; });
}
function renderPreview(){
  const t=S.tests.find(x=>x.id===S.sel); if(!t){ setHtml($("preview"), html`<p class="sub">Select a test.</p>`); return; }
  const r=S.results[t.id];
  const noCred=S.execMode==="live"&&t.identityId&&!(S.auth.creds||{})[t.identityId]&&!isCookieScheme();
  const execution=S.execMode==="live"?(isAuthorized(S.sandboxUrl)?"REGISTERED SANDBOX TARGET":"NOT REGISTERED: register the target first")+(isCookieScheme()?(S.cookieAck?" · COOKIE SUPPORT ACKED":" · COOKIE SUPPORT NOT ACKED — run will be blocked"):""):"MOCK "+S.mockMode;
  setHtml($("preview"), html`<div class="test sel"><h3>Preview ${t.id} — ${t.lawId}</h3>
  <div><b>Hypothesis (${t.hypothesisSource||"heuristic"} planner):</b> ${t.hypothesis}</div>
  <div><b>Identity:</b> <code>${t.identityId||"anonymous"}</code> <b>Endpoint:</b> <code>${t.target.method} ${t.target.pathTemplate}</code></div>
  <div><b>Mutation (${t.mutation.type}):</b> ${JSON.stringify(t.mutation)}</div>
  <div><b>Auth sent (live):</b> <code>${authnHeaderPreview(t)}</code>${noCred?html` <span class="warn">no credential — live run will be blocked</span>`:""}</div>
  <div class="inv">REQUEST\n${t.target.method} ${S.sandboxUrl||""}${t.target.path}\n${authnHeaderPreview(t)}\nX-Sentinel-Test: ${t.id}/${t.lawId} (tracing only, not auth)\n\nEXPECTED: ${t.expectText}\nEXECUTION: ${execution}</div>
  ${r?html`<div><b>Result:</b> <span class="badge b-${r.status}">${r.status}</span> ${r.reason||""}</div>`:""}
  <div class="row"><button class="ghost" id="runOneBtn"${t.skip?html` disabled`:""}>RUN TEST</button><button class="ghost" id="llmOneBtn">Reword hypothesis (LLM)</button></div></div>`);
  const b=$("runOneBtn"); if(b) b.onclick=()=>runOne(t.id);
  const l=$("llmOneBtn"); if(l) l.onclick=()=>llmEnhance(t.id);
}
function renderResults(){
  const ids=Object.keys(S.results); if(!ids.length){ $("results").textContent="—"; return; }
  setHtml($("results"), html`${ids.map(id=>{ const r=S.results[id]; const t=r.test;
    return html`<div class="test"><h3>${id} · ${t.lawId} · ${t.kind} <span class="badge b-${r.status}">${r.status}</span>${r.resp&&r.resp.mock?html` <span class="badge b-SIMULATED">SIMULATED</span>`:""}</h3>
    <div class="sub">[${t.hypothesisSource||"heuristic"}] ${t.hypothesis}</div>
    <div><code>${t.target.method} ${t.target.path}</code> as <code>${t.identityId||"anonymous"}</code> → expected ${t.expectText}, got ${r.resp?("HTTP "+r.resp.status):(r.reason||"")}</div>
    ${r.analysis?html`<div class="sub">ownership: ${r.analysis.rel}${r.analysis.owner?(" (owner "+r.analysis.owner+")"):""} · sensitive: ${(r.analysis.sensFound||[]).join(", ")||"none"}${r.analysis.sim!=null?(` · similarity ${r.analysis.sim}%`):""}</div>`:""}
    ${(r.steps||[]).length?html`<div class="sub">confirmation: ${r.steps.join(" → ")}</div>`:""}
    ${r.stepResults?html`<table><tr><th scope="col">Step</th><th scope="col">Request</th><th scope="col">Expected</th><th scope="col">Got</th><th scope="col">Step verdict</th></tr>${r.stepResults.map(s=>html`<tr><td>${s.label}</td><td><code>${s.path}</code></td><td>${s.expectedDeny?"DENY":"ALLOW"}</td><td>${s.resp.status}</td><td>${s.analysis.verdict} — ${s.analysis.reason}</td></tr>`)}</table>`:""}
    ${r.resp?html`<div class="inv">REQ ${r.resp.request.method} ${r.resp.url}\nRES ${r.resp.status} (${r.resp.ms}ms)\n${String(JSON.stringify(r.resp.body)).slice(0,600)}</div>`:""}</div>`; })}`);
}
function renderMatrix(){
  if(!S.model){ $("matrix").textContent="—"; return; }
  const eps=allIdGets(); if(!eps.length){ setHtml($("matrix"), html`<p class="sub">No ID endpoint.</p>`); return; }
  const ids=S.model.testIdentities||[]; const own=S.model.ownership||[];
  setHtml($("matrix"), html`${eps.map(idGet=>{
    const rows=ids.map(i=>{ const mine=own.find(o=>o.ownerId===i.id); const foreign=own.find(o=>o.ownerId!==i.id);
      const cell=(obj,exp)=>{ if(!obj) return "—"; let p; try{ p=objectPath(idGet.path,obj.objectId); }catch(e){ return "not planned — missing path parameter values"; } const hit=Object.keys(S.results).find(rid=>{ const r=S.results[rid]; return r.test.identityId===i.id&&r.test.target.path===p&&r.test.target.method===idGet.method; });
        if(!hit) return `${exp} (pending)`; const st=S.results[hit].status; return st==="PASS"?`✓ ${exp}`:`${st} (exp ${exp})`; };
      return html`<tr><td><code>${i.id}</code> (${i.role})</td><td><code>${mine?displayObjectPath(idGet.path,mine.objectId):"—"}</code><br>${cell(mine,"ALLOW")}</td><td><code>${foreign?displayObjectPath(idGet.path,foreign.objectId):"—"}</code><br>${cell(foreign,"DENY")}</td></tr>`; });
    return html`<h3><code>${idGet.method+" "+idGet.path}</code></h3><table><tr><th scope="col">Identity</th><th scope="col">Own (expect ALLOW)</th><th scope="col">Foreign (expect DENY)</th></tr>${rows}</table>`;
  })}`);
}
function renderFindings(){
  if(!S.findings.length){ setHtml($("findings"), html`<p class="sub">No findings yet. Run tests. Mock-mode results are labelled SIMULATED, not confirmed.</p>`); $("evidenceOut").textContent="—"; return; }
  setHtml($("findings"), html`${S.findings.map(f=>html`<div class="test"><h3>${f.id} · ${f.type} <span class="badge b-${f.status}">${f.status}</span> <span class="badge b-${f.confidence}">law confidence ${f.confidence}</span> [${f.severity}]</h3>
  <div>Endpoint <code>${f.endpoint}</code> · identity <code>${f.identity}</code> (${f.identityName}) · expected ${f.expected} · observed ${f.observed}</div>
  <div class="sub">own=${f.ownResource||"—"} foreign=${f.foreignResource||"—"} · sensitive: ${(f.sensitiveData||[]).join(", ")||"none"}</div>
  ${(f.sequenceProof||[]).length?html`<div class="sub">proof chain: ${f.sequenceProof.map(s=>`${s.label} → exp ${s.expected}, got ${s.response.status} (${s.stepVerdict})`).join(" → ")}</div>`:""}
  <div class="inv">${f.reproduction.curl}</div></div>`)}`);
  $("evidenceOut").textContent=JSON.stringify(evidencePackage(),null,2);
}
// ---------- auth + target registration + optional LLM wording ----------
function renderAuth(){
  const box=$("authBox"); if(!box) return;
  if(!S.model){ setHtml(box, html`<p class="sub">Load a model first — credential fields appear per identity.</p>`); return; }
  if(isCookieScheme()){
    setHtml(box, html`<div class="note">⚠ Cookie auth uses your <b>browser cookie jar</b> (credentials:include) and runs <b>only if your sandbox supports it</b> — pasted cookie values <b>cannot</b> be sent by browser scripts (forbidden header), so per-identity cookie pasting is <b>unsupported for cross-origin execution</b>. Requirements: (1) log in to the sandbox in this browser first, (2) sandbox returns <code>Access-Control-Allow-Credentials: true</code> with an exact <code>Access-Control-Allow-Origin</code> (no wildcard), or run same-origin / via a proxy. For cross-origin sandboxes prefer Bearer or API-key. Mock mode simulates identities and is unaffected.</div>
    <div class="row"><label style="margin:0"><input type="checkbox" id="cookieAck" style="width:auto"${S.cookieAck?html` checked`:""}> My sandbox supports credentialed cookie requests and I am logged in (required for live cookie runs)</label></div>
    <p class="sub">Scheme <b>cookie (browser jar)</b> · no secrets handled by the lab.</p>`);
    $("cookieAck").onchange=e=>{ S.cookieAck=e.target.checked; renderPreview(); };
    renderApproval(); return;
  }
  setHtml(box, html`${(S.model.testIdentities||[]).map(i=>html`<div class="row"><label style="margin:0;min-width:220px">${i.name} <code>${i.id}</code> (${i.role})</label>
    <input type="password" data-cred="${i.id}" aria-label="Credential for ${i.name} (${i.id})" placeholder="token / key (stored in memory only)" style="flex:1"></div>`)}
    <p class="sub">Scheme <b>${S.auth.scheme}</b> · credentials held in browser memory only — never written to findings or evidence.</p>`);
  // Credential values are set as DOM properties, never serialized into markup.
  box.querySelectorAll("[data-cred]").forEach(inp=>{ inp.value=(S.auth.creds||{})[inp.dataset.cred]||""; inp.onchange=()=>{ S.auth.creds[inp.dataset.cred]=inp.value.trim(); }; });
  renderApproval();
}
function renderApproval(){
  const box=$("approvalBox"); if(!box) return;
  const url=($("sandboxUrl").value||"").trim();
  const target=findTarget(S.targets, url);
  const a=assessTargetHost(url);
  const registered = S.targets.length
    ? html`<p class="sub">Registered targets: ${joinHtml(S.targets.map(t=>html`<code>${t.baseUrl}</code> (${t.id}, ${t.hostClass}, ${t.registeredAt})`)," · ")}</p>`
    : html`<p class="sub">Registered targets: none. Live runs are blocked until you register one.</p>`;
  let body;
  if(target) body=html`<p class="ok" data-testid="target-registered">● Registered sandbox target ${target.id}: <code>${target.baseUrl}</code> · authorized by configuration (your statement, not independently verified).</p>`;
  else if(!url) body=html`<p class="sub">Enter the sandbox base URL to register it as a target.</p>`;
  else if(!a.registrable) body=html`<p class="warn" role="alert" data-testid="target-refused">● <code>${url}</code> cannot be registered: ${a.reason}</p>`;
  else body=html`<p class="sub">Host class: ${a.hostClass}. ${a.reason}</p>
    <div class="row"><label style="margin:0" for="approveChk"><input type="checkbox" id="approveChk" style="width:auto"> I confirm I am authorized to run security tests against <code>${a.baseUrl}</code></label>
    <button class="ghost" type="button" id="approveBtn">Register sandbox target</button></div>`;
  setHtml(box, html`${body}${registered}${S.execMode==="live"&&!target?html`<p class="warn">● Live runs blocked for this URL.</p>`:""}`);
  if($("approveBtn")) $("approveBtn").onclick=()=>{
    if(!$("approveChk").checked){ showStatus($("targetStatus"), "error", "Tick the confirmation checkbox first: registration must be explicit."); return; }
    const r=registerTarget(url,{ id:`TGT-${S.targets.length+1}`, registeredAt:new Date().toISOString() });
    if(!r.ok){ showStatus($("targetStatus"), "error", `Cannot register this target: ${r.reason}`); return; }
    S.targets.push(r.target);
    log(`sandbox target registered: ${r.target.id} ${r.target.baseUrl}`);
    showStatus($("targetStatus"), "success", `Registered ${r.target.id}: ${r.target.baseUrl}.`);
    renderApproval();
  };
  renderTargetBar();
}
/** Always-visible statement of what a run would hit: target, environment, authorization basis, mode and run state. */
function renderTargetBar(){
  const bar=$("targetBar"); if(!bar) return;
  const url=($("sandboxUrl").value||"").trim();
  const target=findTarget(S.targets, url);
  const done=Object.keys(S.results).length;
  const run=S.running?`running (${done}/${S.tests.length})`:S.tests.length?`${done}/${S.tests.length} tests run`:"no tests planned";
  setHtml(bar, html`<span><b>TARGET</b> <code data-testid="target-url">${url||"none"}</code></span>
    <span data-testid="target-env">${target?html`<b>SANDBOX</b> · AUTHORIZED BY CONFIGURATION <span class="sub">(not independently verified)</span>`:html`<b class="warn">NOT REGISTERED</b>`}</span>
    <span><b>MODE</b> ${S.execMode==="live"?"Live sandbox":`Mock (simulated, ${S.mockMode})`}</span>
    <span><b>RUN</b> <span data-testid="run-state">${run}</span></span>`);
}
// Optional LLM wording: user-supplied OpenAI-compatible endpoint rewords heuristic hypotheses.
// This is wording assistance only — test generation, execution and verdicts stay deterministic.
async function llmEnhance(oneId){
  S.llm.endpoint=($("llmEndpoint").value||"").trim(); S.llm.key=$("llmKey").value; S.llm.model=($("llmModel").value||"").trim();
  if(!S.llm.enabled){ showStatus($("llmStatus"), "info", "LLM wording is off. Tick 'Enable LLM' to use your endpoint (optional)."); return; }
  if(!S.llm.endpoint||!S.llm.key||!S.llm.model){ showStatus($("llmStatus"), "error", "Enter the LLM endpoint, API key and model first."); return; }
  const targets=S.tests.filter(t=>!oneId||t.id===oneId);
  for(const t of targets){
    try{
      const prompt=`Reword this security-test hypothesis in one sentence, keeping all IDs/paths exact. Law ${t.lawId} (${t.kind}). Endpoint ${t.target.method} ${t.target.path}. Identity ${t.identityId||"anonymous"}. Mutation ${JSON.stringify(t.mutation)}. Expected ${t.expectText}. Current: ${t.hypothesis}`;
      const ctl=new AbortController(); const to=setTimeout(()=>ctl.abort(),15000);
      const r=await fetch(S.llm.endpoint,{method:"POST",signal:ctl.signal,headers:{"Content-Type":"application/json","Authorization":"Bearer "+S.llm.key},
        body:JSON.stringify({model:S.llm.model,messages:[{role:"system",content:"You reword security test hypotheses precisely. Never change IDs, paths, or expected outcomes."},{role:"user",content:prompt}],max_tokens:120})});
      clearTimeout(to);
      const j=await r.json();
      const txt=j.choices&&j.choices[0]&&j.choices[0].message&&j.choices[0].message.content;
      if(txt){ t.hypothesis=String(txt).trim(); t.hypothesisSource="llm"; }
    }catch(e){ log(`${t.id} LLM reword failed: ${e.message}`); }
  }
  renderAll();
}
// Optional LLM test-idea suggestions (NOT test generation): the heuristic planner above
// is the MVP test set. Ideas below are labelled llm-suggested, never auto-executed —
// review them and, if valid, recreate manually. Keeps real LLM generation optional.
async function llmSuggest(){
  S.llm.endpoint=($("llmEndpoint").value||"").trim(); S.llm.key=$("llmKey").value; S.llm.model=($("llmModel").value||"").trim();
  if(!S.llm.enabled){ showStatus($("llmStatus"), "info", "Tick 'Enable LLM' first (optional)."); return; }
  if(!S.model){ showStatus($("llmStatus"), "empty", "Plan tests first so the LLM gets model context."); return; }
  if(!S.llm.endpoint||!S.llm.key||!S.llm.model){ showStatus($("llmStatus"), "error", "Enter the LLM endpoint, API key and model first."); return; }
  const eps=(S.model.endpoints||[]).map(e=>`${e.method} ${e.path} [${e.resource}/${e.action}, auth:${e.auth?"yes":"no"}]`).join("\n");
  const prompt=`You are a security-test reviewer. Given this sandbox API model, suggest up to 5 EXTRA boundary-test ideas NOT already covered (covered kinds: BOLA baseline/boundary/anonymous, sequence own-then-foreign, admin deny/allow, data-leak, per-endpoint anonymous). Reply as short numbered lines, each: METHOD path — idea — why. Model:\nEndpoints:\n${eps}\nOwnership field(s): ${Object.keys(S.model.resources||{}).map(r=>r+"."+((S.model.resources[r]||{}).ownershipField||"none")).join(", ")}\nRoles: ${[...new Set((S.model.testIdentities||[]).map(i=>i.role))].join(", ")}\nSensitive: ${sensFields().slice(0,10).join(", ")}`;
  setHtml($("llmIdeas"), html`<p class="sub">Asking LLM…</p>`);
  try{
    const ctl=new AbortController(); const to=setTimeout(()=>ctl.abort(),20000);
    const r=await fetch(S.llm.endpoint,{method:"POST",signal:ctl.signal,headers:{"Content-Type":"application/json","Authorization":"Bearer "+S.llm.key},
      body:JSON.stringify({model:S.llm.model,messages:[{role:"system",content:"You suggest extra sandbox authorization test ideas as short numbered lines. No exploit payloads, no production targets."},{role:"user",content:prompt}],max_tokens:300})});
    clearTimeout(to);
    const j=await r.json();
    const txt=j.choices&&j.choices[0]&&j.choices[0].message&&j.choices[0].message.content;
    if(!txt) throw new Error("empty LLM reply");
    S.llmIdeas=String(txt).split("\n").map(s=>s.trim()).filter(Boolean);
    renderLlmIdeas();
  }catch(e){ setHtml($("llmIdeas"), html`<p class="warn">LLM suggestion failed: ${e.message}. Heuristic set above is unaffected.</p>`); }
}
function renderLlmIdeas(){
  const box=$("llmIdeas"); if(!box) return;
  setHtml(box, S.llmIdeas.length?html`<p class="sub">LLM-suggested ideas (source: llm — <b>not executed</b>, review before recreating):</p>${S.llmIdeas.map((s,i)=>html`<div class="test"><h3>Idea ${i+1} <span class="badge b-MEDIUM">llm-suggested</span></h3><div>${s}</div></div>`)}`:html`<p class="sub">No LLM suggestions yet. Heuristic planner output above is the MVP test set.</p>`);
}
function download(name,text){ const a=document.createElement("a"); a.href=URL.createObjectURL(new Blob([text],{type:"application/json"})); a.download=name; a.click(); }

async function loadDemoModel(){
  showStatus($("modelStatus"), "loading", "Loading the demo model…");
  try{
    $("modelText").value = await fetchText("samples/sample-testable-model.json");
    showStatus($("modelStatus"), "success", "Demo model loaded. Next: PLAN TESTS.");
  }catch(e){ showStatus($("modelStatus"), "error", `Could not load the demo model: ${e.message}`, { retry: loadDemoModel }); }
}

window.addEventListener("DOMContentLoaded",()=>{
  $("demoModelBtn").onclick=loadDemoModel;
  $("fileBtn").onclick=()=>$("modelFile").click();
  $("modelFile").addEventListener("change",e=>{
    const f=e.target.files[0]; if(!f) return;
    const rd=new FileReader();
    showStatus($("modelStatus"), "loading", `Reading ${f.name}…`);
    rd.onload=()=>{ $("modelText").value=rd.result; showStatus($("modelStatus"), "success", `Loaded ${f.name}. Next: PLAN TESTS.`); };
    rd.onerror=()=>showStatus($("modelStatus"), "error", `Could not read ${f.name}: ${rd.error?rd.error.message:"unknown error"}`);
    rd.readAsText(f);
  });
  $("planBtn").onclick=()=>{
    const txt=$("modelText").value.trim(); if(!txt){ showStatus($("modelStatus"), "empty", "No model yet: paste testable-security-model.json, upload it, or load the demo model."); return; }
    try{ loadModel(JSON.parse(txt)); }catch(e){ showStatus($("modelStatus"), "error", `Invalid model: ${e.message}`); return; }
    S.execMode=$("execMode").value; S.mockMode=$("mockMode").value; S.sandboxUrl=$("sandboxUrl").value.trim();
    S.auth.scheme=$("authScheme").value; S.auth.apiKeyName=$("apiKeyName").value.trim()||"X-API-Key"; S.auth.cookieName=$("cookieName").value.trim()||"session";
    planTests(); S.sel=S.tests[0]?S.tests[0].id:null;
    $("console").textContent=`planned ${S.tests.length} cases from ${S.model.laws.length} laws (${S.execMode}${S.execMode==="mock"?"-"+S.mockMode:""}).`;
    log(`planner: ${S.model.laws.length} laws → ${S.tests.length} cases (heuristic; all eligible endpoints)${(S.planWarnings||[]).length?" — "+S.planWarnings.join("; "):""}`);
    renderAll(); renderAuth();
    showStatus($("modelStatus"), S.tests.length?"success":"empty", S.tests.length ? `Planned ${S.tests.length} test cases from ${S.model.laws.length} laws.` : "The model produced no test cases (no laws with eligible endpoints).");
  };
  $("execMode").onchange=e=>{ S.execMode=e.target.value; renderAll(); renderApproval(); };
  $("mockMode").onchange=e=>{ S.mockMode=e.target.value; renderTargetBar(); };
  $("authScheme").onchange=e=>{ S.auth.scheme=e.target.value; renderAuth(); renderPreview(); };
  $("runAllBtn").onclick=runAll;
  $("resetBtn").onclick=()=>{ S.results={}; S.findings=[]; renderAll(); $("console").textContent="reset."; };
  $("llmAllBtn").onclick=()=>llmEnhance(null);
  $("llmSuggestBtn").onclick=()=>llmSuggest();
  $("llmEnable").onchange=e=>{ S.llm.enabled=e.target.checked; };
  $("sandboxUrl").oninput=()=>{ S.sandboxUrl=$("sandboxUrl").value.trim(); renderApproval(); };
  $("dlEvidence").onclick=()=>download("evidence-package.json",JSON.stringify(evidencePackage(),null,2));
  $("copyEvidence").onclick=async()=>{
    try{ await copyText(JSON.stringify(evidencePackage(),null,2)); showStatus($("evidenceStatus"), "success", "Evidence package copied."); }
    catch(e){ showStatus($("evidenceStatus"), "error", `Copy failed (${e.message}). Use Download instead.`); }
  };
  renderApproval();
});
