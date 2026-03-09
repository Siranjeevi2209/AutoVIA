import { useState, useEffect, useCallback, useMemo } from "react";

// ═══════════════════════════════════════════════════════════════════
// AUTO-VIA v3 — Clean Light Dashboard Edition
// ═══════════════════════════════════════════════════════════════════

const API_PROXY = "/api/proxy";

const ECU = {
  braking:      { name: "Braking",       full: "Electronic Braking",    asil: "ASIL-D", mod: 1.30, color: "#e11d48", bg: "#fff1f2", ico: "🛑" },
  steering:     { name: "Steering",      full: "Power Steering",        asil: "ASIL-D", mod: 1.30, color: "#be123c", bg: "#ffe4e6", ico: "🎯" },
  powertrain:   { name: "Powertrain",    full: "Powertrain / Engine",   asil: "ASIL-C", mod: 1.20, color: "#ea580c", bg: "#fff7ed", ico: "⚡" },
  chassis:      { name: "Chassis",       full: "Chassis Control",       asil: "ASIL-C", mod: 1.20, color: "#d97706", bg: "#fffbeb", ico: "🔧" },
  adas:         { name: "ADAS",          full: "ADAS / Autonomous",     asil: "ASIL-D", mod: 1.30, color: "#7c3aed", bg: "#f5f3ff", ico: "🤖" },
  gateway:      { name: "Gateway",       full: "Gateway ECU",           asil: "ASIL-B", mod: 1.10, color: "#2563eb", bg: "#eff6ff", ico: "🌐" },
  telematics:   { name: "Telematics",    full: "Telematics Unit",       asil: "ASIL-A", mod: 1.05, color: "#0891b2", bg: "#ecfeff", ico: "📡" },
  infotainment: { name: "Infotainment",  full: "Infotainment / IVI",    asil: "QM",     mod: 1.00, color: "#059669", bg: "#ecfdf5", ico: "🎵" },
  body:         { name: "Body",          full: "Body Control",          asil: "QM",     mod: 1.00, color: "#65a30d", bg: "#f7fee7", ico: "🚗" },
  diagnostics:  { name: "Diagnostics",   full: "Diagnostics",           asil: "QM",     mod: 1.00, color: "#64748b", bg: "#f8fafc", ico: "🔍" },
};

const REACH = { "remote_external|telematics":1.25,"remote_external|wifi_bt":1.18,"remote_adjacent|wifi_bt":1.15,"remote_adjacent|ethernet":1.12,"local|can":1.05,"local|diagnostic":1.05,"physical|diagnostic":1.00,"physical|can":0.95 };
const EXPLOIT = { active_exploitation:1.40,weaponized:1.30,functional:1.15,poc:1.10,unknown:0.90 };
const TIERS = {
  P0_critical: { tag:"Critical", color:"#e11d48", bg:"#fff1f2", sla:"Immediate (24–72h)", act:"Patch" },
  P1_high:     { tag:"High",     color:"#ea580c", bg:"#fff7ed", sla:"Within 7 days",      act:"Patch" },
  P2_medium:   { tag:"Medium",   color:"#d97706", bg:"#fffbeb", sla:"Within 30 days",     act:"Mitigate" },
  P3_low:      { tag:"Low",      color:"#2563eb", bg:"#eff6ff", sla:"Scheduled",          act:"Monitor" },
};
const SURFACES=["remote_external","remote_adjacent","local","physical"];
const PATHS=["telematics","wifi_bt","ethernet","can","diagnostic","unknown"];
const EXPLOITS=["active_exploitation","weaponized","functional","poc","unknown"];

const CPE_RULES = [
  [/qnx/i,"adas"],[/vxworks/i,"powertrain"],[/autosar/i,"powertrain"],[/freertos/i,"gateway"],
  [/zephyr/i,"body"],[/threadx/i,"telematics"],[/android.*auto/i,"infotainment"],
  [/openssl/i,"gateway"],[/wolfssl/i,"telematics"],[/mbedtls/i,"telematics"],
  [/linux.*kernel/i,"gateway"],[/can.*bus|socketcan|j1939/i,"gateway"],[/flexray/i,"chassis"],
  [/doip|unified.*diagnostic/i,"diagnostics"],[/some.*ip/i,"adas"],[/obd/i,"diagnostics"],
  [/bluetooth|ble/i,"infotainment"],[/wifi|wi-fi/i,"infotainment"],[/v2x|dsrc/i,"telematics"],
  [/cellular|5g|lte/i,"telematics"],[/ota|over.*the.*air/i,"telematics"],
  [/lidar/i,"adas"],[/mobileye|nvidia.*drive/i,"adas"],[/bosch/i,"braking"],
  [/continental/i,"chassis"],[/denso/i,"powertrain"],[/harman/i,"infotainment"],
  [/nxp/i,"gateway"],[/infineon/i,"powertrain"],[/renesas/i,"powertrain"],
  [/brake|braking|abs|esc/i,"braking"],[/steering|eps/i,"steering"],
  [/airbag|srs/i,"chassis"],[/engine.*control|ecm/i,"powertrain"],
  [/battery.*management|bms/i,"powertrain"],[/door.*lock|keyless|key.*fob/i,"body"],
  [/gateway.*ecu/i,"gateway"],[/telematics.*control|tcu/i,"telematics"],
  [/infotainment|ivi|head.*unit/i,"infotainment"],
  [/toyota|tesla|bmw|mercedes|volkswagen|ford|hyundai|honda|nissan|kia|volvo/i,"gateway"],
  [/geotab|fleet/i,"telematics"],[/ev.*charg/i,"powertrain"],[/tpms|tire.*pressure/i,"body"],
];

const AUTOMOTIVE_NVD_SEARCHES = [
  {keyword:"qnx",label:"QNX"},{keyword:"vxworks",label:"VxWorks"},{keyword:"autosar",label:"AUTOSAR"},
  {keyword:"android automotive",label:"Android Auto"},{keyword:"freertos",label:"FreeRTOS"},
  {keyword:"openssl",label:"OpenSSL"},{keyword:"wolfssl",label:"WolfSSL"},{keyword:"mbedtls",label:"mbedTLS"},
  {keyword:"can bus",label:"CAN Bus"},{keyword:"bluetooth automotive",label:"BT Auto"},
  {keyword:"bosch automotive",label:"Bosch"},{keyword:"continental automotive",label:"Continental"},
  {keyword:"denso",label:"Denso"},{keyword:"harman",label:"Harman"},
  {keyword:"nvidia drive",label:"NVIDIA"},{keyword:"mobileye",label:"Mobileye"},
  {keyword:"linux kernel CAN",label:"Linux CAN"},{keyword:"linux kernel bluetooth",label:"Linux BT"},
  {keyword:"telematics",label:"Telematics"},{keyword:"vehicle gateway",label:"Gateway"},
  {keyword:"nxp",label:"NXP"},{keyword:"infineon",label:"Infineon"},{keyword:"renesas",label:"Renesas"},
  {keyword:"toyota vehicle",label:"Toyota"},{keyword:"tesla vehicle",label:"Tesla"},
  {keyword:"CAN injection",label:"CAN Inject"},{keyword:"keyless entry vehicle",label:"Keyless"},
  {keyword:"EV charging station",label:"EV Charge"},{keyword:"autonomous driving",label:"ADAS"},
  {keyword:"connected car",label:"Connected Car"},
];

// ── ENGINE ────────────────────────────────────────────────────────
function computeARS(v) {
  const b=v.cvss_v4_base_score||v.cvss_base_score||0,e=ECU[v.ecu_domain],am=e?e.mod:1,rm=REACH[`${v.attack_surface}|${v.network_path}`]||1,em=EXPLOIT[v.exploit_maturity]||.9;
  const raw=b*am*rm*em,score=Math.min(10,+raw.toFixed(2));
  let tier=v.kev_listed?"P0_critical":score>=9?"P0_critical":score>=7?"P1_high":score>=4?"P2_medium":"P3_low";
  return{ars:score,priority_tier:tier,recommended_action:TIERS[tier].act,raw_score:raw,asil_mod:am,reach_mod:rm,exploit_mod:em,
    justification_trace:[`CVSS Base: ${b}`,`ECU: ${e?.full||v.ecu_domain} — ×${am}`,`Reach: ${v.attack_surface}/${v.network_path} — ×${rm}`,
      `Exploit: ${v.exploit_maturity} — ×${em}`,`Raw: ${raw.toFixed(3)}`,`ARS: ${score}`,v.kev_listed?"⚡ KEV → P0":`Tier: ${tier}`]};
}
function classify(text){for(const[p,d]of CPE_RULES)if(p.test(text))return d;return"gateway";}
function inferSurface(vec,desc){let s="local",p="unknown";const d=(desc||"").toLowerCase();if(vec?.includes("AV:N"))s="remote_external";else if(vec?.includes("AV:A"))s="remote_adjacent";else if(vec?.includes("AV:P"))s="physical";if(d.match(/cellular|ota|telematics|5g|lte|v2x|cloud/))p="telematics";else if(d.match(/bluetooth|ble|wifi|wireless|nfc|uwb/))p="wifi_bt";else if(d.match(/ethernet|tcp|some.ip/))p="ethernet";else if(d.match(/can|j1939|obd|lin|flexray/))p="can";else if(d.match(/diagnostic|uds|doip|jtag|usb/))p="diagnostic";else if(s==="remote_external")p="telematics";else if(s==="remote_adjacent")p="wifi_bt";else if(s==="physical")p="diagnostic";else p="can";return{s,p};}
function parseNVD(item,kevSet){const c=item.cve;if(!c?.id)return null;const desc=c.descriptions?.find(d=>d.lang==="en")?.value||"";const m=c.metrics||{};let bs=0,vec="";if(m.cvssMetricV40?.length){bs=m.cvssMetricV40[0].cvssData?.baseScore||0;vec=m.cvssMetricV40[0].cvssData?.vectorString||"";}else if(m.cvssMetricV31?.length){bs=m.cvssMetricV31[0].cvssData?.baseScore||0;vec=m.cvssMetricV31[0].cvssData?.vectorString||"";}else if(m.cvssMetricV30?.length){bs=m.cvssMetricV30[0].cvssData?.baseScore||0;vec=m.cvssMetricV30[0].cvssData?.vectorString||"";}else if(m.cvssMetricV2?.length){bs=m.cvssMetricV2[0].cvssData?.baseScore||0;vec=m.cvssMetricV2[0].cvssData?.vectorString||"";}if(!bs)return null;const cpes=[];(c.configurations||[]).forEach(x=>(x.nodes||[]).forEach(n=>(n.cpeMatch||[]).forEach(m=>m.criteria&&cpes.push(m.criteria))));const cwes=[];(c.weaknesses||[]).forEach(w=>(w.description||[]).forEach(d=>d.value&&!d.value.includes("noinfo")&&!d.value.includes("Other")&&cwes.push(d.value)));const dom=classify(desc+" "+cpes.join(" "));const{s,p}=inferSurface(vec,desc);const kev=kevSet.has(c.id);let prod="";if(cpes.length){const x=cpes[0].split(":");if(x.length>=5)prod=`${x[3]}:${x[4]}${x[5]&&x[5]!=="*"?":"+x[5]:""}`;}if(!prod){const mm=desc.match(/(?:in|of|for)\s+([A-Z][\w\s.-]+?)(?:\s+(?:before|prior|through|allows|could|may|is|via))/i);prod=mm?mm[1].trim():"";}const v={cve_id:c.id,published:c.published?.split("T")[0]||"",modified:c.lastModified?.split("T")[0]||"",description:desc,cvss_v4_base_score:bs,cvss_vector:vec,cwe_ids:cwes,cpe_matches:cpes.slice(0,5),affected_product:prod,ecu_domain:dom,attack_surface:s,network_path:p,exploit_maturity:kev?"active_exploitation":"unknown",kev_listed:kev,source_feeds:kev?["NVD","CISA_KEV"]:["NVD"],classification_method:"cpe_taxonomy_rule"};return{...v,...computeARS(v)};}

// ═══════════════════════════════════════════════════════════════════
// CSS
// ═══════════════════════════════════════════════════════════════════
const CSS = `
@import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=Fira+Code:wght@400;500;600&display=swap');
:root{--bg:#f8fafc;--surface:#ffffff;--surface-2:#f1f5f9;--border:#e2e8f0;--border-h:#cbd5e1;--text-0:#0f172a;--text-1:#334155;--text-2:#64748b;--text-3:#94a3b8;
--blue:#2563eb;--blue-bg:#eff6ff;--cyan:#0891b2;--red:#e11d48;--amber:#d97706;--green:#059669;--purple:#7c3aed;
--font:'Plus Jakarta Sans',sans-serif;--mono:'Fira Code',monospace;--shadow:0 1px 3px rgba(0,0,0,.06),0 1px 2px rgba(0,0,0,.04);--shadow-md:0 4px 6px -1px rgba(0,0,0,.07),0 2px 4px -2px rgba(0,0,0,.05);--shadow-lg:0 10px 15px -3px rgba(0,0,0,.08),0 4px 6px -4px rgba(0,0,0,.04);--radius:14px;}
*{box-sizing:border-box;margin:0;padding:0;}body{background:var(--bg);}
::-webkit-scrollbar{width:6px;}::-webkit-scrollbar-track{background:var(--surface-2);}::-webkit-scrollbar-thumb{background:var(--border-h);border-radius:6px;}
::selection{background:#2563eb20;}
@keyframes fadeUp{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:translateY(0)}}
@keyframes slideIn{from{transform:translateX(100%);opacity:0}to{transform:translateX(0);opacity:1}}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.5}}
option{background:#fff;color:#0f172a;}
`;

// ── ATOMS ─────────────────────────────────────────────────────────
const Tag = ({children,color,bg,style:s,...p}) => (
  <span {...p} style={{display:"inline-flex",alignItems:"center",gap:4,padding:"4px 10px",borderRadius:20,fontSize:11,fontWeight:600,fontFamily:"var(--font)",color:color||"var(--text-1)",background:bg||"var(--surface-2)",whiteSpace:"nowrap",...(s||{})}}>{children}</span>
);

const TierTag = ({tier}) => {const t=TIERS[tier];return t?<Tag color={t.color} bg={t.bg}><span style={{width:6,height:6,borderRadius:"50%",background:t.color,display:"inline-block"}}/>{t.tag}</Tag>:null;};
const KevTag = () => <Tag color="#fff" bg="#e11d48" style={{fontSize:10,padding:"3px 8px",fontWeight:700}}>⚡ KEV</Tag>;
const EcuTag = ({d}) => {const e=ECU[d];return e?<Tag color={e.color} bg={e.bg}>{e.ico} {e.name}</Tag>:<span>{d}</span>;};
const AsilTag = ({a}) => {const c=a?.includes("D")?"#e11d48":a?.includes("C")?"#ea580c":a?.includes("B")?"#d97706":a?.includes("A")?"#2563eb":"#64748b";return<Tag color={c} bg={`${c}10`}>{a}</Tag>;};

function ScoreCircle({score,size=56}){
  const r=size*.36,circ=2*Math.PI*r,off=circ-(score/10)*circ;
  const c=score>=9?"#e11d48":score>=7?"#ea580c":score>=4?"#d97706":"#2563eb";
  return(<svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} style={{flexShrink:0}}>
    <circle cx={size/2} cy={size/2} r={r} fill="none" stroke="#e2e8f0" strokeWidth={size*.065}/>
    <circle cx={size/2} cy={size/2} r={r} fill="none" stroke={c} strokeWidth={size*.065} strokeDasharray={circ} strokeDashoffset={off} strokeLinecap="round" transform={`rotate(-90 ${size/2} ${size/2})`} style={{transition:"stroke-dashoffset .8s cubic-bezier(.4,0,.2,1)"}}/>
    <text x={size/2} y={size/2-size*.03} textAnchor="middle" fill="#0f172a" fontSize={size*.26} fontWeight="700" fontFamily="var(--mono)">{score.toFixed(1)}</text>
    <text x={size/2} y={size/2+size*.15} textAnchor="middle" fill="#94a3b8" fontSize={size*.12} fontWeight="600" fontFamily="var(--font)">ARS</text>
  </svg>);
}

const Card = ({children,pad,style:s,...p}) => (<div {...p} style={{background:"var(--surface)",border:"1px solid var(--border)",borderRadius:"var(--radius)",padding:pad||20,boxShadow:"var(--shadow)",...(s||{})}}>{children}</div>);
const CardTitle = ({children,icon}) => (<div style={{display:"flex",alignItems:"center",gap:8,marginBottom:16}}>{icon&&<span style={{fontSize:18}}>{icon}</span>}<h3 style={{fontFamily:"var(--font)",fontSize:14,fontWeight:700,color:"var(--text-0)",letterSpacing:"-.01em"}}>{children}</h3></div>);

// ── DETAIL PANEL ──────────────────────────────────────────────────
function DetailPanel({v,onClose}){
  if(!v)return null;const e=ECU[v.ecu_domain],t=TIERS[v.priority_tier];
  const[tab,setTab]=useState("info");
  const avr={record_id:`avia-${v.cve_id.replace("CVE-","").replace("-","-")}`,cve_id:v.cve_id,source_feeds:v.source_feeds,published_date:v.published,last_modified_date:v.modified,cvss_v4_base_score:v.cvss_v4_base_score,cvss_vector:v.cvss_vector,exploit_maturity:v.exploit_maturity,kev_listed:v.kev_listed,affected_product:v.affected_product,ecu_domain:v.ecu_domain,safety_criticality:e?.asil||"QM",attack_surface:v.attack_surface,network_path:v.network_path,contextual_risk_score:v.ars,priority_tier:v.priority_tier,recommended_action:v.recommended_action,justification_trace:v.justification_trace};
  const tara={asset_id:`TARA-ASSET-${(v.affected_product||v.cve_id).replace(/[\s:]/g,"_")}-${v.ecu_domain}`,asset_name:v.affected_product,asset_type:"software_component",ecu_domain:v.ecu_domain,safety_criticality:e?.asil||"QM",affected_cve:v.cve_id,ars_score:v.ars,priority_tier:v.priority_tier,recommended_action:v.recommended_action,treatment_sla:t?.sla,damage_scenario:`Exploitation of ${v.affected_product} in ${e?.full} domain via ${v.attack_surface} (${v.network_path})`,iso_21434_clause:"Cl.15",generated_at:new Date().toISOString()};
  const dl=(data,name)=>{const b=new Blob([JSON.stringify(data,null,2)],{type:"application/json"});const u=URL.createObjectURL(b);const a=document.createElement("a");a.href=u;a.download=name;a.click();URL.revokeObjectURL(u);};
  const Row=({label,children})=>(<div style={{display:"flex",justifyContent:"space-between",alignItems:"center",padding:"10px 0",borderBottom:"1px solid var(--border)"}}><span style={{fontSize:12,color:"var(--text-2)",fontWeight:600}}>{label}</span><span>{children}</span></div>);
  const dlBtn={width:"100%",marginTop:14,padding:"12px",borderRadius:10,background:"var(--blue-bg)",border:"1px solid #bfdbfe",color:"var(--blue)",fontFamily:"var(--mono)",fontSize:12,fontWeight:600,cursor:"pointer",textAlign:"center"};

  return(
    <div style={{position:"fixed",top:0,right:0,bottom:0,width:"min(620px,94vw)",background:"var(--surface)",borderLeft:"1px solid var(--border)",zIndex:1000,display:"flex",flexDirection:"column",animation:"slideIn .3s ease",boxShadow:"-10px 0 40px rgba(0,0,0,.1)"}}>
      <div style={{padding:"20px 24px",borderBottom:"1px solid var(--border)",display:"flex",alignItems:"center",gap:14}}>
        <ScoreCircle score={v.ars} size={56}/>
        <div style={{flex:1}}><div style={{display:"flex",alignItems:"center",gap:10}}><span style={{fontFamily:"var(--mono)",fontSize:17,fontWeight:700,color:"var(--text-0)"}}>{v.cve_id}</span><a href={`https://nvd.nist.gov/vuln/detail/${v.cve_id}`} target="_blank" rel="noopener noreferrer" style={{display:"inline-flex",alignItems:"center",gap:4,padding:"4px 10px",borderRadius:8,background:"var(--blue-bg)",border:"1px solid #bfdbfe",color:"var(--blue)",fontFamily:"var(--mono)",fontSize:11,fontWeight:600,textDecoration:"none",transition:"all .2s"}} onMouseEnter={e=>{e.currentTarget.style.background="var(--blue)";e.currentTarget.style.color="#fff";}} onMouseLeave={e=>{e.currentTarget.style.background="var(--blue-bg)";e.currentTarget.style.color="var(--blue)";}}>↗ NVD</a></div>
          <div style={{display:"flex",gap:6,marginTop:6,flexWrap:"wrap"}}><TierTag tier={v.priority_tier}/>{v.kev_listed&&<KevTag/>}<EcuTag d={v.ecu_domain}/></div></div>
        <button onClick={onClose} style={{background:"var(--surface-2)",border:"1px solid var(--border)",borderRadius:10,color:"var(--text-2)",padding:"8px 12px",cursor:"pointer",fontSize:16,lineHeight:1}}>✕</button>
      </div>
      <div style={{display:"flex",borderBottom:"1px solid var(--border)",padding:"0 24px"}}>
        {[["info","Overview"],["ars","ARS Score"],["avr","AVR JSON"],["tara","TARA"]].map(([id,label])=>(
          <button key={id} onClick={()=>setTab(id)} style={{background:"none",border:"none",padding:"12px 16px",cursor:"pointer",fontFamily:"var(--font)",fontSize:12,fontWeight:600,color:tab===id?"var(--blue)":"var(--text-3)",borderBottom:tab===id?"2px solid var(--blue)":"2px solid transparent",transition:"all .2s"}}>{label}</button>
        ))}
      </div>
      <div style={{flex:1,overflow:"auto",padding:24}}>
        {tab==="info"&&<div style={{display:"flex",flexDirection:"column",gap:20}}>
          <div><CardTitle icon="📄">Description</CardTitle><p style={{color:"var(--text-1)",fontSize:13,lineHeight:1.8}}>{v.description}</p>
            <a href={`https://nvd.nist.gov/vuln/detail/${v.cve_id}`} target="_blank" rel="noopener noreferrer" style={{display:"inline-flex",alignItems:"center",gap:6,marginTop:12,padding:"8px 14px",borderRadius:8,background:"var(--blue-bg)",border:"1px solid #bfdbfe",color:"var(--blue)",fontFamily:"var(--mono)",fontSize:12,fontWeight:600,textDecoration:"none"}}>↗ View on NVD (nist.gov)</a></div>
          <div><CardTitle icon="🏷️">Classification</CardTitle><Row label="ECU Domain"><EcuTag d={v.ecu_domain}/></Row><Row label="ASIL"><AsilTag a={e?.asil}/></Row><Row label="Attack Surface"><Tag>{v.attack_surface}</Tag></Row><Row label="Network Path"><Tag>{v.network_path}</Tag></Row><Row label="CVSS"><span style={{fontFamily:"var(--mono)",fontWeight:700,fontSize:14}}>{v.cvss_v4_base_score}</span></Row><Row label="Exploit"><Tag color={v.exploit_maturity==="active_exploitation"?"#e11d48":"var(--text-2)"} bg={v.exploit_maturity==="active_exploitation"?"#fff1f2":"var(--surface-2)"}>{v.exploit_maturity}</Tag></Row><Row label="KEV"><span style={{fontWeight:700,color:v.kev_listed?"#e11d48":"var(--text-3)"}}>{v.kev_listed?"YES":"NO"}</span></Row></div>
          <div><CardTitle icon="⏰">Treatment SLA</CardTitle><div style={{padding:14,borderRadius:12,background:t?.bg,border:`1px solid ${t?.color}20`}}><div style={{fontFamily:"var(--font)",fontSize:14,fontWeight:700,color:t?.color}}>{t?.sla}</div><div style={{fontSize:12,color:"var(--text-2)",marginTop:4}}>Action: <strong style={{color:"var(--text-0)"}}>{v.recommended_action}</strong></div></div></div>
        </div>}
        {tab==="ars"&&<div style={{display:"flex",flexDirection:"column",gap:20}}>
          <div><CardTitle icon="🧮">ARS Formula</CardTitle><div style={{padding:14,borderRadius:10,background:"var(--blue-bg)",fontFamily:"var(--mono)",fontSize:12,color:"var(--blue)"}}>ARS = MIN(10.0, Base × ASIL × Reach × Exploit)</div></div>
          <div><CardTitle icon="📊">Breakdown</CardTitle>
            {[["CVSS Base",v.cvss_v4_base_score,"—",v.cvss_v4_base_score],[`ASIL (${e?.asil})`,v.ecu_domain,`×${v.asil_mod}`,(v.cvss_v4_base_score*v.asil_mod).toFixed(2)],["Reachability",`${v.attack_surface}/${v.network_path}`,`×${v.reach_mod}`,(v.cvss_v4_base_score*v.asil_mod*v.reach_mod).toFixed(2)],["Exploit",v.exploit_maturity,`×${v.exploit_mod}`,v.raw_score?.toFixed(2)]].map(([f,val,mod,run],i)=>(
              <div key={i} style={{display:"grid",gridTemplateColumns:"1.2fr 1fr .6fr .8fr",gap:8,padding:"10px 0",borderBottom:"1px solid var(--border)",fontSize:12}}>
                <span style={{color:"var(--text-1)",fontWeight:600}}>{f}</span><span style={{fontFamily:"var(--mono)",color:"var(--text-2)"}}>{val}</span><span style={{fontFamily:"var(--mono)",color:"var(--blue)"}}>{mod}</span><span style={{fontFamily:"var(--mono)",fontWeight:700,color:"var(--text-0)",textAlign:"right"}}>{run}</span></div>))}
            <div style={{display:"flex",justifyContent:"space-between",padding:"14px 0",borderTop:"2px solid var(--border-h)"}}><span style={{fontWeight:700,fontSize:14}}>Final ARS</span><span style={{fontFamily:"var(--mono)",fontSize:24,fontWeight:800,color:t?.color}}>{v.ars?.toFixed(1)}</span></div></div>
          <div><CardTitle icon="📋">Audit Trail</CardTitle>{v.justification_trace?.map((l,i)=>(<div key={i} style={{display:"flex",gap:8,padding:"6px 10px",borderRadius:8,background:i%2?"transparent":"var(--surface-2)",fontSize:11,fontFamily:"var(--mono)"}}><span style={{color:"var(--text-3)",minWidth:18}}>{String(i+1).padStart(2,"0")}</span><span style={{color:"var(--text-1)"}}>{l}</span></div>))}</div>
        </div>}
        {tab==="avr"&&<div><CardTitle icon="📦">AVR Record</CardTitle><pre style={{background:"var(--surface-2)",border:"1px solid var(--border)",borderRadius:12,padding:16,fontSize:11,fontFamily:"var(--mono)",color:"var(--text-1)",overflow:"auto",whiteSpace:"pre-wrap",lineHeight:1.7,maxHeight:500}}>{JSON.stringify(avr,null,2)}</pre><button onClick={()=>dl(avr,`${v.cve_id}_AVR.json`)} style={dlBtn}>⬇ Download AVR</button></div>}
        {tab==="tara"&&<div><CardTitle icon="📑">TARA Asset Register</CardTitle><pre style={{background:"var(--surface-2)",border:"1px solid var(--border)",borderRadius:12,padding:16,fontSize:11,fontFamily:"var(--mono)",color:"var(--text-1)",overflow:"auto",whiteSpace:"pre-wrap",lineHeight:1.7,maxHeight:500}}>{JSON.stringify(tara,null,2)}</pre><button onClick={()=>dl(tara,`TARA_${v.cve_id}.json`)} style={dlBtn}>⬇ Download TARA</button></div>}
      </div>
    </div>
  );
}

// ── STATS ─────────────────────────────────────────────────────────
function Stats({vulns,loading}){
  const items=[{l:"Total AVRs",v:loading?"…":vulns.length,c:"var(--blue)",bg:"var(--blue-bg)",ico:"📊"},{l:"Critical",v:loading?"…":vulns.filter(x=>x.priority_tier==="P0_critical").length,c:"#e11d48",bg:"#fff1f2",ico:"🔴"},{l:"High",v:loading?"…":vulns.filter(x=>x.priority_tier==="P1_high").length,c:"#ea580c",bg:"#fff7ed",ico:"🟠"},{l:"Medium",v:loading?"…":vulns.filter(x=>x.priority_tier==="P2_medium").length,c:"#d97706",bg:"#fffbeb",ico:"🟡"},{l:"Low",v:loading?"…":vulns.filter(x=>x.priority_tier==="P3_low").length,c:"#2563eb",bg:"#eff6ff",ico:"🔵"},{l:"KEV",v:loading?"…":vulns.filter(x=>x.kev_listed).length,c:"#e11d48",bg:"#fff1f2",ico:"⚡"},{l:"Avg ARS",v:loading?"…":vulns.length?(vulns.reduce((s,x)=>s+x.ars,0)/vulns.length).toFixed(1):"0",c:"#7c3aed",bg:"#f5f3ff",ico:"📈"}];
  return(<div style={{display:"grid",gridTemplateColumns:"repeat(7,1fr)",gap:12}}>
    {items.map((s,i)=>(<Card key={i} pad="16px" style={{textAlign:"center",animation:`fadeUp .5s ease ${i*.05}s both`}}>
      <div style={{fontSize:22,marginBottom:4}}>{s.ico}</div>
      <div style={{fontFamily:"var(--mono)",fontSize:26,fontWeight:800,color:s.c,lineHeight:1.1}}>{s.v}</div>
      <div style={{fontSize:11,fontWeight:600,color:"var(--text-3)",marginTop:6}}>{s.l}</div>
    </Card>))}
  </div>);
}

// ── CHARTS ────────────────────────────────────────────────────────
function EcuChart({vulns,onFilter}){const counts={};vulns.forEach(v=>{counts[v.ecu_domain]=(counts[v.ecu_domain]||0)+1;});const sorted=Object.entries(counts).sort((a,b)=>b[1]-a[1]);const max=Math.max(...sorted.map(([,c])=>c),1);
  return(<Card><CardTitle icon="🏎️">ECU Domains</CardTitle>{sorted.map(([d,c],i)=>{const e=ECU[d];const pct=(c/max)*100;return(<div key={d} onClick={()=>onFilter&&onFilter("domain",d)} style={{display:"flex",alignItems:"center",gap:10,marginBottom:8,animation:`fadeUp .4s ease ${i*.04}s both`,cursor:"pointer",borderRadius:8,padding:"2px 4px",transition:"background .15s"}}
    onMouseEnter={e=>e.currentTarget.style.background="var(--surface-2)"} onMouseLeave={e=>e.currentTarget.style.background="transparent"}>
    <span style={{minWidth:110,fontSize:12,fontWeight:600,color:e?.color||"var(--text-2)"}}>{e?.ico} {e?.name||d}</span>
    <div style={{flex:1,height:24,background:"var(--surface-2)",borderRadius:8,overflow:"hidden"}}>
      <div style={{height:"100%",width:`${pct}%`,background:`linear-gradient(90deg,${e?.color}30,${e?.color}10)`,borderRadius:8,transition:"width 1s cubic-bezier(.4,0,.2,1)"}}/>
    </div>
    <span style={{fontFamily:"var(--mono)",fontSize:11,fontWeight:700,color:e?.color,minWidth:36,textAlign:"right",flexShrink:0}}>{c}</span>
  </div>);})}</Card>);
}

function PriorityChart({vulns,onFilter}){const total=vulns.length||1;
  return(<Card><CardTitle icon="📋">Priority Distribution</CardTitle>{Object.entries(TIERS).map(([k,t],i)=>{const c=vulns.filter(v=>v.priority_tier===k).length,pct=((c/total)*100).toFixed(0);return(
    <div key={k} onClick={()=>onFilter&&onFilter("priority",k)} style={{display:"flex",alignItems:"center",gap:10,marginBottom:10,animation:`fadeUp .4s ease ${i*.06}s both`,cursor:"pointer",borderRadius:8,padding:"2px 4px",transition:"background .15s"}}
      onMouseEnter={e=>e.currentTarget.style.background="var(--surface-2)"} onMouseLeave={e=>e.currentTarget.style.background="transparent"}>
      <span style={{minWidth:72}}><TierTag tier={k}/></span>
      <div style={{flex:1,height:28,background:"var(--surface-2)",borderRadius:8,overflow:"hidden"}}>
        <div style={{height:"100%",width:`${pct}%`,background:t.bg,borderRadius:8,transition:"width 1s ease",borderRight:c>0?`3px solid ${t.color}`:"none"}}/>
      </div>
      <span style={{fontFamily:"var(--mono)",fontSize:12,fontWeight:700,color:t.color,minWidth:36,textAlign:"right",flexShrink:0}}>{c}</span>
      <span style={{minWidth:36,fontFamily:"var(--mono)",fontSize:12,color:"var(--text-3)",textAlign:"right"}}>{pct}%</span>
    </div>);})}</Card>);
}

// ── MANUAL ─────────────────────────────────────────────────────────
function ManualInput({onCompute}){
  const[f,set]=useState({cve_id:"",description:"",cvss_v4_base_score:7.5,ecu_domain:"gateway",attack_surface:"remote_external",network_path:"telematics",exploit_maturity:"poc",kev_listed:false,affected_product:""});
  const u=(k,v)=>set(p=>({...p,[k]:v}));const go=()=>{if(!f.cve_id)return;const v={...f,cvss_v4_base_score:+f.cvss_v4_base_score,published:new Date().toISOString().split("T")[0],modified:new Date().toISOString().split("T")[0],cvss_vector:"Manual",cwe_ids:[],cpe_matches:[],source_feeds:["Manual"],classification_method:"manual"};onCompute({...v,...computeARS(v)});};
  const inp={background:"var(--surface-2)",border:"1px solid var(--border)",borderRadius:10,padding:"10px 14px",color:"var(--text-0)",fontFamily:"var(--mono)",fontSize:12,outline:"none",width:"100%",boxSizing:"border-box"};
  const lbl={fontSize:11,color:"var(--text-2)",fontWeight:600,marginBottom:4,display:"block"};
  return(<Card style={{maxWidth:900,margin:"0 auto"}}><CardTitle icon="➕">Manual CVE Assessment</CardTitle>
    <div style={{display:"grid",gridTemplateColumns:"1fr 1fr 1fr",gap:14}}>
      <div><label style={lbl}>CVE ID</label><input style={inp} value={f.cve_id} onChange={e=>u("cve_id",e.target.value)} placeholder="CVE-2026-XXXXX"/></div>
      <div><label style={lbl}>Product</label><input style={inp} value={f.affected_product} onChange={e=>u("affected_product",e.target.value)} placeholder="Product"/></div>
      <div><label style={lbl}>CVSS Base</label><input type="number" step=".1" min="0" max="10" style={inp} value={f.cvss_v4_base_score} onChange={e=>u("cvss_v4_base_score",e.target.value)}/></div>
      <div><label style={lbl}>ECU Domain</label><select style={{...inp,cursor:"pointer"}} value={f.ecu_domain} onChange={e=>u("ecu_domain",e.target.value)}>{Object.entries(ECU).map(([k,v])=><option key={k} value={k}>{v.ico} {v.full}</option>)}</select></div>
      <div><label style={lbl}>Attack Surface</label><select style={{...inp,cursor:"pointer"}} value={f.attack_surface} onChange={e=>u("attack_surface",e.target.value)}>{SURFACES.map(s=><option key={s} value={s}>{s}</option>)}</select></div>
      <div><label style={lbl}>Network Path</label><select style={{...inp,cursor:"pointer"}} value={f.network_path} onChange={e=>u("network_path",e.target.value)}>{PATHS.map(s=><option key={s} value={s}>{s}</option>)}</select></div>
      <div><label style={lbl}>Exploit Maturity</label><select style={{...inp,cursor:"pointer"}} value={f.exploit_maturity} onChange={e=>u("exploit_maturity",e.target.value)}>{EXPLOITS.map(s=><option key={s} value={s}>{s}</option>)}</select></div>
      <div><label style={lbl}>KEV Listed</label><select style={{...inp,cursor:"pointer"}} value={f.kev_listed} onChange={e=>u("kev_listed",e.target.value==="true")}><option value="false">No</option><option value="true">Yes</option></select></div>
    </div>
    <div style={{marginTop:14}}><label style={lbl}>Description</label><textarea style={{...inp,height:64,resize:"vertical"}} value={f.description} onChange={e=>u("description",e.target.value)} placeholder="Vulnerability description..."/></div>
    <button onClick={go} style={{marginTop:16,width:"100%",padding:"12px",borderRadius:10,background:"var(--blue)",border:"none",color:"#fff",fontFamily:"var(--font)",fontSize:14,fontWeight:700,cursor:"pointer"}}>Compute ARS & Generate AVR</button>
  </Card>);
}

// ═══════════════════════════════════════════════════════════════════
// MAIN APP
// ═══════════════════════════════════════════════════════════════════
export default function AutoVIA(){
  const[vulns,setVulns]=useState([]);const[loading,setLoading]=useState(true);const[logs,setLogs]=useState([]);
  const[search,setSearch]=useState("");const[fDomain,setFDomain]=useState("all");const[fPriority,setFPriority]=useState("all");
  const[fKEV,setFKEV]=useState(false);const[selected,setSelected]=useState(null);const[view,setView]=useState("dashboard");
  const[sortBy,setSortBy]=useState("ars_desc");const[progress,setProgress]=useState({current:0,total:0,source:""});
  const[kevSet,setKevSet]=useState(new Set());const[liveSearching,setLiveSearching]=useState(false);const[dbInfo,setDbInfo]=useState(null);
  const[chatMsgs,setChatMsgs]=useState([]);const[chatInput,setChatInput]=useState("");const[chatLoading,setChatLoading]=useState(false);

  const log=useCallback((msg,type="info")=>{setLogs(p=>[...p.slice(-60),{t:new Date().toLocaleTimeString("en-US",{hour12:false,hour:"2-digit",minute:"2-digit",second:"2-digit"}),msg,type}]);},[]);

  useEffect(()=>{let stop=false;async function load(){log("Starting…");
    try{const r=await fetch("/cve-database.json");if(r.ok){const db=await r.json();if(db.vulnerabilities?.length){
      try{const kr=await fetch(`${API_PROXY}?source=kev`);if(kr.ok){const kd=await kr.json();const ks=new Set();kd.vulnerabilities?.forEach(v=>ks.add(v.cveID));setKevSet(ks);}}catch{}
      const enriched=db.vulnerabilities.map(v=>({...v,cvss_v4_base_score:v.cvss_base_score||v.cvss_v4_base_score||0,...computeARS({...v,cvss_v4_base_score:v.cvss_base_score||v.cvss_v4_base_score||0})}));
      if(!stop){setVulns(enriched);setLoading(false);setDbInfo({count:enriched.length,date:db.generated_at});log(`Loaded ${enriched.length} AVRs`,"success");}return;}}}catch{}
    // Fallback
    let ks=new Set();try{const kr=await fetch(`${API_PROXY}?source=kev`);if(kr.ok){const kd=await kr.json();kd.vulnerabilities?.forEach(v=>ks.add(v.cveID));setKevSet(ks);log(`KEV: ${ks.size}`,"success");}}catch{}
    const map=new Map();let idx=0;
    for(const si of AUTOMOTIVE_NVD_SEARCHES){if(stop)break;idx++;setProgress({current:idx,total:AUTOMOTIVE_NVD_SEARCHES.length,source:si.label});
      try{const r=await fetch(`${API_PROXY}?source=nvd&keyword=${encodeURIComponent(si.keyword)}&resultsPerPage=50`);if(r.status===429){await new Promise(r=>setTimeout(r,15000));continue;}if(!r.ok)continue;const d=await r.json();let a=0;for(const it of d.vulnerabilities||[]){const id=it.cve?.id;if(!id||map.has(id))continue;const av=parseNVD(it,ks);if(av&&av.cvss_v4_base_score>0){map.set(id,av);a++;}}
        log(`[${idx}/${AUTOMOTIVE_NVD_SEARCHES.length}] ${si.label}: +${a}`,"success");if(!stop)setVulns([...map.values()].sort((a,b)=>b.ars-a.ars));await new Promise(r=>setTimeout(r,7000));}catch{}}
    if(!stop){setVulns([...map.values()].sort((a,b)=>b.ars-a.ars));setLoading(false);}
  }load();return()=>{stop=true;};},[log]);

  const liveSearch=async(q)=>{if(!q||q.length<3||liveSearching)return;setLiveSearching(true);
    try{const r=await fetch(`${API_PROXY}?source=nvd&keyword=${encodeURIComponent(q)}&resultsPerPage=50`);if(!r.ok){setLiveSearching(false);return;}const d=await r.json();let a=0;
      setVulns(p=>{const m=new Map(p.map(v=>[v.cve_id,v]));for(const it of d.vulnerabilities||[]){const id=it.cve?.id;if(!id||m.has(id))continue;const av=parseNVD(it,kevSet);if(av&&av.cvss_v4_base_score>0){m.set(id,av);a++;}}return[...m.values()].sort((a,b)=>b.ars-a.ars);});
      log(`Live: "${q}" → +${a} new`,"success");}catch{}setLiveSearching(false);};

  const handleManual=(v)=>{setVulns(p=>[v,...p]);setSelected(v);setView("search");};
  const filtered=useMemo(()=>{let r=vulns;if(search){const q=search.toLowerCase();r=r.filter(v=>v.cve_id?.toLowerCase().includes(q)||v.description?.toLowerCase().includes(q)||v.affected_product?.toLowerCase().includes(q)||v.ecu_domain?.toLowerCase().includes(q)||v.cwe_ids?.some(c=>c.toLowerCase().includes(q)));}
    if(fDomain!=="all")r=r.filter(v=>v.ecu_domain===fDomain);if(fPriority!=="all")r=r.filter(v=>v.priority_tier===fPriority);if(fKEV)r=r.filter(v=>v.kev_listed);
    r.sort((a,b)=>{switch(sortBy){case"ars_asc":return a.ars-b.ars;case"cvss_desc":return b.cvss_v4_base_score-a.cvss_v4_base_score;case"date_desc":return new Date(b.published)-new Date(a.published);default:return b.ars-a.ars;}});return r;},[vulns,search,fDomain,fPriority,fKEV,sortBy]);

  const handleChartFilter=(type,value)=>{if(type==="domain"){setFDomain(value);setFPriority("all");}else if(type==="priority"){setFPriority(value);setFDomain("all");}setFKEV(false);setSearch("");setView("search");};

  const sendChat=async()=>{
    if(!chatInput.trim()||chatLoading)return;
    const userMsg=chatInput.trim();setChatInput("");
    setChatMsgs(p=>[...p,{role:"user",text:userMsg}]);setChatLoading(true);

    // ── Build rich analytical context ──
    const domCounts={};const domArs={};const domSurfaces={};
    vulns.forEach(v=>{
      domCounts[v.ecu_domain]=(domCounts[v.ecu_domain]||0)+1;
      if(!domArs[v.ecu_domain])domArs[v.ecu_domain]=[];domArs[v.ecu_domain].push(v.ars);
      const sk=`${v.ecu_domain}|${v.attack_surface}|${v.network_path}`;domSurfaces[sk]=(domSurfaces[sk]||0)+1;
    });
    const domStats=Object.entries(domCounts).map(([d,c])=>{const scores=domArs[d];return`${d}: ${c} CVEs, avg ARS ${(scores.reduce((a,b)=>a+b,0)/scores.length).toFixed(1)}, max ARS ${Math.max(...scores).toFixed(1)}, ASIL ${ECU[d]?.asil||"QM"}`;}).join("\n");
    const tierCounts={};vulns.forEach(v=>{tierCounts[v.priority_tier]=(tierCounts[v.priority_tier]||0)+1;});
    const kevVulns=vulns.filter(v=>v.kev_listed);
    const avgArs=vulns.length?(vulns.reduce((s,v)=>s+v.ars,0)/vulns.length).toFixed(1):"0";
    // Attack surface analysis
    const surfaceCounts={};vulns.forEach(v=>{surfaceCounts[v.attack_surface]=(surfaceCounts[v.attack_surface]||0)+1;});
    const pathCounts={};vulns.forEach(v=>{pathCounts[v.network_path]=(pathCounts[v.network_path]||0)+1;});
    // Exploit maturity breakdown
    const exploitCounts={};vulns.forEach(v=>{exploitCounts[v.exploit_maturity]=(exploitCounts[v.exploit_maturity]||0)+1;});
    // Top critical with full detail
    const topCritical=vulns.filter(v=>v.priority_tier==="P0_critical").slice(0,15).map(v=>`${v.cve_id} | ARS:${v.ars} | ECU:${v.ecu_domain} | CVSS:${v.cvss_v4_base_score} | Surface:${v.attack_surface}/${v.network_path} | Exploit:${v.exploit_maturity} | KEV:${v.kev_listed} | Product:${v.affected_product||"unknown"} | Desc:${(v.description||"").slice(0,150)}`).join("\n");
    const topHigh=vulns.filter(v=>v.priority_tier==="P1_high").slice(0,10).map(v=>`${v.cve_id} | ARS:${v.ars} | ECU:${v.ecu_domain} | CVSS:${v.cvss_v4_base_score} | Surface:${v.attack_surface}/${v.network_path} | Product:${v.affected_product||"unknown"} | Desc:${(v.description||"").slice(0,120)}`).join("\n");
    // Cross-domain attack paths
    const topSurfaces=Object.entries(domSurfaces).sort((a,b)=>b[1]-a[1]).slice(0,15).map(([k,c])=>{const[d,s,p]=k.split("|");return`${d} via ${s}/${p}: ${c} CVEs`;}).join("\n");
    // Products most affected
    const prodCounts={};vulns.forEach(v=>{if(v.affected_product){prodCounts[v.affected_product]=(prodCounts[v.affected_product]||0)+1;}});
    const topProducts=Object.entries(prodCounts).sort((a,b)=>b[1]-a[1]).slice(0,15).map(([p,c])=>`${p}: ${c} CVEs`).join("\n");
    // Date range
    const dates=vulns.map(v=>v.published).filter(Boolean).sort();
    const dateRange=dates.length?`${dates[0]} to ${dates[dates.length-1]}`:"unknown";
    // CWE analysis
    const cweCounts={};vulns.forEach(v=>(v.cwe_ids||[]).forEach(c=>{cweCounts[c]=(cweCounts[c]||0)+1;}));
    const topCWEs=Object.entries(cweCounts).sort((a,b)=>b[1]-a[1]).slice(0,10).map(([c,n])=>`${c}: ${n}`).join(", ");

    const systemPrompt=`You are the senior AI cybersecurity analyst for Auto-VIA, an automotive vulnerability intelligence platform. You provide deep, actionable analysis for automotive cybersecurity engineers working under ISO/SAE 21434 and UNECE WP.29 R155.

YOUR CAPABILITIES:
1. REMEDIATION INTELLIGENCE — For any CVE, analyze: attack chain in automotive context, safety impact (what happens to vehicle occupants), specific mitigation steps (not generic), which ISO 21434 clause applies, and urgency based on ARS score
2. RISK POSTURE ASSESSMENT — Summarize the security posture of any ECU domain or the entire vehicle, with concrete numbers, trends, and actionable recommendations
3. ATTACK PATTERN DETECTION — Identify clusters of vulnerabilities sharing attack surfaces, network paths, or affected products that suggest systemic weaknesses
4. COMPLIANCE REPORTING — Generate audit-ready summaries for CSMS reviews referencing ISO/SAE 21434 Clause 15 and UNECE R155 requirements
5. TRIAGE PRIORITIZATION — Help engineers decide what to patch first based on ARS, ASIL, exploitability, and attack reachability

CURRENT DATABASE (${vulns.length} AVRs, date range: ${dateRange}):

ECU DOMAIN STATISTICS:
${domStats}

PRIORITY DISTRIBUTION: ${JSON.stringify(tierCounts)}
ATTACK SURFACES: ${JSON.stringify(surfaceCounts)}
NETWORK PATHS: ${JSON.stringify(pathCounts)}
EXPLOIT MATURITY: ${JSON.stringify(exploitCounts)}
KEV-LISTED: ${kevVulns.length} CVEs${kevVulns.length?` — ${kevVulns.slice(0,5).map(v=>`${v.cve_id}(${v.ecu_domain})`).join(", ")}${kevVulns.length>5?"...":""}`:""} 
AVERAGE ARS: ${avgArs}
TOP CWEs: ${topCWEs||"none classified"}

ATTACK PATH MATRIX (ECU × Surface × Path):
${topSurfaces}

MOST AFFECTED PRODUCTS:
${topProducts}

P0 CRITICAL FINDINGS (${tierCounts.P0_critical||0}):
${topCritical||"None"}

P1 HIGH FINDINGS (top 10 of ${tierCounts.P1_high||0}):
${topHigh||"None"}

ARS FORMULA: ARS = MIN(10.0, CVSS_Base × ASIL_Modifier × Reachability_Modifier × Exploit_Maturity_Factor)
ASIL MODIFIERS: ASIL-D(braking,steering,adas)=×1.30, ASIL-C(powertrain,chassis)=×1.20, ASIL-B(gateway)=×1.10, ASIL-A(telematics)=×1.05, QM(infotainment,body,diagnostics)=×1.00
REACHABILITY: remote_external/telematics=×1.25, remote_external/wifi_bt=×1.18, remote_adjacent/wifi_bt=×1.15, local/can=×1.05, physical/diagnostic=×1.00
EXPLOIT FACTORS: active_exploitation=×1.40, weaponized=×1.30, functional=×1.15, poc=×1.10, unknown=×0.90

RESPONSE GUIDELINES:
- Reference specific CVE IDs, ARS scores, and ASIL levels from the data
- When analyzing a specific CVE, explain the automotive-specific impact (not generic IT impact)
- For remediation, give concrete steps: firmware patch, network segmentation, ECU firewall rule, gateway filter, etc.
- For compliance summaries, cite ISO/SAE 21434 clauses and UNECE R155 requirements by number
- For attack pattern analysis, identify which vehicle functions are at risk and the blast radius
- Use structured sections with clear headers when providing detailed analysis
- Always quantify: "X of Y vulnerabilities", "ARS range X–Y", percentages

FILTER COMMANDS: If the user wants to view specific CVEs in the dashboard, append this at the END of your response:
\`\`\`autovia-action
{"action":"filter","domain":"all|<domain>","priority":"all|<tier>","kev":false,"search":""}
\`\`\``;

    try{
      const history=chatMsgs.slice(-10).map(m=>({role:m.role==="user"?"user":"assistant",content:m.text}));
      const r=await fetch("https://api.anthropic.com/v1/messages",{method:"POST",headers:{"Content-Type":"application/json"},
        body:JSON.stringify({model:"claude-sonnet-4-20250514",max_tokens:2000,system:systemPrompt,
          messages:[...history,{role:"user",content:userMsg}]})});
      if(!r.ok)throw new Error(`API ${r.status}`);
      const d=await r.json();
      const text=d.content?.map(c=>c.text||"").join("")||"Sorry, I couldn't process that.";
      const actionMatch=text.match(/```autovia-action\n([\s\S]*?)\n```/);
      if(actionMatch){try{const act=JSON.parse(actionMatch[1]);if(act.action==="filter"){
        if(act.domain&&act.domain!=="all")setFDomain(act.domain);else setFDomain("all");
        if(act.priority&&act.priority!=="all")setFPriority(act.priority);else setFPriority("all");
        setFKEV(!!act.kev);if(act.search)setSearch(act.search);else setSearch("");
        setTimeout(()=>setView("search"),100);}}catch{}}
      const cleanText=text.replace(/```autovia-action\n[\s\S]*?\n```/g,"").trim();
      setChatMsgs(p=>[...p,{role:"assistant",text:cleanText,hasAction:!!actionMatch}]);
    }catch(err){setChatMsgs(p=>[...p,{role:"assistant",text:`Connection error: ${err.message}\n\nTo use the AI Assistant, you need an Anthropic API route configured on your Vercel deployment. Add a /api/chat endpoint that proxies requests to the Anthropic API with your API key.`}]);}
    setChatLoading(false);
  };

  const sel={background:"var(--surface-2)",border:"1px solid var(--border)",borderRadius:10,padding:"8px 12px",color:"var(--text-1)",fontFamily:"var(--font)",fontSize:12,fontWeight:500,outline:"none",cursor:"pointer"};
  const expBtn={padding:"10px 16px",borderRadius:10,background:"var(--surface)",border:"1px solid var(--border)",color:"var(--blue)",fontFamily:"var(--mono)",fontSize:12,fontWeight:600,cursor:"pointer"};

  return(
    <div style={{minHeight:"100vh",background:"var(--bg)",color:"var(--text-0)",fontFamily:"var(--font)"}}>
      <style>{CSS}</style>

      {/* HEADER */}
      <header style={{padding:"0 32px",height:64,display:"flex",alignItems:"center",justifyContent:"space-between",borderBottom:"1px solid var(--border)",background:"var(--surface)",position:"sticky",top:0,zIndex:100}}>
        <div style={{display:"flex",alignItems:"center",gap:12}}>
          <svg width="38" height="38" viewBox="0 0 38 38" style={{flexShrink:0}}>
            <defs>
              <linearGradient id="logoGrad" x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" stopColor="#2563eb"/>
                <stop offset="100%" stopColor="#0891b2"/>
              </linearGradient>
            </defs>
            <rect width="38" height="38" rx="10" fill="url(#logoGrad)"/>
            <path d="M10 26L15.5 11h2.8l2.2 6.5L22.7 11h2.8L31 26h-3l-3.5-10.5L25 21h-3.5l-2.5-5.5L15.5 26z" fill="#fff" opacity=".95"/>
            <rect x="9" y="27.5" width="20" height="2" rx="1" fill="#fff" opacity=".5"/>
          </svg>
          <div><div style={{fontFamily:"var(--font)",fontWeight:800,fontSize:16,color:"var(--text-0)",letterSpacing:"-.02em"}}>Auto-VIA</div>
            <div style={{fontSize:10,color:"var(--text-3)",fontWeight:500,letterSpacing:".06em"}}>AUTOMOTIVE VULNERABILITY INTELLIGENCE</div></div>
        </div>
        <nav style={{display:"flex",gap:2}}>
          {[["dashboard","Dashboard","◫"],["search","Search & Triage","⌕"],["ai","AI Assistant","✦"],["assess","Manual Assessment","＋"],["about","How It Works","ℹ"]].map(([id,label,ico])=>(
            <button key={id} onClick={()=>setView(id)} style={{background:view===id?"var(--blue-bg)":"transparent",border:view===id?"1px solid #bfdbfe":"1px solid transparent",borderRadius:10,padding:"8px 16px",cursor:"pointer",fontFamily:"var(--font)",fontSize:12,fontWeight:600,color:view===id?"var(--blue)":"var(--text-2)",transition:"all .2s"}}>{ico} {label}</button>
          ))}
        </nav>
        <div style={{display:"flex",alignItems:"center",gap:8}}>
          {loading?<Tag color="var(--amber)" bg="#fffbeb" style={{animation:"pulse 1.5s infinite"}}>◌ Loading {progress.source}…</Tag>
            :<Tag color="var(--green)" bg="#ecfdf5">● {vulns.length} AVRs{dbInfo?` · Updated ${new Date(dbInfo.date).toLocaleDateString()}`:""}</Tag>}
        </div>
      </header>

      <main style={{maxWidth:1440,margin:"0 auto",padding:"24px 32px"}}>
        {view==="dashboard"&&<div style={{display:"flex",flexDirection:"column",gap:20}}>
          {/* Welcome Banner */}
          <Card pad="24px" style={{background:"linear-gradient(135deg,#eff6ff,#f0f9ff)",border:"1px solid #bfdbfe"}}>
            <div style={{display:"flex",gap:20,alignItems:"flex-start"}}>
              <div style={{flex:1}}>
                <h2 style={{fontFamily:"var(--font)",fontSize:20,fontWeight:800,color:"var(--text-0)",marginBottom:8}}>Welcome to Auto-VIA</h2>
                <p style={{fontSize:13,color:"var(--text-1)",lineHeight:1.7,marginBottom:12}}>
                  <strong>Auto-VIA</strong> (Automotive Vulnerability Intelligence Aggregator) is an open-source platform that continuously monitors cybersecurity vulnerabilities affecting vehicle systems. It ingests CVEs from the NVD and CISA KEV, classifies them by ECU domain, and scores each using the <strong>Automotive Risk Score (ARS)</strong> — a hybrid model that factors in safety criticality (ASIL), attack reachability, and exploit maturity beyond standard CVSS.
                </p>
                <div style={{display:"flex",gap:8,flexWrap:"wrap"}}>
                  <Tag color="var(--blue)" bg="var(--blue-bg)">📊 ARS = Automotive Risk Score (0–10)</Tag>
                  <Tag color="#7c3aed" bg="#f5f3ff">📦 AVR = Auto-VIA Vulnerability Record</Tag>
                  <Tag color="#059669" bg="#ecfdf5">🏎️ 10 ECU Domains Classified</Tag>
                  <Tag color="#e11d48" bg="#fff1f2">⚡ CISA KEV Real-Time Tracking</Tag>
                </div>
              </div>
              <button onClick={()=>setView("about")} style={{padding:"10px 18px",borderRadius:10,background:"var(--blue)",border:"none",color:"#fff",fontFamily:"var(--font)",fontSize:12,fontWeight:700,cursor:"pointer",whiteSpace:"nowrap"}}>Learn More →</button>
            </div>
          </Card>

          <Stats vulns={vulns} loading={loading}/>
          <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:20}}><EcuChart vulns={vulns} onFilter={handleChartFilter}/><PriorityChart vulns={vulns} onFilter={handleChartFilter}/></div>
          <Card><CardTitle icon="🚨">Critical & High Findings</CardTitle>
            {vulns.filter(v=>v.priority_tier==="P0_critical"||v.priority_tier==="P1_high").slice(0,8).map((v,i)=>(
              <div key={v.cve_id} onClick={()=>setSelected(v)} style={{display:"flex",alignItems:"center",gap:14,padding:"12px 14px",borderRadius:12,border:"1px solid var(--border)",cursor:"pointer",transition:"all .2s",marginBottom:8,animation:`fadeUp .4s ease ${i*.04}s both`}}
                onMouseEnter={e=>{e.currentTarget.style.borderColor="var(--border-h)";e.currentTarget.style.boxShadow="var(--shadow-md)";}} onMouseLeave={e=>{e.currentTarget.style.borderColor="var(--border)";e.currentTarget.style.boxShadow="none";}}>
                <ScoreCircle score={v.ars} size={44}/><div style={{flex:1,minWidth:0}}>
                  <div style={{display:"flex",alignItems:"center",gap:6,flexWrap:"wrap"}}><span style={{fontFamily:"var(--mono)",fontSize:13,fontWeight:700}}>{v.cve_id}</span><TierTag tier={v.priority_tier}/>{v.kev_listed&&<KevTag/>}</div>
                  <div style={{fontSize:11,color:"var(--text-3)",marginTop:3,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{v.affected_product} — {v.description?.slice(0,90)}…</div></div><EcuTag d={v.ecu_domain}/>
              </div>))}
          </Card>
        </div>}

        {view==="search"&&<div style={{display:"flex",flexDirection:"column",gap:14}}>
          <Card pad="14px 16px" style={{display:"flex",gap:8,flexWrap:"wrap",alignItems:"center"}}>
            <div style={{flex:1,position:"relative",minWidth:220}}>
              <span style={{position:"absolute",left:14,top:"50%",transform:"translateY(-50%)",color:"var(--text-3)",fontSize:15}}>🔍</span>
              <input value={search} onChange={e=>setSearch(e.target.value)} onKeyDown={e=>{if(e.key==="Enter")liveSearch(search);}} placeholder="Search CVE, product, domain, CWE…"
                style={{width:"100%",background:"var(--surface-2)",border:"1px solid var(--border)",borderRadius:10,padding:"10px 14px 10px 40px",color:"var(--text-0)",fontFamily:"var(--mono)",fontSize:13,outline:"none"}}/>
            </div>
            <select value={fDomain} onChange={e=>setFDomain(e.target.value)} style={sel}><option value="all">All Domains</option>{Object.entries(ECU).map(([k,v])=><option key={k} value={k}>{v.ico} {v.name}</option>)}</select>
            <select value={fPriority} onChange={e=>setFPriority(e.target.value)} style={sel}><option value="all">All Priorities</option>{Object.entries(TIERS).map(([k,v])=><option key={k} value={k}>{v.tag}</option>)}</select>
            <button onClick={()=>setFKEV(!fKEV)} style={{...sel,background:fKEV?"#fff1f2":"var(--surface-2)",border:fKEV?"1px solid #fecdd3":"1px solid var(--border)",color:fKEV?"#e11d48":"var(--text-2)",fontWeight:700}}>⚡ KEV</button>
            <button onClick={()=>liveSearch(search)} disabled={liveSearching||search.length<3} style={{...sel,background:"var(--blue-bg)",border:"1px solid #bfdbfe",color:"var(--blue)",fontWeight:700,opacity:search.length<3?.4:1}}>
              {liveSearching?"⏳ Searching…":"🔍 Search NVD Live"}</button>
            <select value={sortBy} onChange={e=>setSortBy(e.target.value)} style={sel}><option value="ars_desc">ARS ↓</option><option value="ars_asc">ARS ↑</option><option value="cvss_desc">CVSS ↓</option><option value="date_desc">Date ↓</option></select>
          </Card>
          <div style={{fontSize:12,color:"var(--text-2)"}}><strong style={{color:"var(--text-0)"}}>{filtered.length}</strong> of {vulns.length} vulnerabilities {loading&&<span style={{color:"var(--amber)"}}>(loading…)</span>}</div>
          <Card pad="0" style={{overflow:"hidden"}}>
            <table style={{width:"100%",borderCollapse:"collapse"}}>
              <thead><tr style={{background:"var(--surface-2)"}}>
                {["ARS","CVE ID","Priority","ECU Domain","CVSS","Exploit","Product","KEV","Date"].map(h=>(<th key={h} style={{padding:"12px 14px",textAlign:"left",fontSize:11,fontWeight:700,color:"var(--text-3)",textTransform:"uppercase",letterSpacing:".04em",borderBottom:"1px solid var(--border)"}}>{h}</th>))}
              </tr></thead>
              <tbody>{filtered.slice(0,200).map((v,i)=>(
                <tr key={v.cve_id} onClick={()=>setSelected(v)} style={{borderBottom:"1px solid var(--border)",cursor:"pointer",transition:"background .15s",animation:`fadeUp .3s ease ${Math.min(i*.015,.3)}s both`}}
                  onMouseEnter={e=>e.currentTarget.style.background="var(--surface-2)"} onMouseLeave={e=>e.currentTarget.style.background="transparent"}>
                  <td style={{padding:"10px 14px"}}><ScoreCircle score={v.ars} size={40}/></td>
                  <td style={{padding:"10px 14px",fontFamily:"var(--mono)",fontSize:12,fontWeight:700}}>{v.cve_id}</td>
                  <td style={{padding:"10px 14px"}}><TierTag tier={v.priority_tier}/></td>
                  <td style={{padding:"10px 14px"}}><EcuTag d={v.ecu_domain}/></td>
                  <td style={{padding:"10px 14px",fontFamily:"var(--mono)",fontSize:12,color:"var(--text-2)"}}>{v.cvss_v4_base_score}</td>
                  <td style={{padding:"10px 14px"}}><Tag>{v.exploit_maturity}</Tag></td>
                  <td style={{padding:"10px 14px",fontSize:11,color:"var(--text-2)",maxWidth:160,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{v.affected_product}</td>
                  <td style={{padding:"10px 14px"}}>{v.kev_listed?<KevTag/>:<span style={{color:"var(--border-h)"}}>—</span>}</td>
                  <td style={{padding:"10px 14px",fontFamily:"var(--mono)",fontSize:10,color:"var(--text-3)"}}>{v.published}</td>
                </tr>))}</tbody>
            </table>
            {filtered.length===0&&!loading&&<div style={{padding:48,textAlign:"center",color:"var(--text-3)"}}><div style={{fontSize:36,marginBottom:8}}>🔍</div>No results. Try "Search NVD Live" to query the NVD directly.</div>}
          </Card>
          <div style={{display:"flex",gap:8}}>
            <button onClick={()=>{const d=filtered.slice(0,500).map(v=>({cve_id:v.cve_id,ars:v.ars,priority_tier:v.priority_tier,ecu_domain:v.ecu_domain,cvss:v.cvss_v4_base_score,exploit:v.exploit_maturity,kev:v.kev_listed,product:v.affected_product}));const b=new Blob([JSON.stringify(d,null,2)],{type:"application/json"});const u=URL.createObjectURL(b);const a=document.createElement("a");a.href=u;a.download="AutoVIA_Export.json";a.click();}} style={expBtn}>⬇ Export JSON</button>
            <button onClick={()=>{const csv=["CVE,ARS,Priority,ECU,CVSS,Exploit,KEV,Product",...filtered.slice(0,500).map(v=>`${v.cve_id},${v.ars},${v.priority_tier},${v.ecu_domain},${v.cvss_v4_base_score},${v.exploit_maturity},${v.kev_listed},"${(v.affected_product||"").replace(/"/g,"'")}"`)].join("\n");const b=new Blob([csv],{type:"text/csv"});const u=URL.createObjectURL(b);const a=document.createElement("a");a.href=u;a.download="AutoVIA_Export.csv";a.click();}} style={expBtn}>⬇ Export CSV</button>
          </div>
        </div>}

        {view==="assess"&&<ManualInput onCompute={handleManual}/>}

        {/* ── AI ASSISTANT ── */}
        {view==="ai"&&<div style={{maxWidth:900,margin:"0 auto",display:"flex",flexDirection:"column",height:"calc(100vh - 140px)"}}>
          <Card pad="20px" style={{background:"linear-gradient(135deg,#eff6ff,#f0f9ff)",border:"1px solid #bfdbfe",marginBottom:16,flexShrink:0}}>
            <div style={{display:"flex",alignItems:"center",gap:12}}>
              <div style={{width:40,height:40,borderRadius:12,background:"linear-gradient(135deg,#2563eb,#0891b2)",display:"flex",alignItems:"center",justifyContent:"center",fontSize:20}}>✦</div>
              <div style={{flex:1}}><h2 style={{fontFamily:"var(--font)",fontSize:18,fontWeight:800,color:"var(--text-0)",marginBottom:2}}>Auto-VIA AI Analyst</h2>
                <p style={{fontSize:12,color:"var(--text-2)"}}>Deep vulnerability analysis, remediation intelligence, attack pattern detection, and compliance reporting — powered by your live AVR database.</p></div>
              {chatMsgs.length>0&&<button onClick={()=>setChatMsgs([])} style={{padding:"6px 12px",borderRadius:8,background:"var(--surface)",border:"1px solid var(--border)",color:"var(--text-3)",fontFamily:"var(--font)",fontSize:11,fontWeight:600,cursor:"pointer"}}>Clear Chat</button>}
            </div>
          </Card>

          {/* Chat messages */}
          <Card pad="0" style={{flex:1,display:"flex",flexDirection:"column",overflow:"hidden",minHeight:0}}>
            <div style={{flex:1,overflow:"auto",padding:20,display:"flex",flexDirection:"column",gap:14}} ref={el=>{if(el)el.scrollTop=el.scrollHeight;}}>
              {chatMsgs.length===0&&<div style={{flex:1,display:"flex",flexDirection:"column",alignItems:"center",justifyContent:"center",gap:20,color:"var(--text-3)",padding:"20px 0"}}>
                <div style={{fontSize:40,opacity:.5}}>✦</div>
                <div style={{fontSize:15,fontWeight:700,color:"var(--text-1)"}}>What would you like to analyze?</div>
                <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:10,width:"100%",maxWidth:620}}>
                  {[
                    {cat:"Remediation",color:"#e11d48",bg:"#fff1f2",prompts:["Analyze CVE-2024-21762 — what's the attack chain and remediation for automotive?","What should we patch first in the ADAS domain and why?"]},
                    {cat:"Risk Posture",color:"#2563eb",bg:"#eff6ff",prompts:["Give me a risk posture summary for the braking and steering ECUs","What percentage of our attack surface is remotely exploitable?"]},
                    {cat:"Attack Patterns",color:"#7c3aed",bg:"#f5f3ff",prompts:["Are there vulnerability clusters sharing the same attack path?","Which products have the most concentrated risk?"]},
                    {cat:"Compliance",color:"#059669",bg:"#ecfdf5",prompts:["Generate a CSMS audit summary for ISO 21434 Clause 15","Draft a UNECE R155 vulnerability monitoring status report"]},
                  ].map((g,gi)=>(
                    <div key={gi} style={{display:"flex",flexDirection:"column",gap:6}}>
                      <div style={{fontSize:10,fontWeight:700,color:g.color,textTransform:"uppercase",letterSpacing:".06em",padding:"0 4px"}}>{g.cat}</div>
                      {g.prompts.map((q,qi)=>(
                        <button key={qi} onClick={()=>setChatInput(q)} style={{padding:"10px 12px",borderRadius:10,background:g.bg,border:`1px solid ${g.color}20`,color:"var(--text-1)",fontFamily:"var(--font)",fontSize:11,fontWeight:500,cursor:"pointer",textAlign:"left",lineHeight:1.5,transition:"all .2s"}}
                          onMouseEnter={e=>{e.currentTarget.style.borderColor=g.color;e.currentTarget.style.transform="translateY(-1px)";}}
                          onMouseLeave={e=>{e.currentTarget.style.borderColor=`${g.color}20`;e.currentTarget.style.transform="translateY(0)";}}>{q}</button>
                      ))}
                    </div>
                  ))}
                </div>
              </div>}
              {chatMsgs.map((m,i)=>(
                <div key={i} style={{display:"flex",gap:10,justifyContent:m.role==="user"?"flex-end":"flex-start",animation:"fadeUp .3s ease"}}>
                  {m.role==="assistant"&&<div style={{width:28,height:28,borderRadius:8,background:"linear-gradient(135deg,#2563eb,#0891b2)",display:"flex",alignItems:"center",justifyContent:"center",fontSize:13,flexShrink:0,marginTop:2}}>
                    <span style={{color:"#fff"}}>✦</span></div>}
                  <div style={{maxWidth:"75%",padding:"12px 16px",borderRadius:m.role==="user"?"14px 14px 4px 14px":"14px 14px 14px 4px",
                    background:m.role==="user"?"var(--blue)":"var(--surface-2)",
                    color:m.role==="user"?"#fff":"var(--text-1)",
                    border:m.role==="user"?"none":"1px solid var(--border)",
                    fontSize:13,lineHeight:1.7,fontFamily:"var(--font)",whiteSpace:"pre-wrap",wordBreak:"break-word"}}>
                    {m.text}
                    {m.hasAction&&<div style={{marginTop:8,padding:"6px 10px",borderRadius:6,background:m.role==="user"?"rgba(255,255,255,.15)":"var(--blue-bg)",fontSize:11,fontWeight:600,color:m.role==="user"?"#fff":"var(--blue)"}}>✓ Filters applied — check Search & Triage</div>}
                  </div>
                  {m.role==="user"&&<div style={{width:28,height:28,borderRadius:8,background:"var(--surface-2)",border:"1px solid var(--border)",display:"flex",alignItems:"center",justifyContent:"center",fontSize:12,flexShrink:0,marginTop:2}}>👤</div>}
                </div>
              ))}
              {chatLoading&&<div style={{display:"flex",gap:10,animation:"fadeUp .3s ease"}}>
                <div style={{width:28,height:28,borderRadius:8,background:"linear-gradient(135deg,#2563eb,#0891b2)",display:"flex",alignItems:"center",justifyContent:"center",fontSize:13,flexShrink:0}}>
                  <span style={{color:"#fff"}}>✦</span></div>
                <div style={{padding:"12px 16px",borderRadius:"14px 14px 14px 4px",background:"var(--surface-2)",border:"1px solid var(--border)",fontSize:13,color:"var(--text-3)"}}>
                  <span style={{animation:"pulse 1.5s infinite"}}>Analyzing vulnerabilities…</span></div>
              </div>}
            </div>

            {/* Input bar */}
            <div style={{padding:"14px 20px",borderTop:"1px solid var(--border)",display:"flex",gap:10,alignItems:"center",background:"var(--surface)"}}>
              <input value={chatInput} onChange={e=>setChatInput(e.target.value)} onKeyDown={e=>{if(e.key==="Enter"&&!e.shiftKey){e.preventDefault();sendChat();}}}
                placeholder="Analyze a CVE, assess risk posture, detect attack patterns, or generate compliance reports…"
                style={{flex:1,background:"var(--surface-2)",border:"1px solid var(--border)",borderRadius:12,padding:"12px 16px",color:"var(--text-0)",fontFamily:"var(--font)",fontSize:13,outline:"none",transition:"border-color .2s"}}
                onFocus={e=>e.target.style.borderColor="var(--blue)"} onBlur={e=>e.target.style.borderColor="var(--border)"}/>
              <button onClick={sendChat} disabled={chatLoading||!chatInput.trim()}
                style={{padding:"12px 20px",borderRadius:12,background:chatInput.trim()?"var(--blue)":"var(--surface-2)",border:chatInput.trim()?"none":"1px solid var(--border)",color:chatInput.trim()?"#fff":"var(--text-3)",fontFamily:"var(--font)",fontSize:13,fontWeight:700,cursor:chatInput.trim()?"pointer":"default",transition:"all .2s",whiteSpace:"nowrap"}}>
                {chatLoading?"Thinking…":"Send ↗"}</button>
            </div>
          </Card>
        </div>}

        {/* ── HOW IT WORKS ── */}
        {view==="about"&&<div style={{maxWidth:900,margin:"0 auto",display:"flex",flexDirection:"column",gap:20}}>
          
          {/* Hero */}
          <Card pad="32px" style={{background:"linear-gradient(135deg,#eff6ff,#f0f9ff)",border:"1px solid #bfdbfe",textAlign:"center"}}>
            <div style={{fontSize:36,marginBottom:8}}>🏎️</div>
            <h1 style={{fontFamily:"var(--font)",fontSize:28,fontWeight:800,color:"var(--text-0)",marginBottom:8}}>How Auto-VIA Works</h1>
            <p style={{fontSize:14,color:"var(--text-2)",maxWidth:600,margin:"0 auto",lineHeight:1.7}}>Auto-VIA bridges the gap between generic vulnerability databases and the specific needs of automotive cybersecurity teams. Here's how every piece fits together.</p>
          </Card>

          {/* What is AVR */}
          <Card>
            <CardTitle icon="📦">What is an AVR?</CardTitle>
            <p style={{fontSize:13,color:"var(--text-1)",lineHeight:1.8,marginBottom:14}}>
              An <strong>AVR (Auto-VIA Vulnerability Record)</strong> is the enriched data structure that represents a single vulnerability in the Auto-VIA system. When a raw CVE is ingested from the NVD, it gets normalized and enriched with automotive-specific context to create an AVR.
            </p>
            <p style={{fontSize:13,color:"var(--text-1)",lineHeight:1.8,marginBottom:14}}>
              Each AVR contains six field groups defined in the Auto-VIA Schema v3.0:
            </p>
            <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:10}}>
              {[
                ["🔖 Group A","Source & Identification — CVE ID, source feeds, timestamps"],
                ["📊 Group B","CVSS v4.0 Metrics — scores, vectors, exploit maturity, KEV status"],
                ["📦 Group C","SBOM Correlation — affected component, purl, CPE matches"],
                ["🏎️ Group D","ECU Domain & Vehicle Context — which ECU, ASIL safety level"],
                ["🌐 Group E","Reachability & Exposure — attack surface, network path"],
                ["🎯 Group F","Contextual Prioritization — ARS score, priority tier, treatment SLA"],
              ].map(([title,desc],i)=>(
                <div key={i} style={{padding:12,borderRadius:10,background:"var(--surface-2)",border:"1px solid var(--border)"}}>
                  <div style={{fontSize:12,fontWeight:700,color:"var(--text-0)",marginBottom:4}}>{title}</div>
                  <div style={{fontSize:11,color:"var(--text-2)",lineHeight:1.6}}>{desc}</div>
                </div>
              ))}
            </div>
          </Card>

          {/* What is ARS */}
          <Card>
            <CardTitle icon="🧮">What is the ARS?</CardTitle>
            <p style={{fontSize:13,color:"var(--text-1)",lineHeight:1.8,marginBottom:14}}>
              The <strong>ARS (Automotive Risk Score)</strong> is Auto-VIA's proprietary risk scoring model. Standard CVSS scores treat all systems equally — a vulnerability scores the same whether it affects a website or a vehicle's braking ECU. ARS fixes this by incorporating automotive-specific risk factors.
            </p>
            <div style={{padding:16,borderRadius:12,background:"var(--blue-bg)",border:"1px solid #bfdbfe",fontFamily:"var(--mono)",fontSize:13,color:"var(--blue)",textAlign:"center",marginBottom:14}}>
              ARS = MIN(10.0, CVSS_Base × ASIL_Modifier × Reachability_Modifier × Exploit_Maturity_Factor)
            </div>
            <div style={{display:"flex",flexDirection:"column",gap:10}}>
              {[
                ["CVSS Base Score","The standard vulnerability severity score (0–10) from the National Vulnerability Database.","The starting point"],
                ["ASIL Safety Modifier","Based on ISO 26262 Automotive Safety Integrity Level. ASIL-D (braking, steering) gets ×1.30 uplift; QM (infotainment) gets ×1.00.","Higher ASIL = higher risk"],
                ["Reachability Modifier","How accessible is the vulnerable component? Remotely exploitable over cellular (×1.25) is far more dangerous than requiring physical OBD-II access (×1.00).","Remote = more dangerous"],
                ["Exploit Maturity Factor","Is there active exploitation? KEV-listed/weaponized (×1.40) vs theoretical with no known exploit (×0.90).","Known exploits = urgent"],
              ].map(([title,desc,note],i)=>(
                <div key={i} style={{display:"flex",gap:14,padding:14,borderRadius:10,background:"var(--surface-2)",border:"1px solid var(--border)"}}>
                  <div style={{width:28,height:28,borderRadius:8,background:"var(--blue-bg)",display:"flex",alignItems:"center",justifyContent:"center",fontFamily:"var(--mono)",fontSize:12,fontWeight:800,color:"var(--blue)",flexShrink:0}}>{i+1}</div>
                  <div style={{flex:1}}><div style={{fontSize:13,fontWeight:700,color:"var(--text-0)",marginBottom:2}}>{title}</div>
                    <div style={{fontSize:12,color:"var(--text-2)",lineHeight:1.6}}>{desc}</div></div>
                  <Tag color="var(--blue)" bg="var(--blue-bg)" style={{alignSelf:"center",fontSize:10}}>{note}</Tag>
                </div>
              ))}
            </div>
          </Card>

          {/* ECU Domains */}
          <Card>
            <CardTitle icon="🏎️">ECU Domain Taxonomy</CardTitle>
            <p style={{fontSize:13,color:"var(--text-1)",lineHeight:1.8,marginBottom:14}}>
              Auto-VIA classifies every vulnerability into one of <strong>10 ECU (Electronic Control Unit) domains</strong>. Each domain has a default ASIL safety rating that influences the ARS score — vulnerabilities in safety-critical systems like braking or steering are automatically prioritized higher.
            </p>
            <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:8}}>
              {Object.entries(ECU).map(([k,e])=>(
                <div key={k} style={{display:"flex",alignItems:"center",gap:10,padding:10,borderRadius:10,background:e.bg,border:`1px solid ${e.color}15`}}>
                  <span style={{fontSize:20}}>{e.ico}</span>
                  <div style={{flex:1}}><div style={{fontSize:12,fontWeight:700,color:e.color}}>{e.full}</div>
                    <div style={{fontSize:10,color:"var(--text-2)"}}>Default: {e.asil} · ARS modifier: ×{e.mod}</div></div>
                </div>
              ))}
            </div>
          </Card>

          {/* Priority Tiers */}
          <Card>
            <CardTitle icon="🚦">Priority Tiers & Treatment SLAs</CardTitle>
            <p style={{fontSize:13,color:"var(--text-1)",lineHeight:1.8,marginBottom:14}}>
              The final ARS score maps to a priority tier, each with a defined treatment SLA aligned with ISO/SAE 21434 Clause 15 vulnerability management requirements.
            </p>
            <div style={{display:"flex",flexDirection:"column",gap:8}}>
              {[
                ["P0_critical","9.0 – 10.0","Immediate (24–72 hours)","Patch immediately. KEV-listed CVEs are automatically forced to P0 regardless of score."],
                ["P1_high","7.0 – 8.9","Within 7 days","Patch or apply mitigation controls within one week."],
                ["P2_medium","4.0 – 6.9","Within 30 days","Apply mitigations or schedule patching within the next maintenance cycle."],
                ["P3_low","0.1 – 3.9","Scheduled maintenance","Monitor and address during scheduled maintenance windows."],
              ].map(([tier,range,sla,desc])=>{const t=TIERS[tier];return(
                <div key={tier} style={{display:"flex",gap:14,padding:14,borderRadius:10,background:t.bg,border:`1px solid ${t.color}20`}}>
                  <div style={{minWidth:80}}><TierTag tier={tier}/></div>
                  <div style={{flex:1}}><div style={{fontSize:12,color:"var(--text-1)",lineHeight:1.6}}>{desc}</div>
                    <div style={{fontSize:11,color:"var(--text-3)",marginTop:4}}>ARS Range: <strong>{range}</strong> · SLA: <strong>{sla}</strong></div></div>
                </div>);})}
            </div>
          </Card>

          {/* Data Sources */}
          <Card>
            <CardTitle icon="📡">Data Sources</CardTitle>
            <p style={{fontSize:13,color:"var(--text-1)",lineHeight:1.8,marginBottom:14}}>
              Auto-VIA ingests vulnerability data from authoritative threat intelligence sources and enriches each record with automotive context.
            </p>
            <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:10}}>
              {[
                ["🏛️ NVD (National Vulnerability Database)","NIST's repository of CVE data with CVSS scores, CPE mappings, and CWE classifications. Primary enrichment source, polled via REST API v2.0."],
                ["⚡ CISA KEV Catalog","Known Exploited Vulnerabilities — CVEs with confirmed active exploitation in the wild. KEV listing forces P0_critical priority regardless of ARS."],
                ["🔍 Automotive Relevance Classifier","Three-stage pipeline: CPE-to-ECU rule matching, keyword pattern scoring, and heuristic classification filters ~30,000 annual CVEs down to automotive-relevant ones."],
                ["📋 TARA Export","Generates ISO/SAE 21434 Cl.9 Threat Analysis and Risk Assessment asset register entries directly from AVR data for audit compliance."],
              ].map(([title,desc],i)=>(
                <div key={i} style={{padding:14,borderRadius:10,background:"var(--surface-2)",border:"1px solid var(--border)"}}>
                  <div style={{fontSize:13,fontWeight:700,color:"var(--text-0)",marginBottom:6}}>{title}</div>
                  <div style={{fontSize:12,color:"var(--text-2)",lineHeight:1.7}}>{desc}</div>
                </div>
              ))}
            </div>
          </Card>

          {/* Standards */}
          <Card>
            <CardTitle icon="📜">Regulatory Alignment</CardTitle>
            <div style={{display:"flex",flexDirection:"column",gap:8}}>
              {[
                ["ISO/SAE 21434:2021","Clause 15 — Vulnerability management process. AVR schema, ARS scoring, and TARA exports are designed to satisfy identification, assessment, and treatment documentation requirements."],
                ["UNECE WP.29 R155","Continuous monitoring and CSMS audit evidence. Auto-VIA provides real-time CVE ingestion, KEV tracking, and compliance report generation for type approval."],
                ["CVSS v4.0","Native support for CVSS v4.0 Base and Threat metric groups as primary severity signals, with v3.1 fallback."],
                ["NHTSA Guidance","ASIL-weighted scoring specifically elevates findings in safety-critical ECU domains (braking, steering, powertrain) per NHTSA best practices."],
              ].map(([std,desc],i)=>(
                <div key={i} style={{padding:14,borderRadius:10,background:"var(--surface-2)",border:"1px solid var(--border)"}}>
                  <div style={{fontSize:13,fontWeight:700,color:"var(--blue)",marginBottom:4}}>{std}</div>
                  <div style={{fontSize:12,color:"var(--text-2)",lineHeight:1.7}}>{desc}</div>
                </div>
              ))}
            </div>
          </Card>

          {/* Credits */}
          <Card pad="24px" style={{textAlign:"center",background:"linear-gradient(135deg,#f0f9ff,#eff6ff)",border:"1px solid #bfdbfe"}}>
            <p style={{fontSize:13,color:"var(--text-1)",lineHeight:1.8}}>
              <strong>Auto-VIA</strong> is an open-source platform designed and architected by<br/>
              <strong style={{color:"var(--blue)",fontSize:15}}>Siranjeevi Srinivasa Raghavan</strong><br/>
              <span style={{color:"var(--text-2)"}}>Automotive Cybersecurity Systems Engineer</span>
            </p>
          </Card>
        </div>}
      </main>

      {selected&&<><div onClick={()=>setSelected(null)} style={{position:"fixed",top:0,left:0,right:0,bottom:0,background:"rgba(0,0,0,.3)",zIndex:999}}/><DetailPanel v={selected} onClose={()=>setSelected(null)}/></>}

      <footer style={{padding:"16px 32px",borderTop:"1px solid var(--border)",background:"var(--surface)",display:"flex",justifyContent:"space-between",alignItems:"center",flexWrap:"wrap",gap:8}}>
        <span style={{fontSize:11,color:"var(--text-3)"}}>Auto-VIA v3.0 — Automotive Vulnerability Intelligence Aggregator</span>
        <div style={{display:"flex",gap:6}}>{["ISO/SAE 21434","UNECE R155","CVSS v4.0","NVD API","CISA KEV"].map(s=><Tag key={s}>{s}</Tag>)}</div>
      </footer>
    </div>
  );
}
