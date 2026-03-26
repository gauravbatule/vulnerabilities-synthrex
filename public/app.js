// Synthrex v3 — Production Build
const API='';
let scanId=null,poll=null,allOpen=false;



function normalizeTarget(t){
  t=t.trim();if(!t)return '';
  if(!/^https?:\/\//i.test(t))t='https://'+t;
  return t;
}

let pendingTarget=null;

function showLoader(){const l=$('precheckLoader');if(l)l.classList.add('visible');}
function hideLoader(){const l=$('precheckLoader');if(l)l.classList.remove('visible');}

async function startScan(overrideCode){
  const raw=overrideCode?pendingTarget:document.getElementById('inp').value.trim();
  if(!raw){alert('Enter a domain');return;}
  const btn=$('btn');btn.disabled=true;btn.innerHTML='Checking…';
  try{
    // Pre-check: security.txt or access code required?
    if(!overrideCode){
      showLoader();
      const body={target:raw};
      const pc=await fetch(`${API}/api/precheck`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
      const pcd=await pc.json();

      if(!pcd.allowed && pcd.reason==='invalid_domain'){
        hideLoader();
        alert(pcd.error || 'This domain does not exist or is unreachable.');
        btn.disabled=false;btn.innerHTML='🔍 Scan';return;
      }
      if(!pcd.allowed && pcd.requireCode){
        hideLoader();
        pendingTarget=raw;
        showCodeModal();
        btn.disabled=false;btn.innerHTML='🔍 Scan';return;
      }
      // Has security.txt — proceed directly
      hideLoader();
    }
    // Proceed with scan
    const body={target:raw};
    if(overrideCode)body.accessCode=overrideCode;
    else body.precheckPassed=true;
    const r=await fetch(`${API}/api/scan`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
    const d=await r.json();
    if(d.error){alert(d.error);btn.disabled=false;btn.innerHTML='🔍 Scan';return;}
    scanId=d.scanId;
    hideCodeModal();
    $('hero').style.display='none';
    $('prog').style.display='block';
    $('pTarget').textContent=d.target;
    $('navStats').style.display='flex';
    poll=setInterval(pollStatus,1200);
  }catch(e){
    hideLoader();
    console.error(e);btn.disabled=false;btn.innerHTML='🔍 Scan';
    alert('Cannot reach server.');
  }
}

function showCodeModal(){
  let m=$('codeModal');
  if(!m){
    m=document.createElement('div');m.id='codeModal';
    m.innerHTML=`<div class="modal-overlay"><div class="modal-box">
      <h3>Authorization Required</h3>
      <p>This website does not have a <code>security.txt</code> file.<br>Enter the access code to confirm you have authorization to scan this target.</p>
      <input type="text" id="codeInp" placeholder="Enter access code" autocomplete="off" maxlength="10">
      <div class="modal-btns">
        <button onclick="hideCodeModal()" class="btn-secondary">Cancel</button>
        <button onclick="submitCode()" class="btn-primary">Verify & Scan</button>
      </div>
    </div></div>`;
    document.body.appendChild(m);
  }
  m.style.display='flex';
  setTimeout(()=>{const i=$('codeInp');if(i)i.focus();},100);
}
function hideCodeModal(){const m=$('codeModal');if(m)m.style.display='none';}
function submitCode(){
  const code=$('codeInp')?.value.trim();
  if(!code){alert('Please enter an access code.');return;}
  startScan(code);
}


async function pollStatus(){
  if(!scanId)return;
  try{
    const r=await fetch(`${API}/api/scan/${scanId}`);
    const s=await r.json();
    $('pArc').style.strokeDashoffset=326.7*(1-s.progress/100);
    $('pPct').textContent=s.progress+'%';
    $('pScan').textContent=s.currentScanner||'Finishing…';
    $('pCnt').textContent=s.totalTests+' tests';
    q('#nT').textContent=s.totalTests;
    q('#nP').textContent=s.totalPassed;
    q('#nF').textContent=s.totalFailed;
    q('#nW').textContent=s.totalWarnings;

    if(s.status==='completed'){clearInterval(poll);showResults(s);}
  }catch(e){console.error(e);}
}


function showResults(s){
  $('prog').style.display='none';
  $('results').style.display='block';
  let cr=0,hi=0,me=0,lo=0,inf=0,issueCards=0,passCards=0;
  for(const r of s.results){
    const tests=r.results?.tests||[];let hasIssue=false;
    for(const t of tests){
      if(t.status==='fail'||t.status==='warn'){
        const v=t.severity;if(v==='critical')cr++;else if(v==='high')hi++;else if(v==='medium')me++;else if(v==='low')lo++;else inf++;
        hasIssue=true;
      }
    }
    if(hasIssue)issueCards++;else passCards++;
  }
  const score=Math.max(0,Math.min(100,Math.round(100-cr*12-hi*5-me*2-lo*.5)));
  const arc=$('arc'),circ=263.9;
  setTimeout(()=>{arc.style.transition='stroke-dashoffset 1s ease-out';arc.style.strokeDashoffset=circ-(score/100)*circ;},80);
  anim('sNum',score);
  const sn=$('sNum');
  sn.style.color=score>=75?'var(--green)':score>=40?'var(--amber)':'var(--red)';
  $('sC').textContent=cr;$('sH').textContent=hi;$('sM').textContent=me;$('sL').textContent=lo;$('sI').textContent=inf;
  $('fAll').textContent=s.results.length;$('fIss').textContent=issueCards;$('fPas').textContent=passCards;
  renderList(s.results);
  $('btn').disabled=false;$('btn').innerHTML='Scan';
  runAi();
}

function anim(id,t){const e=$(id);let c=0;const s=Math.max(1,Math.floor(t/20));const i=setInterval(()=>{c=Math.min(c+s,t);e.textContent=Math.round(c);if(c>=t)clearInterval(i);},25);}

function renderList(results){
  const g=$('rlist');g.innerHTML='';
  for(const r of results){
    const tests=r.results?.tests||[];
    const fails=tests.filter(t=>t.status==='fail');
    const warns=tests.filter(t=>t.status==='warn');
    const passes=tests.filter(t=>t.status==='pass');
    let bc='pass',bt;
    if(tests.length===0){bc='pass';bt='✓ No issues';}
    else if(fails.length){bc='fail';bt=fails.length+' fail'+(warns.length?', '+warns.length+' warn':'');}
    else if(warns.length){bc='warn';bt=warns.length+' warn';}
    else{bt=passes.length+' passed';}
    const d=document.createElement('div');
    d.className='sc';d.dataset.type=bc;
    d.innerHTML=`<div class="sc-h" onclick="tog(this)"><span class="ic">${r.icon||'🔍'}</span><h4>${esc(r.scanner)}</h4><span class="badge ${bc}">${bt}</span><span class="chevron">▶</span></div><div class="sc-b">${renderTests(tests)}</div>`;
    g.appendChild(d);
  }
  g.querySelectorAll('.badge.fail').forEach(b=>{
    const body=b.closest('.sc').querySelector('.sc-b');body.classList.add('open');
    b.closest('.sc').querySelector('.chevron').style.transform='rotate(90deg)';
  });
}

function renderTests(tests){
  if(!tests||tests.length===0)return '<div class="test-row"><span class="dot info"></span><span class="test-name" style="color:var(--text3)">No data returned from this scanner</span></div>';
  const sorted=[...tests].sort((a,b)=>{const o={fail:0,warn:1,info:2,pass:3};return(o[a.status]??3)-(o[b.status]??3);});
  const show=sorted.slice(0,50);const rem=sorted.length-show.length;
  let h=show.map(t=>{
    const sevLabel=(t.status==='pass')?'info':t.severity;
    return `<div class="test-row"><span class="dot ${t.status}"></span><span class="test-name">${esc(t.name)}</span><span class="test-sev ${sevLabel}">${sevLabel}</span></div>`;
  }).join('');
  if(rem>0)h+=`<div class="test-row"><span class="dot info"></span><span class="test-name" style="color:var(--text3)">+ ${rem} more…</span></div>`;
  return h;
}

function tog(h){const b=h.nextElementSibling;b.classList.toggle('open');h.querySelector('.chevron').style.transform=b.classList.contains('open')?'rotate(90deg)':'rotate(0)';}
function toggleAll(){
  allOpen=!allOpen;
  document.querySelectorAll('.sc-b').forEach(b=>{allOpen?b.classList.add('open'):b.classList.remove('open');});
  document.querySelectorAll('.chevron').forEach(a=>{a.style.transform=allOpen?'rotate(90deg)':'rotate(0)';});
}
function filter(f,btn){
  document.querySelectorAll('.ftab').forEach(t=>t.classList.remove('active'));
  btn.classList.add('active');
  document.querySelectorAll('.sc').forEach(c=>{
    if(f==='all')c.classList.remove('hidden');
    else if(f==='fail')c.classList.toggle('hidden',c.dataset.type==='pass');
    else if(f==='pass')c.classList.toggle('hidden',c.dataset.type!=='pass');
  });
}

// AI
async function runAi(){
  if(!scanId)return;
  try{
    const r=await fetch(`${API}/api/ai-analyze`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({scanId})});
    const d=await r.json();
    const md=d.success?d.analysis:(d.fallbackAnalysis||d.error||'Analysis not available');
    $('aiMd').innerHTML=renderMd(md);
    $('aiBox').style.display='block';
  }catch(e){console.error('AI:',e);}
}
function renderMd(text){
  if(!text)return '';
  if(typeof marked!=='undefined'&&marked.parse){
    try{marked.setOptions({breaks:true,gfm:true});return marked.parse(text);}catch(e){console.warn(e);}
  }
  let h=esc(text);
  h=h.replace(/^### (.+)$/gm,'<h3>$1</h3>').replace(/^## (.+)$/gm,'<h2>$1</h2>').replace(/^# (.+)$/gm,'<h1>$1</h1>');
  h=h.replace(/\*\*(.+?)\*\*/g,'<strong>$1</strong>').replace(/`(.+?)`/g,'<code>$1</code>');
  return h;
}

// PDF
function exportPdf(){
  const el=document.createElement('div');
  el.style.cssText='padding:28px;font-family:Inter,sans-serif;color:#111;background:#fff;max-width:700px;';
  const sn=$('sNum').textContent;
  el.innerHTML=`<div style="display:flex;align-items:center;gap:10px;margin-bottom:20px;border-bottom:2px solid #10b981;padding-bottom:12px"><div style="font-size:22px;font-weight:900;letter-spacing:-0.03em">Synthrex</div><div style="font-size:10px;color:#666">Security Report · ${new Date().toLocaleDateString()}</div></div>`;
  el.innerHTML+=`<div style="display:flex;gap:16px;margin-bottom:16px;padding:14px;background:#f8f8f8;border-radius:10px;flex-wrap:wrap"><div style="text-align:center;min-width:60px"><div style="font-size:28px;font-weight:900;color:${parseInt(sn)>=75?'#10b981':parseInt(sn)>=40?'#f59e0b':'#ef4444'}">${sn}</div><div style="font-size:9px;color:#666;text-transform:uppercase">Score</div></div><div style="flex:1;font-size:12px;line-height:2.2"><span style="color:#ef4444">● Critical: ${$('sC').textContent}</span> &nbsp; <span style="color:#f97316">● High: ${$('sH').textContent}</span> &nbsp; <span style="color:#f59e0b">● Medium: ${$('sM').textContent}</span> &nbsp; <span style="color:#10b981">● Low: ${$('sL').textContent}</span></div></div>`;
  el.innerHTML+=`<p style="font-size:10px;color:#666;margin-bottom:12px">Tests: ${q('#nT').textContent} · Passed: ${q('#nP').textContent} · Failed: ${q('#nF').textContent} · Warnings: ${q('#nW').textContent}</p>`;
  const aiMd=$('aiMd').innerHTML;
  if(aiMd)el.innerHTML+=`<div style="margin-bottom:20px"><h2 style="font-size:15px;border-bottom:1px solid #ddd;padding-bottom:4px;margin-bottom:8px">AI Assessment</h2><div style="font-size:12px;line-height:1.8;color:#333">${aiMd}</div></div>`;
  document.querySelectorAll('.sc').forEach(card=>{
    const t=card.querySelector('h4').textContent,b=card.querySelector('.badge').textContent,ic=card.querySelector('.ic').textContent;
    let rows='';
    card.querySelectorAll('.test-row').forEach(tr=>{
      const n=tr.querySelector('.test-name')?.textContent||'',s=tr.querySelector('.test-sev')?.textContent||'',dot=tr.querySelector('.dot');
      const c=dot.classList.contains('fail')?'#ef4444':dot.classList.contains('warn')?'#f59e0b':'#10b981';
      rows+=`<div style="display:flex;align-items:center;gap:5px;padding:2px 0;font-size:10px;border-bottom:1px solid #f0f0f0"><span style="width:5px;height:5px;border-radius:50%;background:${c};flex-shrink:0"></span><span style="flex:1">${n}</span><span style="font-size:8px;font-weight:700;text-transform:uppercase;color:${c}">${s}</span></div>`;
    });
    el.innerHTML+=`<div style="margin-bottom:8px;border:1px solid #e0e0e0;border-radius:6px;overflow:hidden"><div style="padding:8px 12px;background:#f8f8f8;border-bottom:1px solid #e0e0e0;display:flex;justify-content:space-between"><span style="font-weight:600;font-size:12px">${ic} ${t}</span><span style="font-size:9px;font-weight:600;padding:1px 6px;border-radius:100px;background:#f0f0f0">${b}</span></div><div style="padding:6px 12px">${rows}</div></div>`;
  });
  el.innerHTML+=`<div style="margin-top:16px;padding-top:8px;border-top:1px solid #ddd;text-align:center;font-size:9px;color:#999">Synthrex Security Report · Built by Gaurav Batule · synthrex.in</div>`;
  document.body.appendChild(el);
  html2pdf().set({margin:[8,8,8,8],filename:`synthrex-${new Date().toISOString().slice(0,10)}.pdf`,image:{type:'jpeg',quality:0.95},html2canvas:{scale:2,useCORS:true},jsPDF:{unit:'mm',format:'a4',orientation:'portrait'}}).from(el).save().then(()=>el.remove());
}

function $(id){return document.getElementById(id);}
function q(sel){return document.querySelector(sel);}
function esc(t){const d=document.createElement('div');d.textContent=t;return d.innerHTML;}
document.addEventListener('DOMContentLoaded',()=>{
  $('inp').addEventListener('keydown',e=>{if(e.key==='Enter'){e.preventDefault();startScan();}});
});
