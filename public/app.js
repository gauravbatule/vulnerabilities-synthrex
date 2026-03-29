const API='';
let lastScan=null,allOpen=false;

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

    if(!overrideCode){
      showLoader();
      const body={target:raw};
      const pc=await fetch(`${API}/api/precheck`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
      const pcd=await pc.json();

      if(!pcd.allowed&&pcd.reason==='invalid_domain'){
        hideLoader();
        alert(pcd.error || 'This domain does not exist or is unreachable.');
        btn.disabled=false;btn.innerHTML='🔍 Scan';return;
      }
      if(!pcd.allowed&&pcd.requireCode){
        hideLoader();
        pendingTarget=raw;
        showCodeModal();
        btn.disabled=false;btn.innerHTML='🔍 Scan';return;
      }

      hideLoader();
    }

    hideCodeModal();

    // Fetch scanner list
    const slResp=await fetch(`${API}/api/scanners`);
    const scannerList=await slResp.json();

    // Show progress UI
    $('hero').style.display='none';
    $('prog').style.display='block';
    $('pTarget').textContent=raw;
    $('navStats').style.display='flex';

    // Client-side orchestration: run each scanner individually
    const allResults=[];
    let totalTests=0,totalPassed=0,totalFailed=0,totalWarnings=0;

    for(let i=0;i<scannerList.length;i++){
      const sc=scannerList[i];

      // Update progress
      const progress=Math.round((i/scannerList.length)*100);
      $('pArc').style.strokeDashoffset=326.7*(1-progress/100);
      $('pPct').textContent=progress+'%';
      $('pScan').textContent=sc.name;
      $('pCnt').textContent=totalTests+' tests';

      try{
        const r=await fetch(`${API}/api/run-scanner`,{
          method:'POST',
          headers:{'Content-Type':'application/json'},
          body:JSON.stringify({target:raw,scannerId:sc.id})
        });
        const result=await r.json();
        if(result&&result.scanner){
          allResults.push(result);
          const tests=result.results?.tests||[];
          totalTests+=tests.length;
          totalPassed+=tests.filter(t=>t.status==='pass').length;
          totalFailed+=tests.filter(t=>t.status==='fail').length;
          totalWarnings+=tests.filter(t=>t.status==='warn').length;
        }else{
          allResults.push({scanner:sc.name,icon:sc.icon,results:{tests:[]},testCount:0});
        }
      }catch(e){
        allResults.push({scanner:sc.name,icon:sc.icon,results:{tests:[],error:e.message},testCount:0});
      }

      // Update nav stats live
      q('#nT').textContent=totalTests;
      q('#nP').textContent=totalPassed;
      q('#nF').textContent=totalFailed;
      q('#nW').textContent=totalWarnings;
    }

    // Mark 100%
    $('pArc').style.strokeDashoffset=0;
    $('pPct').textContent='100%';
    $('pScan').textContent='Complete';

    showResults({
      target:raw,
      status:'completed',
      results:allResults,
      totalTests,totalPassed,totalFailed,totalWarnings
    });

  }catch(e){
    hideLoader();
    btn.disabled=false;btn.innerHTML='🔍 Scan';
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
      <p style="font-size:12px;color:#999;margin-bottom:16px;">Don't have an access code? <a href="https://www.linkedin.com/in/gaurav-batule/" target="_blank" rel="noopener noreferrer" style="color:#10b981;text-decoration:none;font-weight:600;">Contact me on LinkedIn</a> to get one.</p>
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


function showResults(s){
  lastScan=s;
  $('prog').style.display='none';
  $('results').style.display='block';
  let cr=0,hi=0,me=0,lo=0,inf=0,issueCards=0,passCards=0;
  for(const r of s.results){
    if(!r)continue;
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
  s.score=score;
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
    if(!r||!r.scanner)continue;
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
    d.innerHTML=`<div class="sc-h" onclick="tog(this)"><span class="ic">${r.icon||'🔍'}</span><h4>${esc(r.scanner||'Unknown Scanner')}</h4><span class="badge ${bc}">${bt}</span><span class="chevron">▶</span></div><div class="sc-b">${renderTests(tests)}</div>`;
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


async function runAi(){
  if(!lastScan)return;
  try{
    const r=await fetch(`${API}/api/ai-analyze`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({target:lastScan.target,results:lastScan.results})});
    const d=await r.json();
    const md=d.success?d.analysis:(d.fallbackAnalysis||d.error||'Analysis not available');
    $('aiMd').innerHTML=renderMd(md);
    $('aiBox').style.display='block';
    if(d.success&&d.analysis)lastScan.aiAnalysis={analysis:d.analysis};
  }catch(e){}
}
function renderMd(text){
  if(!text)return '';
  if(typeof marked!=='undefined'&&marked.parse){
    try{marked.setOptions({breaks:true,gfm:true});return marked.parse(text);}catch(e){}
  }
  let h=esc(text);
  h=h.replace(/^### (.+)$/gm,'<h3>$1</h3>').replace(/^## (.+)$/gm,'<h2>$1</h2>').replace(/^# (.+)$/gm,'<h1>$1</h1>');
  h=h.replace(/\*\*(.+?)\*\*/g,'<strong>$1</strong>').replace(/`(.+?)`/g,'<code>$1</code>');
  return h;
}


function exportPdf(){
  if(!lastScan){alert('No scan data available. Please run a scan first.');return;}
  const btn=document.querySelector('.action-btn.primary');
  const orig=btn.innerHTML;
  btn.innerHTML='⏳ Generating...';btn.disabled=true;

  fetch(`${API}/api/export-pdf`,{
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body:JSON.stringify(lastScan)
  })
    .then(r=>{
      if(!r.ok) throw new Error('PDF generation failed. Please try again.');
      return r.blob();
    })
    .then(blob=>{
      const url=URL.createObjectURL(blob);
      const a=document.createElement('a');
      a.href=url;
      a.download=`Synthrex-Report-${new Date().toISOString().slice(0,10)}.pdf`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    })
    .catch(e=>{
      alert(e.message);
    })
    .finally(()=>{
      btn.innerHTML=orig;btn.disabled=false;
    });
}

function $(id){return document.getElementById(id);}
function q(sel){return document.querySelector(sel);}
function esc(t){const d=document.createElement('div');d.textContent=t;return d.innerHTML;}
document.addEventListener('DOMContentLoaded',()=>{
  $('inp').addEventListener('keydown',e=>{if(e.key==='Enter'){e.preventDefault();startScan();}});
});
