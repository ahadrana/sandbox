package main

// dashboardHTML is the sim's live UI: single self-contained page, no
// external resources, dark theme, vanilla JS polling /api/state.
const dashboardHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>sandbox-sim</title>
<style>
  :root { --bg:#0d1117; --panel:#161b22; --border:#30363d; --fg:#e6edf3; --dim:#8b949e;
    --green:#3fb950; --amber:#d29922; --blue:#58a6ff; --red:#f85149; --purple:#bc8cff; }
  * { box-sizing:border-box; margin:0; padding:0; }
  body { background:var(--bg); color:var(--fg); font:14px/1.45 -apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif; padding:18px 22px; }
  h1 { font-size:18px; font-weight:600; }
  h1 .scenario { color:var(--purple); font-weight:400; margin-left:8px; }
  .sub { color:var(--dim); font-size:12px; margin-top:2px; }
  .stats { display:flex; flex-wrap:wrap; gap:10px; margin:14px 0 18px; }
  .stat { background:var(--panel); border:1px solid var(--border); border-radius:8px; padding:8px 14px; min-width:110px; }
  .stat .v { font-size:20px; font-weight:650; }
  .stat .k { color:var(--dim); font-size:11px; text-transform:uppercase; letter-spacing:.4px; }
  .stat.ok .v { color:var(--green); } .stat.bad .v { color:var(--red); } .stat.warn .v { color:var(--amber); }
  .cards { display:grid; grid-template-columns:repeat(auto-fill,minmax(250px,1fr)); gap:12px; margin-bottom:18px; }
  .card { background:var(--panel); border:1px solid var(--border); border-left:4px solid var(--dim); border-radius:8px; padding:10px 14px; cursor:pointer; }
  .card.sel { outline:2px solid var(--blue); }
  .card .name { font-weight:650; font-size:15px; }
  .card .state { float:right; font-size:11px; font-weight:700; padding:2px 8px; border-radius:10px; background:#21262d; }
  .card .row { color:var(--dim); font-size:12px; margin-top:3px; }
  .card .row b { color:var(--fg); font-weight:550; }
  .cont-PASS { color:var(--green); font-weight:700; } .cont-FAIL { color:var(--red); font-weight:700; }
  .st-RUNNING { border-left-color:var(--green); } .st-RUNNING .state { color:var(--green); }
  .st-SUSPENDED, .st-SUSPENDING { border-left-color:var(--amber); } .st-SUSPENDED .state, .st-SUSPENDING .state { color:var(--amber); }
  .st-RESUMING, .st-STARTING { border-left-color:var(--blue); } .st-RESUMING .state, .st-STARTING .state { color:var(--blue); }
  .st-FAILED, .st-TERMINATED { border-left-color:var(--red); } .st-FAILED .state, .st-TERMINATED .state { color:var(--red); }
  .logwrap { background:var(--panel); border:1px solid var(--border); border-radius:8px; }
  .loghead { padding:8px 14px; border-bottom:1px solid var(--border); font-weight:600; display:flex; justify-content:space-between; }
  .loghead .filter { color:var(--dim); font-weight:400; font-size:12px; }
  .loghead .filter a { color:var(--blue); cursor:pointer; text-decoration:none; }
  #log { height:340px; overflow-y:auto; padding:8px 14px; font:12px/1.6 "SF Mono",Menlo,Consolas,monospace; }
  #log .ev { white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
  #log .t { color:var(--dim); margin-right:8px; }
  #log .sb { color:var(--purple); margin-right:8px; }
  #log .k { font-weight:700; margin-right:8px; }
  #log .ok-false { color:var(--red); }
  .k-CREATE,.k-BIND { color:var(--blue); } .k-EXEC { color:var(--dim); } .k-CURL { color:#79c0ff; }
  .k-SUSPEND { color:var(--amber); } .k-RESTORE { color:var(--green); } .k-ERROR { color:var(--red); } .k-INFO { color:var(--fg); }
</style>
</head>
<body>
<h1>sandbox-sim <span class="scenario" id="scenario"></span></h1>
<div class="sub" id="sub">loading…</div>
<div class="stats" id="stats"></div>
<div class="cards" id="cards"></div>
<div class="logwrap">
  <div class="loghead"><span>Event log</span><span class="filter" id="filter"></span></div>
  <div id="log"></div>
</div>
<script>
let selected = null;
let state = null;
function esc(s){ const d=document.createElement('div'); d.textContent=s==null?'':String(s); return d.innerHTML; }
function statBox(k,v,cls){ return '<div class="stat '+(cls||'')+'"><div class="v">'+esc(v)+'</div><div class="k">'+esc(k)+'</div></div>'; }
function render(){
  if(!state) return;
  const st = state.stats || {};
  document.getElementById('scenario').textContent = 'scenario: ' + (state.scenario||'?');
  const byState = st.by_state || {};
  const parts = Object.keys(byState).sort().map(k => k.toLowerCase()+' '+byState[k]);
  document.getElementById('sub').textContent =
    'uptime '+ (st.uptime_seconds||0) +'s · control plane ' + (st.cp_healthy?'healthy':'UNREACHABLE') +
    ' · ' + parts.join(' · ');
  let boxes = statBox('sandboxes', (state.sandboxes||[]).length);
  boxes += statBox('restores', (st.restores||0)+' ok / '+(st.restore_fails||0)+' fail', st.restore_fails?'warn':'ok');
  boxes += statBox('continuity', (st.continuity_pass||0)+' / '+(st.continuity_fail||0), st.continuity_fail?'bad':'ok');
  boxes += statBox('exec ticks', (st.exec_ok||0)+' / '+(st.exec_fail||0), st.exec_fail?'warn':'ok');
  boxes += statBox('endpoint 200s', (st.curl_ok||0)+' / '+(st.curl_fail||0), st.curl_fail?'warn':'ok');
  boxes += statBox('latency avg', (st.avg_latency_ms||0)+'ms');
  boxes += statBox('latency p95', (st.p95_latency_ms||0)+'ms');
  boxes += statBox('control plane', st.cp_healthy?'up':'DOWN', st.cp_healthy?'ok':'bad');
  document.getElementById('stats').innerHTML = boxes;

  const cards = (state.sandboxes||[]).map(sb => {
    const cls = 'st-'+(sb.state||'');
    const cont = sb.continuity ? '<span class="cont-'+sb.continuity+'">'+sb.continuity+'</span>' : '<span style="color:var(--dim)">—</span>';
    return '<div class="card '+cls+(selected===sb.name?' sel':'')+'" onclick="toggle(\''+esc(sb.name)+'\')">' +
      '<span class="state">'+esc(sb.state||'?')+'</span>' +
      '<div class="name">'+esc(sb.name)+'</div>' +
      '<div class="row">epoch <b>'+sb.epoch+'</b> · ws gen <b>'+sb.workspace_generation+'</b> · counter <b>'+sb.counter+'</b></div>' +
      '<div class="row">continuity '+cont+'</div>' +
      '<div class="row">'+esc(sb.last_action||'')+'</div>' +
      '</div>';
  }).join('');
  document.getElementById('cards').innerHTML = cards;

  document.getElementById('filter').innerHTML = selected ?
    'filtered to <b>'+esc(selected)+'</b> · <a onclick="toggle(null)">clear</a>' : 'click a card to filter';
  const evs = (state.events||[]).filter(e => !selected || e.sandbox===selected).slice(-200);
  const log = document.getElementById('log');
  const atBottom = log.scrollHeight - log.scrollTop - log.clientHeight < 40;
  log.innerHTML = evs.map(e => {
    const t = (e.time||'').substr(11,8);
    return '<div class="ev"><span class="t">'+esc(t)+'</span>' +
      (e.sandbox?'<span class="sb">'+esc(e.sandbox)+'</span>':'') +
      '<span class="k k-'+esc(e.kind)+'">'+esc(e.kind)+'</span>' +
      '<span class="'+(e.ok?'':'ok-false')+'">'+esc(e.detail)+(e.dur_ms?' ('+e.dur_ms+'ms)':'')+'</span></div>';
  }).join('');
  if(atBottom) log.scrollTop = log.scrollHeight;
}
function toggle(name){ selected = (selected===name)?null:name; render(); }
function poll(){
  fetch('/api/state').then(r => r.json()).then(j => { state = j; render(); })
    .catch(() => { document.getElementById('sub').textContent = 'sim /api/state unreachable'; })
    .finally(() => setTimeout(poll, 1500));
}
poll();
</script>
</body>
</html>
`
