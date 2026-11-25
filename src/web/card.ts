/**
 * Verdict card shown inside AI chat apps that render MCP UI resources: MCP Apps hosts (Claude and others,
 * ui:// resources with the text/html;profile=mcp-app type) and ChatGPT apps (text/html+skybridge, window.openai).
 * The page is self-contained (no network, no external fonts) and reads the tool's structuredContent.
 */

export const CARD_URI = 'ui://oculon/verdict.html';
export const CARD_URI_OPENAI = 'ui://oculon/verdict-openai.html';
export const MCP_APP_MIME = 'text/html;profile=mcp-app';
export const SKYBRIDGE_MIME = 'text/html+skybridge';

export interface CardData {
  kind: string;
  title: string;
  verdict: string | null;
  tone: 'bad' | 'warn' | 'ok' | 'info';
  risk: number | null;
  points: string[];
  sources: string;
  seenBefore: { at: string; changes: string[] } | null;
  links: { replay: string | null; report: string | null };
  checkId: string;
}

export const CARD_HTML = `<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<style>
:root{--bg:#05090a;--line:#1d2a2d;--ink:#eef3f4;--mut:#8fa3a7;--y:#00f0ff;--bad:#ff5d6c;--warn:#f5a524;--ok:#3ddc97;--info:#8fa3a7}
@media (prefers-color-scheme: light){:root{--bg:#ffffff;--line:#dfe6e8;--ink:#0d1416;--mut:#5b6b6f;--y:#007a85;--bad:#c8323f;--warn:#b26f00;--ok:#14895a;--info:#5b6b6f}}
*{box-sizing:border-box}
html,body{margin:0;background:transparent;color:var(--ink);font:14px/1.5 ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif}
.c{border:1px solid var(--line);background:var(--bg);border-radius:12px;padding:16px 18px;max-width:640px}
.top{display:flex;justify-content:space-between;align-items:center;font:600 11px ui-monospace,Consolas,monospace;letter-spacing:.18em;color:var(--mut);text-transform:uppercase}
.top b{color:var(--y)}
.t{margin:8px 0 10px;font-size:15px;font-weight:600;overflow-wrap:anywhere}
.v{display:flex;align-items:center;gap:12px;flex-wrap:wrap}
.pill{font:700 13px ui-monospace,Consolas,monospace;letter-spacing:.06em;text-transform:uppercase;padding:6px 10px;border-radius:6px;color:#fff;background:var(--info)}
.pill.bad{background:var(--bad)}.pill.warn{background:var(--warn)}.pill.ok{background:var(--ok)}
.risk{flex:1;min-width:140px}.risk span{font:600 12px ui-monospace,Consolas,monospace;color:var(--mut)}
.bar{height:6px;background:var(--line);border-radius:4px;margin-top:4px;overflow:hidden}.bar i{display:block;height:100%}
ul{margin:12px 0 0;padding-left:18px}li{margin:3px 0}
.seen{margin-top:12px;border-left:3px solid var(--y);padding:6px 10px;font-size:13px;color:var(--mut)}
.seen b{color:var(--ink)}
.foot{margin-top:14px;display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap;font-size:12px;color:var(--mut)}
.foot a{color:var(--y);cursor:pointer;text-decoration:none;margin-left:12px}
.empty{color:var(--mut)}
</style></head>
<body><div class="c" id="c"><div class="empty">Waiting for the result...</div></div>
<script>
(function(){
  var esc=function(s){return String(s==null?'':s).replace(/[&<>"']/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];});};
  var nextId=1, pending={};
  function rpc(method, params){
    var id=nextId++;
    try{ window.parent.postMessage({jsonrpc:'2.0',id:id,method:method,params:params||{}},'*'); }catch(e){}
    return new Promise(function(res){ pending[id]=res; setTimeout(function(){ if(pending[id]){ delete pending[id]; res(null);} },3000); });
  }
  function notify(method, params){ try{ window.parent.postMessage({jsonrpc:'2.0',method:method,params:params||{}},'*'); }catch(e){} }
  function open(url){
    if(!url) return;
    if(window.openai && window.openai.openExternal){ window.openai.openExternal({href:url}); return; }
    rpc('ui/open-link',{url:url}).then(function(r){ if(!r) window.open(url,'_blank','noopener'); });
  }
  function size(){ var h=document.documentElement.scrollHeight; notify('ui/notifications/size-changed',{width:document.documentElement.scrollWidth,height:h}); }
  function render(d){
    if(!d||!d.checkId){ return; }
    var color={bad:'var(--bad)',warn:'var(--warn)',ok:'var(--ok)',info:'var(--info)'}[d.tone]||'var(--info)';
    var h='<div class="top"><span><b>OCULON</b> &middot; '+esc(d.kind)+'</span><span>'+esc(d.checkId.slice(0,8))+'</span></div>';
    h+='<div class="t">'+esc(d.title)+'</div><div class="v"><span class="pill '+esc(d.tone)+'">'+esc(d.verdict||'result')+'</span>';
    if(d.risk!=null) h+='<div class="risk"><span>risk '+esc(d.risk)+'/100</span><div class="bar"><i style="width:'+Math.max(2,Math.min(100,d.risk))+'%;background:'+color+'"></i></div></div>';
    h+='</div>';
    if(d.points&&d.points.length) h+='<ul>'+d.points.slice(0,6).map(function(p){return '<li>'+esc(p)+'</li>';}).join('')+'</ul>';
    if(d.seenBefore) h+='<div class="seen"><b>Seen before</b> on '+esc(String(d.seenBefore.at).slice(0,16).replace('T',' '))+' UTC. '+(d.seenBefore.changes.length?esc(d.seenBefore.changes.slice(0,4).join('; ')):'Nothing changed since then.')+'</div>';
    h+='<div class="foot"><span>'+esc(d.sources)+'</span><span>'+(d.links&&d.links.replay?'<a data-u="'+esc(d.links.replay)+'">Replay log</a>':'')+(d.links&&d.links.report?'<a data-u="'+esc(d.links.report)+'">PDF report</a>':'')+'</span></div>';
    var c=document.getElementById('c'); c.innerHTML=h;
    Array.prototype.forEach.call(c.querySelectorAll('a[data-u]'),function(a){ a.onclick=function(){ open(a.getAttribute('data-u')); }; });
    size();
  }
  function fromResult(r){ if(!r) return null; return r.structuredContent||(r.result&&r.result.structuredContent)||null; }
  window.addEventListener('message',function(ev){
    var m=ev.data; if(!m||typeof m!=='object') return;
    if(m.id!=null&&pending[m.id]){ var f=pending[m.id]; delete pending[m.id]; f(m.result||null); return; }
    if(m.method==='ui/notifications/tool-result') render(fromResult(m.params));
    if(m.type==='openai:set_globals'&&window.openai) render(window.openai.toolOutput);
  });
  window.addEventListener('openai:set_globals',function(){ if(window.openai) render(window.openai.toolOutput); });
  if(window.openai&&window.openai.toolOutput) render(window.openai.toolOutput);
  rpc('ui/initialize',{protocolVersion:'2026-01-26',appInfo:{name:'oculon-verdict',version:'1.0.0'},appCapabilities:{}}).then(function(){ notify('ui/notifications/initialized',{}); });
})();
</script></body></html>`;
