#!/usr/bin/env python3
from __future__ import annotations
import argparse,csv,html,json,os,secrets,shlex,shutil,socket,subprocess,sys,tempfile,threading,time,webbrowser
from pathlib import Path
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from urllib.parse import parse_qs,urlparse

IS_MAC=sys.platform=="darwin"; IS_LINUX=sys.platform.startswith("linux")
ROOT_DEFAULT=Path("/Library/Application Support/GIDEONAgent") if IS_MAC else Path("/opt/gideon-agent")

CSS="""*{box-sizing:border-box}body{margin:0;background:#0e161d;color:#f6f8fa;font-family:Segoe UI,Inter,system-ui,-apple-system,sans-serif;min-height:100vh}.wrap{max-width:820px;margin:36px auto;padding:0 18px}.brand{display:flex;gap:12px;align-items:center;margin-bottom:20px}.logo{width:42px;height:42px;border-radius:10px;background:linear-gradient(135deg,#e31837 0 48%,#fff 49% 55%,#0078ae 56%)}h1{font-size:24px;margin:0}.sub{color:#9db0bd;margin:3px 0}.card{background:#151f27;border:1px solid #2b3b47;border-radius:14px;padding:24px;box-shadow:0 20px 50px #0006}.warn{border-left:4px solid #ff7a1a;background:#ff7a1a12;padding:12px 14px;border-radius:8px;margin-bottom:20px;color:#ffd7bd}.grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}.full{grid-column:1/-1}label{display:block;font-size:13px;font-weight:700;margin-bottom:6px}input,select{width:100%;padding:11px 12px;background:#0f1921;color:#fff;border:1px solid #40525f;border-radius:8px;font:inherit}input:focus,select:focus{outline:none;border-color:#08a9e6;box-shadow:0 0 0 3px #08a9e622}.hint{font-size:12px;color:#9db0bd;margin-top:5px}.actions{display:flex;justify-content:flex-end;gap:10px;margin-top:22px}button{padding:11px 18px;border:0;border-radius:8px;font-weight:700;cursor:pointer}.primary{background:#08a9e6;color:#fff}.secondary{background:#263640;color:#fff}.primary:disabled{opacity:.6;cursor:wait}.msg{white-space:pre-wrap;padding:13px;border-radius:8px;margin-top:16px}.err{background:#35191d;border:1px solid #7b3039;color:#ffd2d7}.ok{background:#123724;border:1px solid #216b42;color:#cdf8dd}.status{font-size:12px;color:#9db0bd;margin-top:15px}.dot{display:inline-block;width:8px;height:8px;background:#50d890;border-radius:50%;margin-right:7px}.spin{display:inline-block;width:14px;height:14px;border:2px solid #ffffff55;border-top-color:#fff;border-radius:50%;animation:s .7s linear infinite;margin-right:7px;vertical-align:-2px}@keyframes s{to{transform:rotate(360deg)}}@media(max-width:680px){.grid{grid-template-columns:1fr}.full{grid-column:1}.wrap{margin:18px auto}}"""

def esc(v):return html.escape(str(v or ""),quote=True)
def load_json(p):
    try:
        x=json.loads(Path(p).read_text(encoding="utf-8-sig"));return x if isinstance(x,dict) else {}
    except Exception:return {}
def defaults(root):
    t=load_json(root/"agent.template.json");cp=t.get("control_plane") if isinstance(t.get("control_plane"),dict) else {}
    return {"agent_name":socket.gethostname(),"site_code":str(t.get("site_code") or "").strip(),"site_name":str(t.get("site_name") or "").strip(),"gateway":str(cp.get("base_url") or "").strip()}
def sites(root):
    p=root/"site-catalog.csv"
    if not p.is_file():return []
    text=p.read_text(encoding="utf-8-sig",errors="replace")
    try:d=csv.Sniffer().sniff(text[:4096],delimiters=",;|\t")
    except Exception:d=csv.excel
    out=[];r=csv.reader(text.splitlines(),dialect=d)
    for row in r:
        if len(row)<2:continue
        a,b=str(row[0]).strip(),str(row[1]).strip()
        if not a or not b or a.casefold() in {"sitecode","site_code","codigo","código","code"}:continue
        out.append((a,b))
    seen=set();return [x for x in out if not ((x[0].casefold(),x[1].casefold()) in seen or seen.add((x[0].casefold(),x[1].casefold())))]
def run(cmd,timeout=1200):
    cp=subprocess.run(cmd,text=True,capture_output=True,timeout=timeout)
    return cp.returncode,((cp.stdout or "")+("\n"+cp.stderr if cp.stderr else "")).strip()
def secret_file(value):
    value=str(value or "").strip()
    if not value:return None
    fd,p=tempfile.mkstemp(prefix=f"gideon-enroll-{os.getuid()}-",suffix=".secret");os.close(fd)
    Path(p).write_text(value,encoding="utf-8");os.chmod(p,0o600);return Path(p)
def privileged(values):
    args=["--site-code",values["site_code"],"--site-name",values["site_name"],"--agent-name",values["agent_name"],"--gateway",values["gateway"],"--non-interactive"]
    sf=secret_file(values.get("secret",""))
    if sf:args+=["--enrollment-secret-file",str(sf)]
    setup=shutil.which("gideon-agent-setup") or "/usr/local/bin/gideon-agent-setup"
    try:
        if os.geteuid()==0:return run([setup,*args])
        if IS_LINUX:
            px=shutil.which("pkexec")
            if not px:return 127,"No se encontró pkexec/Polkit. Use la contingencia: sudo gideon-agent-setup"
            return run([px,setup,*args])
        if IS_MAC:
            cmd=" ".join(shlex.quote(x) for x in [setup,*args])
            return run(["/usr/bin/osascript","-e",f"do shell script {json.dumps(cmd)} with administrator privileges"])
        return 2,"Sistema no soportado por el wizard."
    finally:
        if sf:
            try:sf.unlink(missing_ok=True)
            except Exception:pass
def opener(url):
    if IS_MAC:
        try:subprocess.Popen(["/usr/bin/open",url],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);return True
        except Exception:pass
    if IS_LINUX:
        for c in (["xdg-open",url],["gio","open",url],["sensible-browser",url]):
            e=shutil.which(c[0])
            if e:
                try:subprocess.Popen([e,*c[1:]],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);return True
                except Exception:pass
    try:return bool(webbrowser.open(url,new=1))
    except Exception:return False
def page(token,root,message="",ok=False):
    d=defaults(root);ss=sites(root);opts=['<option value="">Seleccione una sede…</option>']
    for c,n in ss:opts.append(f'<option value="{esc(c)}" data-name="{esc(n)}"{" selected" if c==d["site_code"] else ""}>{esc(c)} · {esc(n)}</option>')
    opts.append('<option value="__manual__">Otra / ingreso manual</option>')
    boot=(root/"bootstrap.enrollment").exists()
    hint="Credencial temporal incluida automáticamente. No se muestra ni se expone al navegador." if boot else "No se detectó bootstrap. Ingrese una credencial temporal."
    msg=f'<div class="msg {"ok" if ok else "err"}">{esc(message)}</div>' if message else ""
    macnote='<div class="hint">macOS puede solicitar Screen Recording/Accessibility en Ajustes del Sistema. Apple no permite conceder esos permisos silenciosamente sin MDM/PPPC.</div>' if IS_MAC else ""
    return f"""<!doctype html><html><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><title>Gideon Rx Agent · Identificación</title><style>{CSS}</style></head><body><div class=wrap><div class=brand><div class=logo></div><div><h1>Gideon Rx Agent</h1><div class=sub>Identificación y enrolamiento inicial</div></div></div><div class=card><div class=warn><b>CRUCIAL:</b> estos datos identifican el dispositivo en la consola principal de Gideon Rx Project. Verifique nombre, código y sede.</div><form method=post action=/apply><input type=hidden name=token value="{esc(token)}"><div class=grid><div class=full><label>Nombre del agente</label><input name=agent_name required maxlength=120 value="{esc(d["agent_name"])}"></div><div class=full><label>Sede registrada</label><select id=sel>{''.join(opts)}</select></div><div><label>Código de sede</label><input id=code name=site_code required value="{esc(d["site_code"])}"></div><div><label>Nombre de sede</label><input id=name name=site_name required value="{esc(d["site_name"])}"></div><div class=full><label>Gateway HTTPS</label><input name=gateway type=url pattern="https://.*" required value="{esc(d["gateway"])}"></div><div class=full><label>Secreto de enrolamiento</label><input name=secret type=password autocomplete=off placeholder="{'Incluido automáticamente' if boot else 'Credencial temporal'}"><div class=hint>{esc(hint)}</div></div></div><div class=status><span class=dot></span>Asistente local 127.0.0.1. La elevación ocurre sólo al aplicar.</div>{macnote}{msg}<div class=actions><button type=button class=secondary onclick="window.close()">Cancelar</button><button id=go class=primary>Configurar y enrolar</button></div></form></div></div><script>const s=document.getElementById('sel'),c=document.getElementById('code'),n=document.getElementById('name');function sync(){{let o=s.options[s.selectedIndex];if(!o)return;if(s.value==='__manual__'){{c.readOnly=false;n.readOnly=false;c.focus();return}}if(s.value){{c.value=s.value;n.value=o.dataset.name||'';c.readOnly=true;n.readOnly=true}}}}s.onchange=sync;if(s.value)sync();document.querySelector('form').onsubmit=()=>{{let b=document.getElementById('go');b.disabled=true;b.innerHTML='<span class=spin></span>Configurando…'}};</script></body></html>"""
class App:
    def __init__(self,root):self.root=root;self.token=secrets.token_urlsafe(32);self.done=threading.Event()
    def handler(self):
        app=self
        class H(BaseHTTPRequestHandler):
            def log_message(self,*a):pass
            def send_html(self,s,status=200):
                b=s.encode();self.send_response(status);self.send_header("Content-Type","text/html; charset=utf-8");self.send_header("Content-Length",str(len(b)));self.send_header("Cache-Control","no-store");self.send_header("Content-Security-Policy","default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; form-action 'self'");self.end_headers();self.wfile.write(b)
            def do_GET(self):
                u=urlparse(self.path)
                if u.path!="/":self.send_error(404);return
                t=parse_qs(u.query).get("token",[""])[0]
                if not secrets.compare_digest(t,app.token):self.send_error(403);return
                if (app.root/"agent.json").is_file():self.send_html(page(app.token,app.root,"Agent ya identificado.",True));app.done.set();return
                self.send_html(page(app.token,app.root))
            def do_POST(self):
                if self.path!="/apply":self.send_error(404);return
                try:l=min(int(self.headers.get("Content-Length","0")),65536)
                except Exception:l=0
                q=parse_qs(self.rfile.read(l).decode("utf-8","replace"))
                t=q.get("token",[""])[0]
                if not secrets.compare_digest(t,app.token):self.send_error(403);return
                v={k:str(q.get(k,[""])[0]).strip() for k in ("agent_name","site_code","site_name","gateway","secret")}
                if not all(v[k] for k in ("agent_name","site_code","site_name")):self.send_html(page(app.token,app.root,"Nombre, código y sede son obligatorios."),400);return
                if not v["gateway"].lower().startswith("https://"):self.send_html(page(app.token,app.root,"Gateway debe usar HTTPS."),400);return
                try:rc,out=privileged(v)
                except Exception as e:rc,out=1,f"{type(e).__name__}: {e}"
                if rc==0 and (app.root/"agent.json").is_file():
                    extra="\n\nAgent enrolado y Remote Access preparado."
                    if IS_MAC:extra+="\nmacOS puede pedir permisos de Screen Recording/Accessibility."
                    self.send_html(page(app.token,app.root,(out[-2200:] or "Configuración completada.")+extra,True));app.done.set();threading.Timer(2,self.server.shutdown).start()
                else:self.send_html(page(app.token,app.root,out[-4000:] or f"Falló rc={rc}"),500)
        return H
def main():
    p=argparse.ArgumentParser();p.add_argument("--root",type=Path,default=ROOT_DEFAULT);p.add_argument("--auto",action="store_true");a=p.parse_args()
    root=a.root
    if (root/"agent.json").is_file():return 0
    if not (root/"agent.template.json").is_file():return 3
    try:
        import fcntl
        lock=(Path(tempfile.gettempdir())/f"gideon-agent-first-run-{os.getuid()}.lock").open("w");fcntl.flock(lock.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
    except Exception:return 0
    app=App(root);srv=ThreadingHTTPServer(("127.0.0.1",0),app.handler());url=f"http://127.0.0.1:{srv.server_address[1]}/?token={app.token}"
    if a.auto:time.sleep(.8)
    if not opener(url):return 4
    th=threading.Thread(target=srv.serve_forever,daemon=True);th.start();app.done.wait(3600);srv.shutdown();srv.server_close();return 0
if __name__=="__main__":raise SystemExit(main())

