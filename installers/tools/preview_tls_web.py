"""Loopback-only visual fixture. No real credentials, keys, broker or GIDEON services."""
import datetime as dt
from pathlib import Path
import sys
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[2]
sys.path.append(str(ROOT/'payload/windows/GIDEON Remote Control/venv/Lib/site-packages'))
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from jinja2 import Environment, FileSystemLoader, select_autoescape
import uvicorn

APP = ROOT/'payload/linux/app/gideon_web_admin'
env = Environment(loader=FileSystemLoader(APP/'templates'), autoescape=select_autoescape(['html']))
app = FastAPI()
app.mount('/static', StaticFiles(directory=str(APP/'static')), name='static')
certificate = {'expires':'2027-09-01T00:00:00+00:00','days_left':364,'sha256':'abcd'*16}
status = {'current':{'mode':'private-ca','web_url':'https://203.0.113.20:9443','agent_url':'https://203.0.113.20',
                    'web_host':'203.0.113.20','agent_host':'203.0.113.20','web_port':9443,'agent_port':443,
                    'admin_cidr':['203.0.113.4/32'], 'certificates':{'web':certificate,'gateway':certificate}},
          'jobs':[], 'busy':False,'certbot_installed':True,'renewal_timer_active':False}


@app.get('/infrastructure/tls', response_class=HTMLResponse)
def page():
    identity = SimpleNamespace(role='SUPERADMIN', username='visual-test', display_name='Prueba visual', csrf_token='fixture-only', can=lambda value:True)
    return env.get_template('tls_management.html').render(title='PRUEBA VISUAL · TLS y acceso externo',identity=identity,
        tls_status=status,tls_error='',tls_enabled=True,client_ip='203.0.113.4',active_path='/infrastructure/tls',
        product_version='6.3.4-rc30 · DATOS SIMULADOS',agent_version='fixture',gateway_version='fixture',
        step_up={'active':True,'until_unix':int(dt.datetime.now().timestamp())+900,'remaining_seconds':900})


@app.get('/infrastructure/tls/status')
def read_status(): return {'ok':True,'result':status}


@app.post('/infrastructure/tls/{action}')
async def action(request:Request, action:str):
    data=await request.json()
    if action=='prepare':
        params=data['params']
        def url(host,port): return 'https://'+host+('' if port==443 else ':'+str(port))
        job={'id':'a'*32,'state':'PREPARED','created':1,'preview':{'mode':params['mode'],'web_url':url(params['web_host'],params['web_port']),
             'agent_url':url(params['agent_host'],params['agent_port']),'admin_cidr':params['admin_cidr'],
             'certificates':{'web':certificate,'gateway':certificate}, 'acme_pending':params['mode']=='letsencrypt'}}
        status['jobs']=[job]
    elif status['jobs']:
        job=status['jobs'][0];job['state']={'apply':'AWAITING_CONFIRMATION','confirm':'CONFIRMED','cancel':'CANCELLED'}.get(action,'FAILED')
        job['deadline']=int(dt.datetime.now().timestamp())+300
    else:
        return JSONResponse({'ok':False,'error':'No hay solicitud de prueba.'}, status_code=400)
    return {'ok':True,'result':job}


if __name__=='__main__':
    uvicorn.run(app, host='127.0.0.1', port=8768, access_log=False)
