from __future__ import annotations
import argparse, ipaddress, json

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--candidates',required=True); ap.add_argument('--used',required=True)
    a=ap.parse_args()
    candidates=json.loads(a.candidates); used_raw=json.loads(a.used)
    used=[]
    for item in used_raw:
        try: used.append(ipaddress.ip_network(str(item), strict=False))
        except Exception: pass
    for item in candidates:
        c=ipaddress.ip_network(str(item),strict=False)
        if not any(c.overlaps(u) for u in used):
            hosts=list(c.hosts())
            print(json.dumps({'subnet':str(c),'host_ip':str(hosts[0]),'guest_ip':str(hosts[1])}))
            return 0
    print(json.dumps({'error':'NO_FREE_SUBNET'}))
    return 2
if __name__=='__main__': raise SystemExit(main())
