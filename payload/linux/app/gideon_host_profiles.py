from __future__ import annotations
import json, platform
from pathlib import Path
from typing import Any, Optional
DEFAULT_FILE = Path(__file__).resolve().parent / "config" / "host_profiles.json"

def normalize_platform(value: Optional[str]=None) -> str:
    raw=(value or platform.system()).strip().lower()
    if raw.startswith('win'): return 'windows'
    if raw in {'darwin','mac','macos'}: return 'darwin'
    if raw in {'linux','gnu/linux'}: return 'linux'
    return raw or 'unknown'

def normalize_arch(value: Optional[str]=None) -> str:
    raw=(value or platform.machine()).strip().lower()
    return {'amd64':'x86_64','x64':'x86_64','aarch64':'arm64','armv8':'arm64'}.get(raw, raw or 'unknown')


def normalize_profile_runtime(profile: dict[str, Any]) -> dict[str, Any]:
    """Return a runtime-safe profile without mutating persisted configuration.

    Built-in Windows profiles from older installations predate approved CMD/BAT
    execution even though WebAdmin can approve those extensions.  Incremental
    product updates deliberately cannot overwrite config/, so compatibility is
    applied in code only to GIDEON built-in Windows profiles. Custom profiles remain
    exactly as the administrator configured them.
    """
    value = dict(profile or {})
    if bool(value.get("builtin")) and normalize_platform(str(value.get("platform") or "")) == "windows":
        allowed = [str(x).lower() for x in value.get("allowed_extensions", []) if str(x).strip()]
        for ext in (".cmd", ".bat"):
            if ext not in allowed:
                allowed.append(ext)
        value["allowed_extensions"] = allowed
    return value

class HostProfileStore:
    def __init__(self,path:Path=DEFAULT_FILE):
        self.path=Path(path); self.data=self._load()
    def _load(self)->dict[str,Any]:
        v=json.loads(self.path.read_text(encoding='utf-8'))
        if not isinstance(v,dict) or not isinstance(v.get('profiles'),dict): raise RuntimeError('host_profiles.json inválido')
        v.setdefault('assignments',{}); return v
    @property
    def profiles(self): return self.data['profiles']
    def list_profiles(self): return sorted(self.profiles.items(),key=lambda x:str(x[1].get('label') or x[0]))
    def get(self,profile_id:str)->dict[str,Any]:
        if profile_id not in self.profiles: raise KeyError(f'Host profile no existe: {profile_id}')
        v=dict(self.profiles[profile_id]); v['id']=profile_id; return normalize_profile_runtime(v)
    def resolve(self,site_code:str,override:Optional[str]=None)->dict[str,Any]:
        pid=override or self.data.get('assignments',{}).get(str(site_code)) or self.data.get('default_profile')
        return self.get(str(pid))
    def assign(self,site_code:str,profile_id:str)->None:
        self.get(profile_id); self.data.setdefault('assignments',{})[str(site_code)]=profile_id; self.save()
    def unassign(self,site_code:str)->None:
        self.data.setdefault('assignments',{}).pop(str(site_code),None); self.save()
    def save(self)->None:
        tmp=self.path.with_suffix(self.path.suffix+'.tmp'); tmp.write_text(json.dumps(self.data,ensure_ascii=False,indent=2),encoding='utf-8'); tmp.replace(self.path)
    def create(self,profile_id:str,value:dict[str,Any])->None:
        profile_id=str(profile_id).strip()
        if not profile_id or not profile_id.replace('_','').replace('-','').isalnum(): raise ValueError('ID de plantilla inválido; use letras, números, _ o -.')
        if profile_id in self.profiles: raise ValueError(f'Host profile ya existe: {profile_id}')
        profile=dict(value); profile['builtin']=False; self.profiles[profile_id]=profile; self.save()
    def update(self,profile_id:str,value:dict[str,Any])->None:
        current=self.get(profile_id); profile=dict(value); profile['builtin']=bool(current.get('builtin',False)); self.profiles[profile_id]=profile; self.save()
    def duplicate(self,source_id:str,new_id:str,label:Optional[str]=None)->None:
        source=self.get(source_id); source.pop('id',None); source['builtin']=False
        if label: source['label']=str(label)
        self.create(new_id,source)
    def delete(self,profile_id:str)->None:
        profile=self.get(profile_id)
        if profile.get('builtin'): raise ValueError('Las plantillas integradas no se eliminan; duplíquela para personalizar.')
        self.profiles.pop(profile_id,None); assignments=self.data.setdefault('assignments',{})
        for site in [k for k,v in assignments.items() if v==profile_id]: assignments.pop(site,None)
        if self.data.get('default_profile')==profile_id: self.data['default_profile']=next(iter(self.profiles),'')
        self.save()
    def validate_runtime(self,profile:dict[str,Any],platform_name:str,arch:str)->tuple[bool,str]:
        expected=normalize_platform(str(profile.get('platform') or '')); current=normalize_platform(platform_name)
        if expected and expected!=current: return False,f"Perfil {profile.get('id')} espera {expected}, host reporta {current}."
        supported=[normalize_arch(str(x)) for x in profile.get('architectures',[])]; cur=normalize_arch(arch)
        if supported and cur not in supported: return False,f'Arquitectura {cur} no está permitida por el perfil.'
        return True,'OK'
