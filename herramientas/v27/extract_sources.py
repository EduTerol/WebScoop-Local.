#!/usr/bin/env python3
"""Exporta fuentes públicas HTML/JS/CSS de una captura de Scalper o de una URL.
No extrae cookies, cabeceras privadas ni URLs firmadas. Python stdlib.
"""
import argparse, email, hashlib, html, json, re, pathlib, urllib.request, urllib.parse, zipfile, mimetypes
from email import policy
from collections import Counter

KEYWORDS = re.compile(r'free_orders|/descargas/|/downloads/|creation_slug|download|descargar|blueprint|creation_zip|\.stl\b|\.3mf\b|\.zip\b|\.rar\b', re.I)
SENSITIVE = re.compile(r'(?:[?&](?:Signature|Expires|Key-Pair-Id|token|access_token|auth|key)=[^\s\"\'<>;&]+)', re.I)
HOSTS={'cults3d.com','www.cults3d.com','assets.cults3d.com'}
MAX=12_000_000

def safe_text(data):
    s=data.decode('utf-8','replace')
    s=SENSITIVE.sub(lambda m: m.group(0).split('=')[0]+'=[REDACTED]',s)
    s=re.sub(r'(<meta\b[^>]*name=[\"\']csrf-token[\"\'][^>]*content=[\"\'])[^\"\']+',r'\1[REDACTED]',s,flags=re.I)
    s=re.sub(r'(<input\b[^>]*name=[\"\']authenticity_token[\"\'][^>]*value=[\"\'])[^\"\']+',r'\1[REDACTED]',s,flags=re.I)
    return s

def classify(filename,mime):
    f=filename.lower().split('?')[0]; m=mime.lower()
    if f.endswith('.js') or 'javascript' in m:return 'js'
    if f.endswith('.css') or 'text/css' in m:return 'css'
    if f.endswith(('.html','.htm')) or 'text/html' in m:return 'html'
    if f.endswith('.json') or 'json' in m:return 'json'
    return None

def save(out, idx, kind, data, url, origin):
    if not data or len(data)>MAX: return None
    fn=f'{idx:04d}_{hashlib.sha256(data).hexdigest()[:12]}.{kind}'
    p=out/'fuentes'/kind/fn;p.parent.mkdir(parents=True,exist_ok=True)
    content=safe_text(data)
    p.write_text(content,encoding='utf-8')
    return {'archivo':str(p.relative_to(out)),'origen':origin,'url_publica':redact_url(url),'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),'tipo':kind}

def redact_url(url):
    try:
        u=urllib.parse.urlsplit(url)
        return urllib.parse.urlunsplit((u.scheme,u.netloc,u.path,'',''))
    except Exception:return '(desconocida)'

def extract_mhtml(data):
    msg=email.message_from_bytes(data,policy=policy.default)
    for part in msg.walk():
        if part.get_content_type()=='text/html':
            yield ('html', part.get_payload(decode=True) or b'',part.get('Content-Location','MHTML'))

def from_capture(files, prefix, out, entries):
    # files: mapping relative resource files -> bytes
    inv=json.loads(files['inventario.json'].decode('utf-8'))
    n=len(entries)
    for res in inv.get('resources',[]):
        filename=res.get('file',''); url=res.get('url','')
        if not filename or filename not in files:continue
        # Evita scripts de comprobación de seguridad que no son código de la aplicación.
        if '/cdn-cgi/challenge-platform/' in url or 'challenges.cloudflare.com' in url:continue
        kind=classify(filename,res.get('mime',''))
        if kind not in ('js','css','html','json'):continue
        item=save(out,n,kind,files[filename],url,prefix);n+=1
        if item: entries.append(item)
    if 'pagina.mhtml' in files:
        for kind, data, url in extract_mhtml(files['pagina.mhtml']):
            item=save(out,n,kind,data,url,prefix+' MHTML');n+=1
            if item:entries.append(item)

def from_archive(path,out,entries):
    with zipfile.ZipFile(path) as z:
        paths=z.namelist()
        prefixes=sorted({p[:p.index('inventario.json')] for p in paths if p.endswith('Cults3D_Copia_Local/inventario.json')})
        for prefix in prefixes:
            files={p[len(prefix):]:z.read(p) for p in paths if p.startswith(prefix) and not p.endswith('/') and (p.endswith(('.json','.js','.css','.html','.mhtml')))}
            from_capture(files,prefix.rstrip('/'),out,entries)
        if not prefixes:raise ValueError('ZIP sin inventario.json de Cults3D')

def from_folder(path,out,entries):
    bases=[p.parent for p in path.rglob('inventario.json') if p.parent.name=='Cults3D_Copia_Local']
    if (path/'inventario.json').exists():bases.insert(0,path)
    for base in sorted(set(bases)):
        files={str(p.relative_to(base)).replace('\\','/'):p.read_bytes() for p in base.rglob('*') if p.is_file() and p.suffix.lower() in ('.json','.js','.css','.html','.mhtml')}
        from_capture(files,str(base),out,entries)
    if not bases:raise ValueError('Directorio sin inventario.json de Cults3D')

def fetch_public(url,out,entries):
    # La navegación de GitHub puede recibir Cloudflare 403: no se intenta eludirlo.
    parsed=urllib.parse.urlsplit(url)
    if parsed.scheme!='https' or parsed.hostname not in HOSTS:raise ValueError('Solo https://cults3d.com y assets.cults3d.com')
    queue=[url];visited=set();n=len(entries);errors=[]
    while queue and len(visited)<180:
        u=queue.pop(0)
        if u in visited:continue
        visited.add(u)
        try:
            req=urllib.request.Request(u,headers={'User-Agent':'Scalper3D-V27-PublicSourceAudit/1.0','Accept':'text/html,application/javascript,text/css,*/*'})
            with urllib.request.urlopen(req,timeout=25) as response:
                final=response.geturl(); mime=response.headers.get_content_type();data=response.read(MAX+1)
            if urllib.parse.urlsplit(final).hostname not in HOSTS:continue
            if len(data)>MAX:errors.append('Recurso >12MB omitido: '+redact_url(u));continue
            kind=classify(urllib.parse.urlsplit(final).path,mime)
            if kind not in ('js','css','html','json'):continue
            if kind=='html' and ('Just a moment' in data[:8000].decode('utf-8','ignore')):
                errors.append('Cloudflare challenge detectado en '+redact_url(u));continue
            item=save(out,n,kind,data,final,'GitHub URL pública');n+=1
            if item:entries.append(item)
            if kind=='html':
                text=data.decode('utf-8','ignore')
                for raw in re.findall(r'<(?:script|link)\b[^>]*(?:src|href)\s*=\s*[\"\']([^\"\']+)',text,re.I):
                    ref=html.unescape(raw);next_url=urllib.parse.urljoin(final,ref)
                    q=urllib.parse.urlsplit(next_url)
                    if q.scheme=='https' and q.hostname in HOSTS and q.path.lower().endswith(('.js','.css')):
                        queue.append(next_url)
        except Exception as ex:
            errors.append(redact_url(u)+' -> '+str(ex)[:180])
    return errors

def report(out,entries,errors):
    records=[]
    for ent in entries:
        p=out/ent['archivo'];txt=p.read_text(encoding='utf-8',errors='replace')
        for m in list(KEYWORDS.finditer(txt))[:150]:
            start=max(0,m.start()-140);end=min(len(txt),m.end()+160)
            snippet=re.sub(r'\s+',' ',txt[start:end])
            records.append({'archivo':ent['archivo'],'termino':m.group(0),'posicion':m.start(),'contexto':snippet})
    (out/'inventario_fuentes.json').write_text(json.dumps(entries,ensure_ascii=False,indent=2),encoding='utf-8')
    (out/'coincidencias_descarga.json').write_text(json.dumps(records,ensure_ascii=False,indent=2),encoding='utf-8')
    count=Counter(e['tipo'] for e in entries)
    lines=['# V27 — Fuentes públicas de Cults3D','',f'**Archivos extraídos:** {len(entries)} | '+', '.join(f'{k}: {v}' for k,v in sorted(count.items())),f'**Coincidencias orientativas:** {len(records)}','', 'Los resultados son código cliente observado, no código privado del servidor. Las coincidencias no demuestran que existan descargas sin sesión.','','## Estado de captura',*((['- '+e for e in errors]) if errors else ['- Sin errores registrados.']),'','## Archivos','- `fuentes/`: HTML, JavaScript, CSS y JSON exportados.','- `inventario_fuentes.json`: correspondencia con las URLs de origen (sin parámetros).','- `coincidencias_descarga.json`: fragmentos donde aparecen términos de descarga.','','**Privacidad:** no almacena cookies ni cabeceras de sesión; elimina tokens habituales del HTML y parámetros de URL firmada. No subas inventarios privados sin revisarlos.']
    (out/'INFORME_V27.md').write_text('\n'.join(lines)+'\n',encoding='utf-8')
    print('\n'.join(lines[:5]));print('Errores:',len(errors))

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--archive');ap.add_argument('--folder');ap.add_argument('--url');ap.add_argument('--output',default='resultado-v27');args=ap.parse_args()
    out=pathlib.Path(args.output);out.mkdir(parents=True,exist_ok=True);entries=[];errors=[]
    if args.archive:from_archive(pathlib.Path(args.archive),out,entries)
    if args.folder:from_folder(pathlib.Path(args.folder),out,entries)
    if args.url:errors+=fetch_public(args.url,out,entries)
    if not any((args.archive,args.folder,args.url)):ap.error('Indica --archive, --folder o --url')
    report(out,entries,errors)

if __name__=='__main__':main()
