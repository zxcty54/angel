#!/usr/bin/env python3
"""Sync honest display branding/SEO; keep Android ID and preference keys stable.
Stdlib only. No keyword stuffing, fake rankings, ratings, publisher URLs or keys.
"""
import argparse
from html import escape
import json
from pathlib import Path
import re
from urllib.parse import urlparse
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]


def identity(root=ROOT):
    data = json.loads((root/'branding/app_identity.json').read_text())
    if not 1 <= len(data['display_name']) <= 30:
        raise ValueError('Store display name must be 1–30 characters.')
    if len(data['short_description']) > 80:
        raise ValueError('Store short description must be at most 80 characters.')
    if data['application_id'] != 'in.mohallacharcha.app':
        raise ValueError('A display rename must not change the existing Android application ID.')
    if data.get('site_url'):
        u = urlparse(data['site_url'])
        if (u.scheme != 'https' or not u.netloc or u.username or u.password or u.query or u.fragment
                or u.hostname in ('localhost','127.0.0.1')):
            raise ValueError('Use a real public HTTPS site URL without credentials/query/fragment.')
        data['site_url'] = data['site_url'].rstrip('/')+'/'
    return data


def dart_string(value):
    return "'"+value.replace('\\','\\\\').replace("'","\\'").replace('$','\\$').replace('\n','\\n')+"'"


def replace_one(pattern, replacement, text):
    result, count = re.subn(pattern, lambda _: replacement, text, flags=re.S)
    if count != 1:
        raise ValueError('Identity marker missing or repeated: '+pattern)
    return result


def page_metadata(data, landing=False):
    title = escape(data['website_title'])
    description = escape(data['web_description'], quote=True)
    tags = f'<title>{title}</title>\n  <meta name="description" content="{description}">\n  <meta name="application-name" content="{escape(data["display_name"],quote=True)}">\n  <meta name="robots" content="index,follow,max-image-preview:large">\n  <meta property="og:title" content="{escape(data["website_title"],quote=True)}">\n  <meta property="og:description" content="{description}">\n  <meta property="og:type" content="website">\n  <meta property="og:locale" content="en_IN">\n  <meta name="twitter:card" content="summary">'
    if data.get('site_url'):
        canonical=data['site_url']+('discover/' if landing else '')
        tags += f'\n  <link rel="canonical" href="{escape(canonical,quote=True)}">\n  <meta property="og:url" content="{escape(canonical,quote=True)}">'
    if landing:
        schema={'@context':'https://schema.org','@type':'SoftwareApplication',
                'name':data['display_name'],'description':data['web_description'],
                'applicationCategory':'SocialNetworkingApplication','operatingSystem':'Android',
                'inLanguage':['hi','en'],'softwareVersion':data['version']}
        if data.get('site_url'):schema['url']=data['site_url']+'discover/'
        tags += '\n  <script type="application/ld+json">'+json.dumps(schema,ensure_ascii=False).replace('<','\\u003c')+'</script>'
    return tags


def outputs(root=ROOT):
    data=identity(root)
    constants = [('displayName','display_name'),('primaryName','primary_name'),('secondaryName','secondary_name'),('shortName','short_name'),('version','version')]
    dart='// Generated from branding/app_identity.json by scripts/sync_identity.py.\n// Display rename only: application ID, backend schema and device keys stay stable.\nabstract final class AppIdentity {\n'
    for field,key in constants:dart+=f'  static const {field} = {dart_string(data[key])};\n'
    dart+='}\n'
    strings='<?xml version="1.0" encoding="utf-8"?>\n<resources>\n    <string name="app_name">'+escape(data['display_name'])+'</string>\n</resources>\n'
    manifest=json.loads((root/'web/manifest.json').read_text())
    manifest.update(name=data['display_name'],short_name=data['short_name'],description=data['web_description'])
    index=(root/'web/index.html').read_text()
    index=replace_one(r'<!-- IDENTITY_META_START -->.*?<!-- IDENTITY_META_END -->','<!-- IDENTITY_META_START -->\n  '+page_metadata(data)+'\n  <!-- IDENTITY_META_END -->',index)
    index=replace_one(r'<meta name="apple-mobile-web-app-title"[^>]*>',f'<meta name="apple-mobile-web-app-title" content="{escape(data["short_name"],quote=True)}">',index)
    index=replace_one(r'<strong id="app-loading-name">.*?</strong>','<strong id="app-loading-name">'+escape(data['display_name'])+'</strong>',index)
    landing=(root/'seo/landing.template.html').read_text()
    landing=landing.replace('{{PAGE_META}}',page_metadata(data,landing=True)).replace('{{APP_NAME}}',escape(data['display_name'])).replace('{{PRIMARY_NAME}}',escape(data['primary_name'])).replace('{{SECONDARY_NAME}}',escape(data['secondary_name']))
    result={root/'lib/config/app_identity.dart':dart,
            root/'android/app/src/main/res/values/strings.xml':strings,
            root/'web/manifest.json':json.dumps(manifest,ensure_ascii=False,indent=2)+'\n',
            root/'web/index.html':index,root/'web/discover/index.html':landing}
    if data.get('site_url'):
        site=data['site_url'];result[root/'web/robots.txt']='User-agent: *\nAllow: /\nSitemap: '+site+'sitemap.xml\n'
        sitemap=ET.Element('urlset',xmlns='http://www.sitemaps.org/schemas/sitemap/0.9')
        # Only real, substantive pages. No generated empty city/ward doorway pages.
        for path in ['', 'discover/']:
            ET.SubElement(ET.SubElement(sitemap,'url'),'loc').text=site+path
        result[root/'web/sitemap.xml']='<?xml version="1.0" encoding="utf-8"?>\n'+ET.tostring(sitemap,encoding='unicode')+'\n'
    else:result[root/'web/robots.txt']='User-agent: *\nAllow: /\n# Add a real public site_url in branding/app_identity.json, then sync for sitemap/canonicals.\n'
    return result


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--check',action='store_true');args=parser.parse_args()
    result=outputs()
    if args.check:
        drift=[str(p.relative_to(ROOT)) for p,s in result.items() if not p.exists() or p.read_text()!=s]
        if drift:parser.exit(1,'Identity drift: '+', '.join(drift)+'\n')
        print('Display identity, native/web metadata and static SEO page match. IDs unchanged.')
        return
    for path,text in result.items():path.parent.mkdir(parents=True,exist_ok=True);path.write_text(text)
    if not identity().get('site_url'):
        # Never leave fake/stale canonical URLs from a previous configuration.
        (ROOT/'web/sitemap.xml').unlink(missing_ok=True)
    print('Identity/SEO files synced. No domain assumed; no ranking or volume claim.')


if __name__=='__main__':main()
