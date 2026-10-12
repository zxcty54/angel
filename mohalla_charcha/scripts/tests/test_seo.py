import importlib.util
import json
from html.parser import HTMLParser
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('sync_identity', ROOT/'scripts/sync_identity.py')
seo = importlib.util.module_from_spec(spec)
spec.loader.exec_module(seo)


class Page(HTMLParser):
    def __init__(self):
        super().__init__(); self.tags=[]; self.meta=[]; self.jsonld=[]; self.in_jsonld=False
    def handle_starttag(self,tag,attrs):
        attrs=dict(attrs); self.tags.append(tag)
        if tag=='meta': self.meta.append(attrs)
        if tag=='script' and attrs.get('type')=='application/ld+json': self.in_jsonld=True
    def handle_endtag(self,tag):
        if tag=='script': self.in_jsonld=False
    def handle_data(self,data):
        if self.in_jsonld: self.jsonld.append(data)


class IdentitySEOTests(unittest.TestCase):
    def test_identity_name_and_short_description_limits(self):
        data=seo.identity()
        self.assertEqual(data['display_name'],'Bihar Local - Mohalla Charcha')
        self.assertEqual(len(data['display_name']),29)
        self.assertLessEqual(len(data['short_description']),80)

    def test_generated_files_are_current(self):
        for path,text in seo.outputs().items():
            self.assertEqual(path.read_text(),text,str(path))

    def test_native_name_changes_but_android_id_does_not(self):
        data=seo.identity()
        xml=ET.parse(ROOT/'android/app/src/main/res/values/strings.xml')
        self.assertEqual(xml.find('string').text,data['display_name'])
        self.assertIn('android:label="@string/app_name"',(ROOT/'android/app/src/main/AndroidManifest.xml').read_text())
        self.assertIn('in.mohallacharcha.app',(ROOT/'android/app/build.gradle.kts').read_text())

    def test_web_manifest_matches_display_identity(self):
        data=seo.identity(); manifest=json.loads((ROOT/'web/manifest.json').read_text())
        self.assertEqual(manifest['name'],data['display_name'])
        self.assertEqual(manifest['short_name'],'Bihar Local')

    def test_static_landing_has_one_title_h1_and_useful_content(self):
        html=(ROOT/'web/discover/index.html').read_text(); page=Page();page.feed(html)
        self.assertEqual(page.tags.count('title'),1); self.assertEqual(page.tags.count('h1'),1)
        self.assertIn('No government APIs',html) if 'No government APIs' in html else self.assertIn('no government APIs',html)
        self.assertIn('Gram Panchayat',html); self.assertIn('Neighbourhood reviews',html)
        self.assertNotIn('flutter_bootstrap.js',html)

    def test_no_meta_keywords_fake_rating_or_fake_store_url(self):
        html=(ROOT/'web/discover/index.html').read_text();page=Page();page.feed(html)
        self.assertFalse(any(m.get('name') in ['keywords','meta-keyword'] for m in page.meta))
        schema=json.loads(''.join(page.jsonld))
        self.assertEqual(schema['name'],seo.identity()['display_name'])
        self.assertNotIn('aggregateRating',schema); self.assertNotIn('offers',schema)
        self.assertNotIn('downloadUrl',schema);self.assertNotIn('url',schema)
        self.assertNotIn('rel="canonical"',html)

    def test_public_https_url_generates_real_canonical_sitemap(self):
        data=seo.identity();data['site_url']='https://site.example/app/'
        with patch.object(seo,'identity',return_value=data): result=seo.outputs()
        self.assertIn('https://site.example/app/discover/',result[ROOT/'web/discover/index.html'])
        xml=ET.fromstring(result[ROOT/'web/sitemap.xml'])
        urls=[e.text for e in xml.iter() if e.tag.endswith('loc')]
        self.assertEqual(urls,['https://site.example/app/','https://site.example/app/discover/'])

    def test_invalid_domain_and_changing_id_are_rejected(self):
        data=seo.identity()
        with tempfile.TemporaryDirectory() as t:
            root=Path(t);(root/'branding').mkdir()
            for url in ['http://site.example/','https://localhost/','https://user:password@site.example/']:
                data['site_url']=url;(root/'branding/app_identity.json').write_text(json.dumps(data))
                with self.assertRaises(ValueError):seo.identity(root)
            data['site_url']=None;data['application_id']='some.other.app'
            (root/'branding/app_identity.json').write_text(json.dumps(data))
            with self.assertRaisesRegex(ValueError,'application ID'):seo.identity(root)


if __name__=='__main__':unittest.main()
