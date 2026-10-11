#!/usr/bin/env python3
"""Regenerate the hand-drawn vector brand and committed Android/web icons.
Optional development tool: python3 -m pip install CairoSVG==2.8.2
No network calls, AI generation, credentials or runtime dependency.
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PRIMARY = '#BD5337'
BACKGROUND = '#F6F7F3'
PATHS = [
    (PRIMARY, 'M28 0H72C88 0 100 12 100 28V72C100 88 88 100 72 100H28C12 100 0 88 0 72V28C0 12 12 0 28 0Z', None, None),
    ('#FFFFFF', 'M27 21H70C79 21 84 26 84 35V60C84 69 78 75 69 75H42L25 88V75H24C17 75 12 69 12 61V34C12 26 19 21 27 21Z', None, None),
    (PRIMARY, 'M28 47L47 31L66 47V62H53V50H41V62H28Z', None, None),
    ('#39765D', 'M68 54H80C85 54 88 57 88 62V68C88 73 85 76 80 76H77L70 82V76H68C63 76 60 72 60 68V62C60 58 63 54 68 54Z', BACKGROUND, 3),
    ('none', 'M67 62H81M67 68H77', '#FFFFFF', 3),
]


def svg():
    paths = []
    for fill, data, stroke, width in PATHS:
        extra = f' stroke="{stroke}" stroke-width="{width}" stroke-linecap="round" stroke-linejoin="round"' if stroke else ''
        paths.append(f'<path fill="{fill}" d="{data}"{extra}/>')
    return ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100" width="1024" height="1024" role="img" aria-labelledby="title desc">'
            '<title id="title">Mohalla Charcha</title><desc id="desc">A home inside a conversation, with a second neighbour joining in.</desc>'
            + ''.join(paths) + '</svg>\n')


def vector(size=96, safe=False, foreground=False):
    paths = []
    for fill, data, stroke, width in PATHS[1 if foreground else 0:]:
        fill = '#00000000' if fill == 'none' else fill
        extra = f' android:strokeColor="{stroke}" android:strokeWidth="{width}" android:strokeLineCap="round" android:strokeLineJoin="round"' if stroke else ''
        paths.append(f'    <path android:fillColor="{fill}" android:pathData="{data}"{extra}/>\n')
    group = '<group android:scaleX="0.68" android:scaleY="0.68" android:translateX="16" android:translateY="16">' if safe else '<group>'
    if foreground:
        group = '<group android:scaleX="0.72" android:scaleY="0.72" android:translateX="18" android:translateY="18">'
    viewport = 108 if foreground else 100
    return (f'<vector xmlns:android="http://schemas.android.com/apk/res/android" android:width="{size}dp" android:height="{size}dp" android:viewportWidth="{viewport}" android:viewportHeight="{viewport}">\n'
            f'  {group}\n' + ''.join(paths) + '  </group>\n</vector>\n')


def write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding='utf-8')


def main():
    import cairosvg
    source = svg()
    branding = ROOT / 'assets/branding'
    write(branding / 'logo.svg', source)
    def png(path, size):
        path.parent.mkdir(parents=True, exist_ok=True)
        cairosvg.svg2png(bytestring=source.encode(), write_to=str(path), output_width=size, output_height=size)
    png(branding / 'logo.png', 1024)
    res = ROOT / 'android/app/src/main/res'
    for density, size in [('mdpi',48),('hdpi',72),('xhdpi',96),('xxhdpi',144),('xxxhdpi',192)]:
        png(res/f'mipmap-{density}/ic_launcher.png', size)
    for name, size in [('Icon-192.png',192),('Icon-512.png',512),('Icon-maskable-192.png',192),('Icon-maskable-512.png',512)]:
        png(ROOT/'web/icons'/name,size)
    png(ROOT/'web/favicon.png',64)
    write(res/'drawable/mc_splash_logo.xml', vector())
    write(res/'drawable/mc_splash_icon.xml', vector(safe=True))
    write(res/'drawable/mc_launcher_foreground.xml', vector(size=108, foreground=True))
    write(res/'mipmap-anydpi-v26/ic_launcher.xml', '<adaptive-icon xmlns:android="http://schemas.android.com/apk/res/android">\n  <background android:drawable="@color/mc_primary"/>\n  <foreground android:drawable="@drawable/mc_launcher_foreground"/>\n</adaptive-icon>\n')
    print('Brand SVG/PNG, density icons, adaptive Android logo, native splash vectors and web icons generated.')


if __name__ == '__main__':
    main()
