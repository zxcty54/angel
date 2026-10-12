#!/usr/bin/env python3
"""Validate a location CSV and emit reviewable privileged SQL. No credentials.
This checks structural consistency, NOT official administrative accuracy.
"""
import argparse
import csv
import math
from pathlib import Path

DISTRICTS = set('Araria|Arwal|Aurangabad|Banka|Begusarai|Bhagalpur|Bhojpur|Buxar|Darbhanga|East Champaran|Gaya|Gopalganj|Jamui|Jehanabad|Kaimur|Katihar|Khagaria|Kishanganj|Lakhisarai|Madhepura|Madhubani|Munger|Muzaffarpur|Nalanda|Nawada|Patna|Purnia|Rohtas|Saharsa|Samastipur|Saran|Sheikhpura|Sheohar|Sitamarhi|Siwan|Supaul|Vaishali|West Champaran'.split('|'))
COLUMNS = ('district','area_type','block_or_ulb','panchayat_name','ward_number','ward_alias','latitude','longitude')


def literal(value):
    if value is None: return 'NULL'
    if isinstance(value, (int, float)): return str(value)
    return "'" + str(value).replace("'", "''") + "'"


def render_import(path: Path, source: str = 'UNVERIFIED — check source before live use') -> str:
    values = []; seen = set()
    with path.open(encoding='utf-8-sig', newline='') as file:
        reader = csv.DictReader(file)
        if not set(COLUMNS).issubset(reader.fieldnames or []):
            raise ValueError('CSV headers must include: ' + ','.join(COLUMNS))
        for line, raw in enumerate(reader, start=2):
            row = {name: (raw.get(name) or '').strip() for name in COLUMNS}
            district, area, unit = row['district'], row['area_type'], row['block_or_ulb']
            panchayat = row['panchayat_name'] or None
            if district not in DISTRICTS:
                raise ValueError(f'Line {line}: unknown district; normalize official spellings to the catalogue.')
            if area not in ('urban','rural') or not unit or len(unit)>100:
                raise ValueError(f'Line {line}: invalid area type or block/ULB name.')
            if area == 'urban' and panchayat is not None or area == 'rural' and panchayat is None:
                raise ValueError(f'Line {line}: urban must have empty panchayat; rural must have a panchayat.')
            if panchayat and len(panchayat)>100 or len(row['ward_alias'])>150:
                raise ValueError(f'Line {line}: name/alias too long.')
            try: ward = int(row['ward_number'])
            except ValueError: raise ValueError(f'Line {line}: ward must be an integer.') from None
            if not 1 <= ward <= 999: raise ValueError(f'Line {line}: ward must be between 1 and 999.')
            identity = (district, area, unit, panchayat, ward)
            if identity in seen: raise ValueError(f'Line {line}: duplicate complete administrative path.')
            seen.add(identity)
            if bool(row['latitude']) != bool(row['longitude']):
                raise ValueError(f'Line {line}: supply both coordinates or neither.')
            latitude = longitude = None
            if row['latitude']:
                try: latitude, longitude = float(row['latitude']), float(row['longitude'])
                except ValueError: raise ValueError(f'Line {line}: invalid numeric coordinates.') from None
                if not math.isfinite(latitude) or not math.isfinite(longitude) or not -90<=latitude<=90 or not -180<=longitude<=180:
                    raise ValueError(f'Line {line}: coordinates must be finite and within geographic ranges.')
            values.append('(' + ','.join(map(literal, (*identity, row['ward_alias'], latitude, longitude))) + ')')
    if not values: raise ValueError('No location rows. This is a template, not a verified dataset.')
    safe_source = ' '.join(source.splitlines())
    return ('-- Structurally validated, NOT officially certified by this helper.\n'
            f'-- Source supplied by operator: {safe_source}\nBEGIN;\n'
            'INSERT INTO public.bl_locations(' + ','.join(COLUMNS) + ') VALUES\n'
            + ',\n'.join(values) + '\nON CONFLICT ON CONSTRAINT location_full_path DO UPDATE SET\n'
            'ward_alias=EXCLUDED.ward_alias, latitude=EXCLUDED.latitude, longitude=EXCLUDED.longitude;\nCOMMIT;\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('csv_file', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--source', default='UNVERIFIED — check source before live use')
    args = parser.parse_args()
    try:
        sql = render_import(args.csv_file, args.source)
        args.output.write_text(sql, encoding='utf-8')
        print(f'Generated {args.output.name}. Review accuracy/provenance before applying as a privileged operator.')
    except (ValueError, OSError) as error:
        parser.exit(1, f'Import validation failed: {error}\n')
