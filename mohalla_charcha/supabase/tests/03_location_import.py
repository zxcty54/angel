#!/usr/bin/env python3
"""Integration-check illustrative seed and importer in a DISPOSABLE mock DB.
Requires migration + 00_supabase_mock.sql. NEVER run against real Supabase.
CI owns/discards the database; fixtures intentionally remain for inspection.
"""
import csv
import os
from pathlib import Path
import sys
import tempfile

import psycopg

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
from import_locations import COLUMNS, render_import  # noqa: E402


def main():
    if not os.environ.get('PGDATABASE', '').startswith('mohalla_test'):
        raise SystemExit('Use an explicitly named disposable mohalla_test* database only.')
    with psycopg.connect(autocommit=True) as db, tempfile.TemporaryDirectory() as tmp:
        actual_database = db.execute('SELECT current_database()').fetchone()[0]
        if not actual_database.startswith('mohalla_test'):
            raise SystemExit('Connected database is not a disposable mohalla_test* database.')
        seed = (ROOT / 'supabase/seed_demo_locations.sql').read_text(encoding='utf-8')
        db.execute(seed)
        db.execute(seed)  # documented opt-in seed can be re-applied
        ids = [1, 2, 3, 4, 101, 102, 103, 201, 202, 301, 401, 501]
        assert db.execute('SELECT count(*) FROM public.bihar_locations WHERE id=ANY(%s)', (ids,)).fetchone()[0] == 12
        file = Path(tmp) / 'fixtures.csv'
        rows = [
            ['Patna', 'urban', 'Patna Municipal Corporation', '', 22, 'आयात परीक्षण', 25.599, 85.158],
            ['Patna', 'urban', "IMPORT TEST ULB's", '', 600, "Ward's alias", '', ''],
            ['Patna', 'rural', 'IMPORT TEST BLOCK', "GP 'alpha'", 4, 'परीक्षण', 25.5, 85.1],
            ['Patna', 'rural', 'IMPORT TEST BLOCK', "GP 'beta'", 4, 'दूसरा परीक्षण', '', ''],
        ]
        def apply():
            with file.open('w', encoding='utf-8', newline='') as output:
                writer = csv.writer(output); writer.writerow(COLUMNS); writer.writerows(rows)
            db.execute(render_import(file, 'Integration fixture only — not official'))
        apply()
        apply()  # NULL urban panchayat conflicts correctly; no duplicate paths
        assert db.execute("SELECT count(*) FROM public.bihar_locations WHERE block_or_ulb LIKE 'IMPORT TEST%%'").fetchone()[0] == 3
        alias, longitude, latitude = db.execute('SELECT ward_alias, extensions.st_x(geom), extensions.st_y(geom) FROM public.bihar_locations WHERE id=1').fetchone()
        assert (alias, longitude, latitude) == ('आयात परीक्षण', 85.158, 25.599)
        assert db.execute('SELECT ward_alias FROM public.bihar_locations WHERE block_or_ulb=%s', ("IMPORT TEST ULB's",)).fetchone()[0] == "Ward's alias"
        rows[1][5:] = ['Updated alias', 25.6, 85.2]
        apply()
        assert db.execute('SELECT ward_alias, latitude, longitude FROM public.bihar_locations WHERE block_or_ulb=%s', ("IMPORT TEST ULB's",)).fetchone() == ('Updated alias', 25.6, 85.2)
        assert db.execute("SELECT count(DISTINCT panchayat_name) FROM public.bihar_locations WHERE block_or_ulb='IMPORT TEST BLOCK' AND ward_number=4").fetchone()[0] == 2
    print('PASS: illustrative seed x2; importer x3; full-path upsert, Unicode/quotes, nulls, PostGIS coordinates and rural ward isolation.')


if __name__ == '__main__':
    main()
