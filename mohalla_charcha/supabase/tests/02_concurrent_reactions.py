#!/usr/bin/env python3
"""DISPOSABLE mohalla_test database only. Requires psycopg[binary]."""
from concurrent.futures import ThreadPoolExecutor
import os
import uuid
import psycopg

DSN = os.getenv('DB_TEST_DSN', '')
USERS = [uuid.uuid5(uuid.NAMESPACE_DNS, f'mohalla-concurrency-{i}') for i in range(20)]


def connect():
    return psycopg.connect(DSN) if DSN else psycopg.connect()


def main():
    with connect() as conn:
        db = conn.execute('select current_database()').fetchone()[0]
        if db != 'mohalla_test':
            raise RuntimeError('Refusing to run destructive fixtures outside a database named mohalla_test.')
        conn.execute("insert into public.bl_locations(id,district,area_type,block_or_ulb,ward_number,ward_alias) values(9900,'Patna','urban','Concurrency test ULB',1,'Test only')")
        for i, uid in enumerate(USERS):
            conn.execute('insert into auth.users(id,phone,phone_confirmed_at) values(%s,NULL,NULL)', (uid,))
            conn.execute("select set_config('request.jwt.claim.sub',%s,false)", (str(uid),))
            conn.execute("select public.bl_save_profile(%s,9900,'')", (f'Test neighbour {i}',))
        conn.execute("select set_config('request.jwt.claim.sub',%s,false)", (str(USERS[0]),))
        post_id = conn.execute("select public.bl_create_post('civic_issue','Concurrency test issue','A disposable post to verify atomic counters.',9900,'{\"severity\":\"medium\"}')").fetchone()[0]

    def react(uid, active):
        with connect() as conn:
            conn.execute('set local role authenticated')
            conn.execute("select set_config('request.jwt.claim.sub',%s,true)", (str(uid),))
            for reaction in ('upvote', 'ditto_problem'):
                # Repeat desired state to exercise uniqueness/idempotency under contention.
                # Fixtures model anonymous guests: every auth user has no phone and no OTP.
                for _ in range(2):
                    conn.execute('select public.bl_set_reaction(%s,%s,%s)', (post_id, reaction, active))

    try:
        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(lambda uid: react(uid, True), USERS))
        with connect() as conn:
            votes, ditto = conn.execute("select upvotes_count,(metadata->>'ditto_count')::integer from public.bl_posts where id=%s", (post_id,)).fetchone()
            rows = conn.execute('select count(*) from public.bl_post_reactions where post_id=%s', (post_id,)).fetchone()[0]
            reputation = conn.execute('select reputation_score from public.bl_profiles where id=%s', (USERS[0],)).fetchone()[0]
            assert (votes, ditto, rows, reputation) == (20, 20, 40, 20), (votes, ditto, rows, reputation)
        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(lambda uid: react(uid, False), USERS))
        with connect() as conn:
            votes, ditto = conn.execute("select upvotes_count,(metadata->>'ditto_count')::integer from public.bl_posts where id=%s", (post_id,)).fetchone()
            rows = conn.execute('select count(*) from public.bl_post_reactions where post_id=%s', (post_id,)).fetchone()[0]
            assert (votes, ditto, rows) == (0, 0, 0), (votes, ditto, rows)
        print('PASS: 20 users, 8 concurrent connections, duplicate desired-state requests, exact upvote/ditto/reputation counters, exact removal.')
    finally:
        with connect() as conn:
            conn.execute('delete from auth.users where id = any(%s)', (USERS,))
            conn.execute('delete from public.bl_locations where id=9900')


if __name__ == '__main__':
    main()
