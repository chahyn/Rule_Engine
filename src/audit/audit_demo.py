"""Démonstration de falsification (Lab 5) : quelle protection détecte quelle attaque.

    python src/audit_demo.py

Travaille dans un dossier temporaire ; ne touche pas à outputs/audit.jsonl.
"""
import json, os, tempfile
from pathlib import Path
from unittest import mock
import audit

KEY = {'CLAIMGUARD_AUDIT_HMAC_KEY': 'demo-key-not-a-secret'}


def build(d, keyed):
    log, anchors = str(d / 'audit.jsonl'), str(d / 'anchors.txt')
    with mock.patch.dict(os.environ, KEY if keyed else {}):
        for cid in ('CG-A', 'CG-B'):
            rid, _ = audit.run_started(cid, b'{"claim":"%s"}' % cid.encode(), {'engine_version': 'demo'}, log=log)
            audit.run_completed(rid, cid, [{'claim_id': cid, 'rule_id': 'R001', 'status': 'FAIL'}, {'claim_id': cid, 'rule_id': 'R002', 'status': 'PASS'}], log=log)
        audit.log_review('reviewer1', 'confirm_issue', 'CG-A', 'R001', 'Missing invoice number confirmed', 'FAIL', log=log)
        audit.save_anchor(log, anchors)
    return Path(log), anchors


def lines(p): return p.read_text(encoding='utf-8').splitlines()
def put(p, ls): p.write_text('\n'.join(ls) + '\n', encoding='utf-8')


def rechain(p):
    previous, out = audit.GENESIS, []
    for l in lines(p):
        row, _, _ = audit._parse(l); row['previous_hash'] = previous; previous = audit.digest(row)
        out.append(json.dumps({**row, 'hash': previous}))
    put(p, out)


ATTACKS = [
    ('Edit the reviewer decision', lambda p: put(p, lines(p)[:-1] + [lines(p)[-1].replace('confirm_issue', 'dismiss_with_reason')]), False),
    ('Delete an event in the middle', lambda p: put(p, lines(p)[:1] + lines(p)[2:]), False),
    ('Cut off the last events', lambda p: put(p, lines(p)[:3]), False),
    ('Edit, then recompute every hash', lambda p: (put(p, [l.replace('Missing invoice number confirmed', 'Looks fine') for l in lines(p)]), rechain(p)), False),
    ('Same forgery on a log written with the HMAC key', lambda p: (put(p, [l.replace('Missing invoice number confirmed', 'Looks fine') for l in lines(p)]), rechain(p)), True),
]


def caught(fn):
    try: fn(); return 'MISSED'
    except ValueError: return 'detected'


def main():
    print(f"{'Attack':<50}{'chain only':<13}{'+ anchor':<11}{'+ HMAC key'}")
    for name, attack, keyed in ATTACKS:
        with tempfile.TemporaryDirectory() as t:
            log, anchors = build(Path(t), keyed); attack(log)
            chain = caught(lambda: audit.verify(str(log)))
            anch = caught(lambda: audit.verify(str(log), audit.load_anchors(anchors)))
            with mock.patch.dict(os.environ, KEY):
                mac = caught(lambda: audit.verify(str(log))) if keyed else 'n/a'
            print(f'{name:<50}{chain:<13}{anch:<11}{mac}')
    print("\n'MISSED' in the first column shows why the head hash must be anchored outside the log,"
          "\nand why an HMAC key kept outside the log's storage stops a recomputed forgery.")


if __name__ == '__main__': main()
