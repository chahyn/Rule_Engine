"""Run the three implemented checks. Extend engine_core.baseline for your MVP.

[TEAM] Écrit aussi la trace d'audit (outputs/audit.jsonl) : fichier reçu, octets d'origine de chaque claim,
empreinte des règles, pièces jointes, résultat de CHAQUE règle, erreurs d'ingestion, puis une ancre.
"""
import argparse, json
from pathlib import Path
from engine_core import config, baseline, validate_transport
import audit  # [TEAM]

ENGINE_VERSION = 'baseline-0.1'  # [TEAM] à changer à chaque modification du comportement du moteur

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--input', default='data/development/claims.jsonl'); p.add_argument('--output', default='outputs/predictions.jsonl'); p.add_argument('--limit', type=int)
    p.add_argument('--audit-log', default='outputs/audit.jsonl'); p.add_argument('--anchor-file', default='outputs/audit_anchors.txt')  # [TEAM]
    a = p.parse_args(); root = Path(__file__).resolve().parents[1]; cfg = config(root); log = a.audit_log
    audit.verify(log)  # [TEAM] on n'écrit pas par-dessus un journal falsifié (lève AuditError)
    rule_versions = {'ruleset': audit.ruleset_fingerprint(root / 'rules'), 'engine_version': ENGINE_VERSION}  # [TEAM]
    audit.log_file(a.input, 'claims_input', log=log)  # [TEAM]
    raws = [l for l in Path(a.input).read_bytes().splitlines() if l.strip()]
    if a.limit is not None: raws = raws[:a.limit]
    out = Path(a.output); out.parent.mkdir(parents=True, exist_ok=True); done = errors = 0
    with out.open('w', encoding='utf-8') as f:
        for n, raw in enumerate(raws, 1):
            try:
                c = json.loads(raw); validate_transport(c)
            except Exception as exc:  # [TEAM] ligne rejetée : mise en quarantaine et tracée, jamais ignorée
                errors += 1; audit.log_ingestion_error(f'{Path(a.input).name}:{n}', type(exc).__name__, log=log); continue
            run_id, _ = audit.run_started(c['claim_id'], raw, rule_versions, log=log)  # [TEAM] hash des octets d'origine
            audit.log_attachments(run_id, c, log=log)  # [TEAM]
            try:
                results = baseline(c, cfg)
            except Exception as exc:  # [TEAM]
                errors += 1; audit.run_failed(run_id, c['claim_id'], type(exc).__name__, log=log); continue
            for result in results: f.write(json.dumps(result, ensure_ascii=False) + '\n')
            audit.run_completed(run_id, c['claim_id'], results, log=log)  # [TEAM] statut + hash de chaque règle
            done += 1
    print(f'Processed {done} claims ({errors} errors). Implemented: R001, R003, R006. Other rules: NOT_IMPLEMENTED. Output: {out}')
    print('Audit anchor:', audit.save_anchor(log, a.anchor_file))  # [TEAM]
if __name__ == '__main__': main()
