# Brancher le journal d'audit (guide pour les autres modules)

`src/audit.py` : aucune dépendance. Journal par défaut `outputs/audit.jsonl`
(variable `CLAIMGUARD_AUDIT_LOG` ou argument `log=`). Tout module appelle des fonctions ; **personne n'écrit
dans le fichier à la main**.

Règle d'or : **ni clé API, ni texte libre du claim** (`notes`, texte des pièces jointes, prompt, réponse brute du
modèle). Un champ nommé `api_key`, `password`, `token`... ou une valeur qui a la forme d'un secret
(`sk-...`, `Bearer ...`, `AKIA...`, `ghp_...`, clé privée) est refusé ; un texte de plus de 1000 caractères aussi.
Un mot comme « password » dans un motif de relecteur n'est pas refusé.

Politique en cas d'échec : **fail-closed**. Si l'audit lève `AuditError`, le run s'arrête ; ne l'attrapez pas pour
continuer sans trace. Un journal dont la fin est incomplète se répare avec `python src/audit.py --repair`.

## 1. Ingestion (fichier reçu, ligne rejetée)

```python
import audit
audit.log_file("data/development/claims.jsonl", "claims_input")           # nom, taille, SHA-256
audit.log_ingestion_error(f"{path}:{numero_ligne}", type(exc).__name__)   # jamais le contenu de la ligne
```

## 2. Moteur de règles (une fois par claim)

```python
rule_versions = {"ruleset": audit.ruleset_fingerprint("rules"), "engine_version": "0.3"}
run_id, input_hash = audit.run_started(claim["claim_id"], raw_line_bytes, rule_versions)
audit.log_attachments(run_id, claim)                     # hash de chaque pièce jointe, pas son texte
try:
    results = evaluate(claim)                            # les 15 résultats du moteur (rule_id + status)
except Exception as exc:
    audit.run_failed(run_id, claim["claim_id"], type(exc).__name__)
    raise
audit.run_completed(run_id, claim["claim_id"], results)  # statut ET hash du constat de CHAQUE règle
```

`raw_line_bytes` = octets originaux de la ligne JSONL, avant `json.loads`.
Claim corrigé : `audit.run_started(..., previous_run=(ancien_run_id, ancien_input_hash))` (crée `CORRECTION_CREATED`).
`src/run_baseline.py` montre l'exemple complet.

## 3. Appel modèle (LLM ou mock)

```python
t0 = time.perf_counter(); error = None; fallback = False
try:
    explanation = llm_explain(...)                       # JSON invalide = erreur
except Exception as exc:
    error, fallback = type(exc).__name__, True
    explanation = template_explain(...)                  # les constats déterministes restent intacts
audit.log_model_call(run_id, claim_id, "nom-du-modele", audit.file_hash("prompts/explain_findings.md"),
                     round((time.perf_counter() - t0) * 1000), error, fallback, rule_id="R004")
```
Ou en une ligne : `audit.audited_model_call(log, run_id, claim_id, model_id, prompt_version, call_fn, fallback_fn)`.

## 4. Décisions de revue

La page exporte `review_decisions.jsonl`, puis :

```bash
python src/audit.py --events outputs/review_decisions.jsonl --predictions outputs/predictions.jsonl
```

Chaque décision est **liée au run et au constat** enregistrés dans le journal. Tout le lot est refusé si un
statut d'origine ne correspond pas au run, si le claim n'a jamais été évalué, si le fichier de prédictions a
changé depuis le run, ou si un motif est vide. Une décision ne porte jamais de statut réécrit : une
correction est un nouveau fichier et un nouveau run.
`--unbound` importe sans lien (format hérité, déconseillé). En Python :

```python
audit.log_review(actor, "dismiss_with_reason", claim_id, rule_id, reason, original_status="FAIL")
```
Actions : `confirm_issue`, `dismiss_with_reason`, `request_information`, `mark_corrected_for_recheck`
(ce dernier pose `recheck_pending`). Acteur, claim, règle, motif et statut d'origine sont obligatoires.

## 5. Évaluation, erreurs d'outil

```python
audit.log_evaluation("validation", "outputs/val_predictions.jsonl", "outputs/val_metrics.json", commit="<hash git>")
audit.log_tool_error("llm", type(exc).__name__, run_id=run_id, claim_id=claim_id)
```

## 6. Sans Python

```bash
python src/audit.py --add '{"type":"INGESTION_ERROR","source":"claims.jsonl:12","error":"JSONDecodeError"}'
```
Types autorisés : `INGESTION_ERROR`, `TOOL_ERROR`, `MODEL_CALL`, `RUN_FAILED`. Les résultats et les décisions ne
peuvent pas être fabriqués par `--add`. Chaque événement ajouté ainsi porte `"via": "cli"`.

## 7. Contrôles

```bash
python src/audit.py --verify                                   # toute la chaîne
python src/audit.py --verify --expect-file outputs/audit_anchors.txt   # + troncature / remplacement complet
python src/audit.py --trace CG-27BFD8541DEB                    # historique d'un claim (chaîne vérifiée d'abord)
python src/audit.py --summary                                  # comptes par type, statut de règle, décision
python src/audit.py --anchor --anchor-file outputs/audit_anchors.txt
python src/audit.py --repair                                   # ligne finale incomplète (écriture interrompue)
python src/audit_demo.py                                       # démonstration de falsification
python -m unittest discover -s tests -v
```

`--trace --fast` lit par l'index : chaque ligne est contrôlée, mais la complétude n'est pas prouvée (utiliser
sans `--fast` pour une preuve). L'index `.idx` est dérivé : supprimable, il se reconstruit.

## 8. À faire pour que l'audit ait de la valeur

- Lancer `python src/audit.py --verify --expect-file ...` **avant chaque démo** et à la fin de chaque run
  (`run_baseline.py` enregistre déjà une ancre).
- **Copier la dernière ancre hors du dépôt** (message au mentor, commit dans un autre dépôt). Une ancre qui reste
  à côté du journal n'est qu'une démonstration.
- Optionnel : `export CLAIMGUARD_AUDIT_HMAC_KEY=...` (clé jamais dans le dépôt). Chaque ligne porte alors un HMAC :
  une chaîne recalculée sans la clé est détectée. Celui qui a la clé peut encore écrire.
- `CLAIMGUARD_AUDIT_FSYNC=0` : écriture plus rapide mais moins durable (tests de charge seulement).
