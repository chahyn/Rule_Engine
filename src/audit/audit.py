"""Local tamper-evident audit trail for ClaimGuard AI; not immutable storage or authentication.

Bibliothèque + CLI, sans dépendance. Les autres modules appellent les fonctions log_* / run_* (voir
docs/AUDIT_INTEGRATION.md). Journal : argument log=..., sinon CLAIMGUARD_AUDIT_LOG, sinon outputs/audit.jsonl.

Format d'une ligne : {sequence, recorded_at, previous_hash, event, hash[, mac]} (JSONL, ajout seul).
Les décisions de revue gardent leur forme historique (champ "action", pas de "type").

Ce que le journal permet de prouver
  * quel run, sur quelle entrée (hash des octets d'origine), avec quelles règles (empreinte des fichiers) ;
  * pour chaque claim, le résultat de CHAQUE règle (statut + hash du constat), pas seulement des compteurs ;
  * chaque décision humaine liée au constat exact et au run sur lesquels elle a été prise ;
  * chaque fichier reçu, pièce jointe (hash), appel modèle (version du prompt, repli), erreur d'outil ;
  * que rien n'a été modifié, supprimé ou réordonné (chaîne de hash), tronqué ou remplacé (ancres externes),
    et, si CLAIMGUARD_AUDIT_HMAC_KEY est défini, que chaque ligne a été écrite par un détenteur de la clé.

Conception : append() ne relit que la dernière ligne (coût constant) ; verify() relit tout, à la demande ;
un index annexe <journal>.idx accélère --trace (dérivé, reconstruit s'il est incohérent).
Limites à déclarer : pas d'authentification des acteurs, pas de stockage WORM, ancrage manuel, verrou de
fichier coopératif, HMAC symétrique (celui qui a la clé peut écrire). Un fichier local n'est pas immuable.
"""
from pathlib import Path
import json, hashlib, hmac, argparse, os, re, sys, time, uuid, contextlib
from datetime import datetime, timezone

GENESIS = '0' * 64
DEFAULT_LOG = os.environ.get('CLAIMGUARD_AUDIT_LOG', 'outputs/audit.jsonl')
FSYNC = os.environ.get('CLAIMGUARD_AUDIT_FSYNC', '1') != '0'  # 0 = plus rapide, moins durable
LOCK_STALE_SECONDS = 30
MAX_STRING = 1000  # une chaîne plus longue ressemble à du texte de claim collé : refusée
REVIEW_ACTIONS = {'confirm_issue', 'dismiss_with_reason', 'request_information', 'mark_corrected_for_recheck'}
FORBIDDEN_REVIEW_KEYS = {'status', 'new_status', 'result_status', 'final_status'}  # une décision ne réécrit jamais un statut
SYSTEM_EVENTS = {  # type -> champs obligatoires
    'INGESTION_ERROR': {'source', 'error'},
    'FILE_RECEIVED': {'file_role', 'file_name', 'size_bytes', 'sha256'},
    'RUN_STARTED': {'run_id', 'claim_id', 'input_hash', 'rule_versions'},
    'ATTACHMENT_RECEIVED': {'run_id', 'claim_id', 'attachment_id', 'attachment_type', 'text_sha256'},
    'RUN_COMPLETED': {'run_id', 'claim_id', 'n_results', 'status_counts', 'rule_results', 'results_sha256'},
    'RUN_FAILED': {'run_id', 'claim_id', 'error'},
    'MODEL_CALL': {'run_id', 'claim_id', 'model_id', 'prompt_version', 'latency_ms', 'error', 'fallback'},
    'TOOL_ERROR': {'tool', 'error'},
    'CORRECTION_CREATED': {'claim_id', 'previous_run_id', 'previous_input_hash', 'new_input_hash'},
    'EVALUATION_COMPLETED': {'split', 'predictions_sha256', 'metrics_sha256'},
    'LOG_REPAIRED': {'quarantined_sha256', 'quarantined_bytes', 'after_sequence'},
}
CLI_ALLOWED_TYPES = {'INGESTION_ERROR', 'TOOL_ERROR', 'MODEL_CALL', 'RUN_FAILED'}  # --add ne peut pas fabriquer de résultats

# Secrets : noms de champs suspects (exacts) et valeurs qui ont la forme d'un secret. Un simple mot comme
# "password" dans un motif de relecteur n'est PAS refusé (sinon une décision humaine légitime serait perdue).
SECRET_KEY_RE = re.compile(r'(^|[_-])(api[_-]?key|apikey|secret|client[_-]?secret|password|passwd|authorization|token|'
                           r'access[_-]?token|auth[_-]?token|private[_-]?key|credentials?|hmac[_-]?key)$', re.I)
SECRET_VALUE_RE = re.compile(
    r'(?<![A-Za-z0-9])(?:sk-[A-Za-z0-9_-]{16,}|ghp_[A-Za-z0-9]{20,}|gho_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}'
    r'|xox[baprs]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{30,})'
    r'|Bearer\s+[A-Za-z0-9._~+/=-]{16,}|Authorization:\s*(?:Basic|Bearer|Token)\s+\S+'
    r'|-----BEGIN [A-Z ]*PRIVATE KEY-----|eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+')
_PARSE_ERRORS = (ValueError, KeyError, TypeError, AttributeError)


class AuditError(ValueError):
    """Événement invalide, journal incohérent ou écriture refusée (sous-classe de ValueError)."""


class AuditLockError(AuditError):
    """Verrou d'écriture non obtenu ou perdu : rien n'a été écrit."""


def digest(obj):
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def file_hash(path):
    """SHA-256 d'un fichier (ex. prompts/explain_findings.md -> prompt_version), None s'il n'existe pas."""
    p = Path(path)
    return sha256_bytes(p.read_bytes()) if p.exists() else None


def finding_hash(result):
    """Empreinte d'un résultat de règle tel que le moteur l'a produit (ce que le relecteur a vu)."""
    return digest(result)


def ruleset_fingerprint(folder='rules'):
    """Empreinte des fichiers de règles : à passer comme rule_versions à run_started."""
    files = {p.name: sha256_bytes(p.read_bytes()) for p in sorted(Path(folder).glob('*.json'))}
    return {'files': files, 'ruleset_sha256': digest(files)}


def _hmac_key():
    key = os.environ.get('CLAIMGUARD_AUDIT_HMAC_KEY')
    return key.encode('utf-8') if key else None


def _mac(key, row_hash):
    return hmac.new(key, row_hash.encode('ascii'), hashlib.sha256).hexdigest()


def _parse(raw):
    """Ligne brute -> (ligne sans hash ni mac, hash annoncé, mac ou None)."""
    row = json.loads(raw)
    claimed = row.pop('hash')
    return row, claimed, row.pop('mac', None)


def _short(text, n=300):
    text = str(text)
    return text if len(text) <= n else text[:n] + '...'


# ================= Bas niveau : lecture de la fin, verrou, index =================
def _sync(f):
    f.flush()
    if FSYNC:
        os.fsync(f.fileno())


def _last_line(path):
    """Dernière ligne non vide d'un fichier, lue depuis la fin (coût constant)."""
    size = os.path.getsize(path)
    if size == 0:
        return None
    with open(path, 'rb') as f:
        f.seek(size - 1)
        if f.read(1) != b'\n':
            raise AuditError('Audit log tail is incomplete (interrupted write?); run: python src/audit.py --repair')
        pos, data = size, b''
        while pos > 0:
            step = min(4096, pos)
            pos -= step
            f.seek(pos)
            data = f.read(step) + data
            body = data.rstrip(b'\r\n')
            if b'\n' in body:
                return body.rsplit(b'\n', 1)[1].rstrip(b'\r')
        return data.strip()


def _tail_state(path):
    """(hash de tête, nombre d'événements) en ne lisant que la dernière ligne, dont le hash est contrôlé."""
    if not os.path.exists(path) or os.path.getsize(path) == 0:
        return GENESIS, 0
    line = _last_line(path)
    try:
        row, claimed, mac = _parse(line)
        if digest(row) != claimed:
            raise ValueError
        key = _hmac_key()
        if key and not hmac.compare_digest(str(mac or ''), _mac(key, claimed)):
            raise ValueError
        return claimed, row['sequence']
    except _PARSE_ERRORS:
        raise AuditError('Audit log tail is invalid; run --verify') from None


@contextlib.contextmanager
def _locked(path, timeout=10.0):
    """Verrou d'écriture portable. Un verrou de plus de 30 s est repris par renommage ATOMIQUE (un seul candidat
    gagne). Le verrou porte un jeton : on ne supprime que son propre verrou, et append() vérifie qu'il n'a pas
    été repris avant d'écrire. Sous Windows, un verrou détenu par un process vivant ne peut pas être repris."""
    lock = str(path) + '.lock'
    token = f'{os.getpid()}-{uuid.uuid4().hex}'
    Path(lock).parent.mkdir(parents=True, exist_ok=True)
    deadline = time.monotonic() + timeout
    while True:
        try:
            fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            break
        except FileExistsError:
            try:
                if time.time() - os.path.getmtime(lock) > LOCK_STALE_SECONDS:
                    grave = f'{lock}.stale-{token}'
                    os.rename(lock, grave)  # atomique : si un autre candidat a gagné, on obtient FileNotFoundError
                    with contextlib.suppress(OSError):
                        os.unlink(grave)
                    continue
            except OSError:
                pass  # déjà repris par un autre, ou (Windows) verrou encore détenu par un process vivant
            if time.monotonic() > deadline:
                raise AuditLockError(f'Audit log locked ({lock}); delete the .lock file if no process is writing')
            time.sleep(0.01)
    os.write(fd, token.encode())

    def still_mine():
        try:
            return Path(lock).read_text() == token
        except OSError:
            return False

    try:
        yield still_mine
    finally:
        mine = still_mine()
        os.close(fd)
        if mine:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(lock)


def _idx_path(path):
    return str(path) + '.idx'


def _idx_last_seq(path):
    idx = _idx_path(path)
    if not os.path.exists(idx) or os.path.getsize(idx) == 0:
        return 0
    try:
        return json.loads(_last_line(idx))['s']
    except (AuditError,) + _PARSE_ERRORS:
        return -1


def _rebuild_index(path):
    """Reconstruit l'index depuis le journal (à appeler sous verrou). Coût linéaire, rare."""
    idx, tmp = _idx_path(path), _idx_path(path) + '.tmp'
    offset = 0
    with open(path, 'rb') as f, open(tmp, 'wb') as g:
        for raw in f:
            line = raw.rstrip(b'\r\n')
            if line.strip():
                try:
                    row = json.loads(line)
                    entry = {'s': row['sequence'], 'c': row['event'].get('claim_id'), 'o': offset}
                except _PARSE_ERRORS:
                    raise AuditError('Cannot index a corrupted audit log; run --verify') from None
                g.write((json.dumps(entry) + '\n').encode())
            offset += len(raw)
        _sync(g)
    os.replace(tmp, idx)


def _ensure_index(path, log_count):
    """Index cohérent avec le journal (dernier numéro), sinon reconstruit (à appeler sous verrou)."""
    idx = _idx_path(path)
    if log_count == 0:
        if os.path.exists(idx):
            os.unlink(idx)
    elif _idx_last_seq(path) != log_count:
        _rebuild_index(path)


# ================= Vérification =================
def load_anchors(path):
    """Lit un fichier d'ancres : chaque ligne se termine par N:HASH. Renvoie [(N, HASH), ...]."""
    anchors = []
    for line in Path(path).read_text(encoding='utf-8').splitlines():
        line = line.strip()
        if line and not line.startswith('#'):
            n, h = line.split()[-1].split(':', 1)
            anchors.append((int(n), h))
    return anchors


def _verify_lines(lines, expect=None):
    expected = dict(expect or [])
    key = _hmac_key()
    previous, count = GENESIS, 0
    for raw in lines:
        raw = raw.rstrip(b'\r\n')
        if not raw.strip():
            continue
        n = count + 1
        try:
            row, claimed, mac = _parse(raw)
            seq_ok = row.get('sequence') == n
            chain_ok = row['previous_hash'] == previous and digest(row) == claimed
        except _PARSE_ERRORS:
            raise AuditError(f'Audit chain invalid at event {n}') from None
        if not seq_ok:
            raise AuditError(f'Audit sequence broken at event {n}')
        if not chain_ok:
            raise AuditError(f'Audit chain invalid at event {n}')
        if key and not hmac.compare_digest(str(mac or ''), _mac(key, claimed)):
            raise AuditError(f'HMAC missing or invalid at event {n}: line not written with the audit key')
        previous, count = claimed, n
        if n in expected and expected[n] != claimed:
            raise AuditError(f'Anchor mismatch at event {n}: log replaced or rewritten')
    if expected and count < max(expected):
        raise AuditError(f'Log has {count} events but an anchor covers {max(expected)}: log truncated')
    return previous, count


def verify(path=None, expect=None):
    """Vérifie toute la chaîne. Raise AuditError (ValueError) sur modification, rupture, séquence non continue.
    expect = ancres [(N, HASH)] : le hash de l'événement N doit correspondre (troncature, remplacement complet).
    Si CLAIMGUARD_AUDIT_HMAC_KEY est défini, chaque ligne doit aussi porter un HMAC valide."""
    path = path or DEFAULT_LOG
    if not Path(path).exists():
        return _verify_lines([], expect)
    with open(path, 'rb') as f:
        return _verify_lines(f, expect)


def _scan(obj, where='event'):
    if isinstance(obj, dict):
        for k, v in obj.items():
            if SECRET_KEY_RE.search(str(k)):
                raise AuditError(f'Refusing to log a secret-like field: {where}.{k}')
            _scan(v, f'{where}.{k}')
    elif isinstance(obj, (list, tuple)):
        for i, v in enumerate(obj):
            _scan(v, f'{where}[{i}]')
    elif isinstance(obj, str):
        if len(obj) > MAX_STRING:
            raise AuditError(f'Refusing a very long text in {where} ({len(obj)} chars): never log claim content')
        if SECRET_VALUE_RE.search(obj):
            raise AuditError(f'Refusing a secret-like value in {where}')


def validate_event(event):
    if not isinstance(event, dict):
        raise AuditError('Invalid event')
    _scan(event)
    etype = event.get('type')
    if etype is None:  # événement de revue humaine (format historique)
        if event.get('action') not in REVIEW_ACTIONS or not event.get('actor') \
                or not event.get('claim_id') or not event.get('rule_id'):
            raise AuditError('Invalid review event')
        if not str(event.get('reason', '')).strip():
            raise AuditError('Review reason is required')
        bad = FORBIDDEN_REVIEW_KEYS & event.keys()
        if bad:
            raise AuditError(f'A review decision cannot carry a rewritten status: {sorted(bad)}')
        if event.get('bound') is True and not all(event.get(k) for k in ('run_id', 'finding_sha256', 'original_status')):
            raise AuditError('A bound decision needs run_id, finding_sha256 and original_status')
    elif etype in SYSTEM_EVENTS:
        missing = SYSTEM_EVENTS[etype] - event.keys()
        if missing:
            raise AuditError(f'{etype} missing fields: {sorted(missing)}')
    else:
        raise AuditError(f'Unknown event type: {etype}')


# ================= Écriture =================
def append(path, events):
    """Ajoute des événements (coût constant). Contrôle seulement la fin du journal ; --verify contrôle tout."""
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    events = list(events)
    for event in events:  # tout est validé avant la première écriture
        validate_event(event)
    key = _hmac_key()
    with _locked(out) as still_mine:
        previous, count = _tail_state(out)
        _ensure_index(out, count)
        start = offset = out.stat().st_size if out.exists() else 0
        log_bytes, idx_bytes = [], []
        for event in events:
            row = {'sequence': count + 1, 'recorded_at': datetime.now(timezone.utc).isoformat(),
                   'previous_hash': previous, 'event': event}
            previous = digest(row)
            line = {**row, 'hash': previous}
            if key:
                line['mac'] = _mac(key, previous)
            data = (json.dumps(line, ensure_ascii=False) + '\n').encode('utf-8')
            idx_bytes.append((json.dumps({'s': count + 1, 'c': event.get('claim_id'), 'o': offset}) + '\n').encode())
            log_bytes.append(data)
            offset += len(data)
            count += 1
        if not still_mine():  # le verrou a été repris pendant un traitement trop long : on n'écrit rien
            raise AuditLockError('Audit lock lost to another writer; nothing was written, retry')
        with open(out, 'ab') as f:  # 1) le journal d'abord
            f.write(b''.join(log_bytes))
            _sync(f)
        if os.path.getsize(out) != offset:
            raise AuditError('Concurrent write detected while appending; run --verify (and --repair if needed)')
        with open(_idx_path(out), 'ab') as f:  # 2) puis l'index (se répare seul s'il est en retard)
            f.write(b''.join(idx_bytes))
            _sync(f)
    return previous, count


def repair(path=None):
    """Répare UNIQUEMENT une ligne finale incomplète (écriture interrompue) : les octets partiels sont mis en
    quarantaine dans <journal>.quarantine-<date>, le journal est tronqué à la dernière ligne complète, et un
    événement LOG_REPAIRED est ajouté. Refuse si la partie complète du journal n'est pas intègre."""
    path = path or DEFAULT_LOG
    p = Path(path)
    data = p.read_bytes()
    cut = data.rfind(b'\n') + 1
    tail = data[cut:]
    if not tail.strip():
        raise AuditError('Nothing to repair: the log ends with a complete line')
    try:
        _, count = _verify_lines(data[:cut].splitlines())
    except AuditError as exc:
        raise AuditError(f'Cannot repair: the complete part of the log is invalid ({exc}); this is not an interrupted write') from None
    with _locked(p):
        if p.stat().st_size != len(data):
            raise AuditError('The log changed during repair; retry')
        stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
        quarantine = Path(f'{path}.quarantine-{stamp}')
        quarantine.write_bytes(tail)
        with open(p, 'r+b') as f:
            f.truncate(cut)
            _sync(f)
    append(path, [{'type': 'LOG_REPAIRED', 'quarantined_sha256': sha256_bytes(tail),
                   'quarantined_bytes': len(tail), 'after_sequence': count}])
    return count, str(quarantine)


# ================= API pour les autres modules =================
def new_run_id():
    return 'RUN-' + uuid.uuid4().hex[:12]


def _raw_bytes(claim_raw):
    if isinstance(claim_raw, bytes):
        return claim_raw
    if isinstance(claim_raw, str):
        return claim_raw.encode('utf-8')
    return json.dumps(claim_raw, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')


def log_ingestion_error(source, error, log=None):
    """Ligne/fichier rejeté à l'ingestion. error = nom de l'erreur, pas de contenu du claim."""
    append(log or DEFAULT_LOG, [{'type': 'INGESTION_ERROR', 'source': str(source), 'error': _short(error)}])


def log_file(path, role='claims_input', log=None):
    """Un fichier qui entre dans le système (claims, règles, upload...) : nom, taille, SHA-256."""
    p = Path(path)
    append(log or DEFAULT_LOG, [{'type': 'FILE_RECEIVED', 'file_role': role, 'file_name': p.name,
                                 'size_bytes': p.stat().st_size, 'sha256': sha256_bytes(p.read_bytes())}])


def run_started(claim_id, claim_raw, rule_versions, previous_run=None, log=None):
    """À appeler juste avant d'évaluer un claim. Renvoie (run_id, input_hash).
    claim_raw : idéalement les OCTETS ORIGINAUX de la ligne JSONL (sinon str ou dict, hash moins strict).
    rule_versions : dict, idéalement {'ruleset': ruleset_fingerprint('rules'), 'engine_version': '...'}.
    previous_run=(run_id, input_hash) si c'est un recheck après correction."""
    run_id, input_hash = new_run_id(), sha256_bytes(_raw_bytes(claim_raw))
    events = []
    if previous_run:
        events.append({'type': 'CORRECTION_CREATED', 'claim_id': claim_id, 'previous_run_id': previous_run[0],
                       'previous_input_hash': previous_run[1], 'new_input_hash': input_hash})
    events.append({'type': 'RUN_STARTED', 'run_id': run_id, 'claim_id': claim_id,
                   'input_hash': input_hash, 'rule_versions': rule_versions})
    append(log or DEFAULT_LOG, events)
    return run_id, input_hash


def log_attachments(run_id, claim, log=None):
    """Une ligne par pièce jointe du claim. Le texte n'est PAS stocké : hash et longueur seulement."""
    events = []
    for a in claim.get('attachments') or []:
        text = str(a.get('text') or '')
        events.append({'type': 'ATTACHMENT_RECEIVED', 'run_id': run_id, 'claim_id': claim.get('claim_id'),
                       'attachment_id': a.get('attachment_id'), 'attachment_type': a.get('type'),
                       'text_sha256': sha256_bytes(text.encode('utf-8')), 'text_chars': len(text)})
    if events:
        append(log or DEFAULT_LOG, events)


def run_completed(run_id, claim_id, results, log=None):
    """À appeler après l'évaluation. results = les dicts du moteur (clés rule_id et status).
    Enregistre le statut ET le hash du constat de CHAQUE règle (passée ou non)."""
    counts, rule_results = {}, []
    for r in results:
        rule = r.get('rule_id', r.get('ruleId'))
        status = r.get('status', r.get('outcome'))
        if rule is None or status is None:
            raise AuditError("Each result needs 'rule_id' and 'status' to be audited")
        counts[status] = counts.get(status, 0) + 1
        entry = {'rule_id': rule, 'status': status, 'finding_sha256': finding_hash(r)}
        if r.get('rule_source'):
            entry['rule_source'] = r['rule_source']
        rule_results.append(entry)
    append(log or DEFAULT_LOG, [{'type': 'RUN_COMPLETED', 'run_id': run_id, 'claim_id': claim_id,
                                 'n_results': len(rule_results), 'status_counts': counts,
                                 'rule_results': rule_results, 'results_sha256': digest(list(results))}])


def run_failed(run_id, claim_id, error, log=None):
    append(log or DEFAULT_LOG, [{'type': 'RUN_FAILED', 'run_id': run_id, 'claim_id': claim_id, 'error': _short(error)}])


def log_tool_error(tool, error, run_id=None, claim_id=None, log=None):
    event = {'type': 'TOOL_ERROR', 'tool': str(tool), 'error': _short(error)}
    if run_id:
        event['run_id'] = run_id
    if claim_id:
        event['claim_id'] = claim_id
    append(log or DEFAULT_LOG, [event])


def log_model_call(run_id, claim_id, model_id, prompt_version, latency_ms, error=None, fallback=False, log=None, rule_id=None):
    """Après chaque appel modèle. error = nom de l'erreur ou None ; fallback=True si le template a été utilisé.
    Ne jamais y mettre le prompt, la réponse brute ni une clé."""
    event = {'type': 'MODEL_CALL', 'run_id': run_id, 'claim_id': claim_id, 'model_id': model_id,
             'prompt_version': prompt_version, 'latency_ms': latency_ms, 'error': error, 'fallback': bool(fallback)}
    if rule_id:
        event['rule_id'] = rule_id
    append(log or DEFAULT_LOG, [event])


def log_evaluation(split, predictions_path, metrics_path, commit=None, log=None):
    """Après evaluate.py : lie les métriques aux prédictions exactes (et au commit gelé)."""
    event = {'type': 'EVALUATION_COMPLETED', 'split': split, 'predictions_sha256': sha256_bytes(Path(predictions_path).read_bytes()),
             'metrics_sha256': sha256_bytes(Path(metrics_path).read_bytes())}
    if commit:
        event['commit'] = commit
    append(log or DEFAULT_LOG, [event])


def _recorded_finding(log, claim_id, rule_id):
    """(run_id, statut, hash du constat) de la dernière évaluation de ce claim qui contient cette règle."""
    found = None
    for row in trace(log, claim_id, verify_chain=False):
        e = row['event']
        if e.get('type') == 'RUN_COMPLETED':
            for rr in e['rule_results']:
                if rr['rule_id'] == rule_id:
                    found = (e['run_id'], rr['status'], rr['finding_sha256'])
    return found


def _bind_decision(log, event, finding=None):
    """Complète une décision avec run_id + hash du constat ENREGISTRÉ, après contrôle du statut d'origine."""
    rec = _recorded_finding(log, event['claim_id'], event['rule_id'])
    if rec is None:
        raise AuditError(f"No recorded run for {event['claim_id']}/{event['rule_id']}: a decision must refer to an evaluated finding "
                         "(run the engine with audit enabled, or import with --unbound to keep it unlinked)")
    run_id, status, fhash = rec
    if event.get('original_status') != status:
        raise AuditError(f"Decision on {event['claim_id']}/{event['rule_id']}: reviewer saw {event.get('original_status')} "
                         f'but the recorded run says {status}')
    if finding is not None and finding_hash(finding) != fhash:
        raise AuditError(f"Finding for {event['claim_id']}/{event['rule_id']} differs from the one recorded by the run")
    return {**event, 'run_id': run_id, 'finding_sha256': fhash, 'bound': True,
            'recheck_pending': event.get('action') == 'mark_corrected_for_recheck'}


def log_review(actor, action, claim_id, rule_id, reason, original_status, finding=None, log=None):
    """Décision humaine LIÉE au constat : le run et le hash du constat sont retrouvés dans le journal.
    Refusée si le claim n'a pas été évalué ou si original_status n'est pas celui du run. Ne change jamais un statut."""
    log = log or DEFAULT_LOG
    event = _bind_decision(log, {'action': action, 'actor': actor, 'claim_id': claim_id, 'rule_id': rule_id,
                                 'reason': reason, 'original_status': original_status,
                                 'created_at': datetime.now(timezone.utc).isoformat()}, finding)
    return append(log, [event])


def import_decisions(log, events_file, predictions_file=None, unbound=False):
    """Importe review_decisions.jsonl. Chaque décision est liée au run et au constat enregistrés ; le lot est
    refusé en entier si une décision est incohérente. predictions_file (optionnel) : le constat du fichier de
    prédictions doit correspondre à celui enregistré. unbound=True : garde les décisions sans lien (hérité)."""
    log = log or DEFAULT_LOG
    events = [json.loads(l) for l in Path(events_file).read_text(encoding='utf-8').splitlines() if l.strip()]
    if unbound:
        return append(log, events)
    verify(log)
    preds = {}
    if predictions_file:
        preds = {(r['claim_id'], r['rule_id']): r for r in
                 (json.loads(l) for l in Path(predictions_file).read_text(encoding='utf-8').splitlines() if l.strip())}
    out = []
    for i, ev in enumerate(events, 1):
        try:
            out.append(_bind_decision(log, ev, preds.get((ev.get('claim_id'), ev.get('rule_id')))))
        except AuditError as exc:
            raise AuditError(f'Decision {i}: {exc}') from None
    return append(log, out)


# Variantes "enveloppe" (optionnelles) : start/complete/failed en un seul appel
def audited_run(log_path, claim_raw, claim_id, rule_versions, run_fn, previous_run=None):
    run_id, input_hash = run_started(claim_id, claim_raw, rule_versions, previous_run, log_path)
    try:
        results = run_fn()
    except Exception as exc:
        run_failed(run_id, claim_id, type(exc).__name__, log_path)
        raise
    run_completed(run_id, claim_id, results, log_path)
    return run_id, input_hash, results


def audited_model_call(log_path, run_id, claim_id, model_id, prompt_version, call_fn, fallback_fn, rule_id=None):
    t0, error, fallback = time.perf_counter(), None, False
    try:
        out = call_fn()
    except Exception as exc:
        error, fallback, out = type(exc).__name__, True, fallback_fn()
    log_model_call(run_id, claim_id, model_id, prompt_version, round((time.perf_counter() - t0) * 1000),
                   error, fallback, log_path, rule_id)
    return out


# ================= Lecture / historique =================
class _StaleIndex(Exception):
    pass


def _claim_offsets(path, claim_id):
    """Positions des événements d'un claim. L'index est contrôlé au passage (numéros 1..N sans trou, N = taille
    du journal) ; sinon il est reconstruit depuis le journal."""
    _, log_count = _tail_state(path)
    if log_count == 0:
        return []
    for _ in range(2):
        out, n, ok = [], 0, os.path.exists(_idx_path(path))
        if ok:
            with open(_idx_path(path), 'rb') as f:
                for raw in f:
                    try:
                        e = json.loads(raw)
                        n += 1
                        if e['s'] != n:
                            ok = False
                            break
                        if e['c'] == claim_id:
                            out.append((e['s'], e['o']))
                    except _PARSE_ERRORS:
                        ok = False
                        break
            ok = ok and n == log_count
        if ok:
            return out
        with _locked(path):
            _rebuild_index(path)
    raise AuditError('Audit index inconsistent with log; run --verify')


def _read_rows(path, claim_id, offsets):
    rows = []
    with open(path, 'rb') as f:
        for seq, off in offsets:
            f.seek(off)
            raw = f.readline().rstrip(b'\r\n')
            try:
                row, claimed, mac = _parse(raw)
                good = row['sequence'] == seq and row['event'].get('claim_id') == claim_id and digest(row) == claimed
            except _PARSE_ERRORS:
                good = False
            if not good:
                raise _StaleIndex
            row['hash'] = claimed
            rows.append(row)
    return rows


def trace(path=None, claim_id=None, verify_chain=True):
    """Historique complet d'un claim. verify_chain=True : contrôle d'abord toute la chaîne (preuve complète).
    verify_chain=False : lecture rapide par index ; chaque ligne lue est contrôlée (hash), mais la complétude
    de la chaîne n'est pas prouvée."""
    path = path or DEFAULT_LOG
    if not Path(path).exists():
        return []
    if verify_chain:
        verify(path)
    for _ in range(2):
        try:
            return _read_rows(path, claim_id, _claim_offsets(path, claim_id))
        except _StaleIndex:
            with _locked(path):
                _rebuild_index(path)
    raise AuditError('Audit index inconsistent with log; run --verify')


def format_trace(rows):
    lines = []
    for r in rows:
        e = r['event']
        label = e.get('type') or e['action']
        detail = {k: v for k, v in e.items() if k not in ('type', 'action', 'claim_id')}
        if 'rule_results' in detail:  # lisible : seules les règles non PASS sont listées
            detail['rule_results'] = [f"{x['rule_id']}:{x['status']}" for x in detail['rule_results'] if x['status'] != 'PASS']
        lines.append(f"#{r['sequence']} {r['recorded_at']} {label} {json.dumps(detail, ensure_ascii=False)}")
    return '\n'.join(lines) or 'Aucun événement pour ce claim.'


def summary(path=None):
    """Comptes par type d'événement, par statut de règle et par décision humaine."""
    path = path or DEFAULT_LOG
    kinds, statuses, actions = {}, {}, {}
    n = 0
    with open(path, 'rb') as f:
        for raw in f:
            if not raw.strip():
                continue
            e = json.loads(raw)['event']
            n += 1
            label = e.get('type') or 'REVIEW_DECISION'
            kinds[label] = kinds.get(label, 0) + 1
            for rr in e.get('rule_results', []):
                statuses[rr['status']] = statuses.get(rr['status'], 0) + 1
            if label == 'REVIEW_DECISION':
                actions[e['action']] = actions.get(e['action'], 0) + 1
    return {'events': n, 'by_type': kinds, 'rule_results_by_status': statuses, 'human_decisions': actions}


def anchor_line(path=None):
    """Ancre à copier HORS du journal : 'N:HASH' (après vérification complète)."""
    head, n = verify(path)
    return f'{n}:{head}'


def save_anchor(log=None, anchor_file='audit_anchors.txt'):
    """Ajoute une ancre datée 'date<TAB>N:HASH' à anchor_file (à garder hors du dépôt / envoyer au mentor)."""
    line = f"{datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}\t{anchor_line(log)}"
    with open(anchor_file, 'a', encoding='utf-8', newline='\n') as f:
        f.write(line + '\n')
    return line


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--log', default=DEFAULT_LOG)
    p.add_argument('--events', help="fichier JSONL de décisions de revue à importer (liées au run et au constat)")
    p.add_argument('--predictions', help="avec --events : contrôler aussi que le constat du fichier correspond à celui du run")
    p.add_argument('--unbound', action='store_true', help="avec --events : importer SANS lien avec un run (format hérité, déconseillé)")
    p.add_argument('--add', metavar='JSON', help='ajouter UN événement (types autorisés : ' + ', '.join(sorted(CLI_ALLOWED_TYPES)) + ')')
    p.add_argument('--verify', action='store_true', help='vérifier toute la chaîne (par défaut si aucune autre action)')
    p.add_argument('--trace', metavar='CLAIM_ID', help="afficher tout l'historique d'un claim")
    p.add_argument('--fast', action='store_true', help='avec --trace : lecture par index (complétude non prouvée)')
    p.add_argument('--summary', action='store_true', help='comptes par type, statut de règle et décision')
    p.add_argument('--repair', action='store_true', help='mettre en quarantaine une ligne finale incomplète (écriture interrompue)')
    p.add_argument('--anchor', action='store_true', help="afficher l'ancre N:HASH à conserver hors du journal")
    p.add_argument('--anchor-file', metavar='FILE', help="avec --anchor : ajouter l'ancre datée à ce fichier")
    p.add_argument('--expect-file', metavar='FILE', help='avec --verify : exiger que toutes les ancres du fichier correspondent')
    a = p.parse_args()
    try:
        if a.repair:
            count, q = repair(a.log)
            print(f'Repaired: kept {count} events; partial bytes moved to {q}.')
            raise SystemExit(0)
        if a.summary:
            verify(a.log)
            print(json.dumps(summary(a.log), indent=1))
            raise SystemExit(0)
        if a.trace:
            if a.fast:
                print('(lecture rapide : lignes contrôlées une à une, complétude non prouvée ; sans --fast pour une preuve)', file=sys.stderr)
            print(format_trace(trace(a.log, a.trace, verify_chain=not a.fast)))
            raise SystemExit(0)
        if a.anchor:
            line = anchor_line(a.log)
            stamp = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
            if a.anchor_file:
                with open(a.anchor_file, 'a', encoding='utf-8', newline='\n') as f:
                    f.write(f'{stamp}\t{line}\n')
            print(f'{stamp}\t{line}')
            raise SystemExit(0)
        if a.add:
            event = json.loads(a.add)
            if event.get('type') not in CLI_ALLOWED_TYPES:
                raise AuditError(f'--add accepts only {sorted(CLI_ALLOWED_TYPES)}: results and decisions are written by the engine and the review import')
            h, n = append(a.log, [{**event, 'via': 'cli'}])
        elif a.events:
            if not (a.unbound or a.predictions):
                print('note: decisions are linked to the run recorded in the log; add --predictions to also check the findings file.', file=sys.stderr)
            h, n = import_decisions(a.log, a.events, a.predictions, a.unbound)
        else:
            h, n = verify(a.log, expect=load_anchors(a.expect_file) if a.expect_file else None)
    except AuditError as exc:
        print(f'AUDIT ERROR: {exc}', file=sys.stderr)
        raise SystemExit(2)
    mac = ' HMAC verified.' if _hmac_key() else ''
    print(f'Chain valid: {n} events; head {h}.{mac} Keep a trusted external copy of this head to detect whole-log replacement or truncation.')
