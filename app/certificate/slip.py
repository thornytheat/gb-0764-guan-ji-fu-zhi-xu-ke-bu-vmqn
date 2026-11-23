import hmac
import json

from app.certificate import tree
from app.problem import DeskError
from app.vault.record import encode, volume


def build(report, run):
    stages = report['stages']
    document = {'document':'馆际复制签发凭证','manifest':report['manifest'],
                'accounting':stages['balance'],'requests':stages['pages']['copies'],
                'revocations':stages['pages']['reversals'],'cancellations':stages['pages']['cancelled'],
                'isolated':stages['intake']['exceptions'],
                'suppressions':stages['intake']['duplicates'],'resolutions':stages['licenses']['verdicts']}
    leaves = tree.permit_leaves(stages['pages'])
    return tree.header(run,document,leaves), document


def stamp(vault, run):
    report = volume(vault,run)
    head, document = build(report,run)
    body = encode({'header':head,'document':document})
    with vault.session() as conn:
        new = conn.execute('INSERT INTO slips VALUES (?,?,?) ON CONFLICT(id) DO NOTHING',
                           (run,tree.seal(head),body)).rowcount
        signed = conn.execute('SELECT digest FROM slips WHERE id=?',(run,)).fetchone()[0]
    return {'run_id':run,'imprint':signed,'reused':not bool(new),'permits':head['permits']}


def certificate(vault, run):
    volume(vault,run)
    with vault.session() as conn:
        record = conn.execute('SELECT digest,body FROM slips WHERE id=?',(run,)).fetchone()
    if record is None:
        raise DeskError('DRAFT_ONLY',409)
    fingerprint, body = record
    try:
        payload = json.loads(body)
        head, document = payload['header'], payload['document']
        leaves = tree.permit_leaves({'copies':document['requests'],'cancelled':document['cancellations']})
        verified = (tree.seal(head)==fingerprint
                    and head['sections']==tree.section_digests(document)
                    and head['permits']['root']==tree.merkle_root(leaves)
                    and head['permits']['count']==len(leaves))
    except (KeyError,TypeError,ValueError):
        head = document = None
        verified = False
    return {'imprint':fingerprint,'verified':verified,'header':head,'document':document}


def permit(vault, run, entry, token):
    report = volume(vault,run)
    with vault.session() as conn:
        record = conn.execute('SELECT digest,body FROM slips WHERE id=?',(run,)).fetchone()
    if record is None:
        raise DeskError('DRAFT_ONLY',409)
    leaves = tree.permit_leaves(report['stages']['pages'])
    index = next((i for i,leaf in enumerate(leaves) if leaf['entry']==entry),None)
    if index is None:
        raise DeskError('PERMIT_UNKNOWN',404)
    leaf = leaves[index]
    if token is None:
        raise DeskError('PERMIT_AUTH_REQUIRED',401)
    if leaf['org'] is None or not hmac.compare_digest(token,tree.pickup_token(leaf['org'])):
        raise DeskError('PERMIT_FORBIDDEN',403)
    if leaf['revoked']:
        raise DeskError('PERMIT_REVOKED',410)
    head = json.loads(record[1])['header']
    return {'run_id':run,'imprint':record[0],'header':head,
            'permit':{'index':index,'leaf':leaf,'proof':tree.merkle_proof(leaves,index)}}


def check(credential):
    try:
        head = credential['header']
        leaf = credential['permit']['leaf']
        root = head['permits']['root']
        root_ok = bool(root) and tree.merkle_check(leaf,credential['permit']['proof'],root)
        imprint_ok = tree.seal(head)==credential['imprint']
        active = leaf['revoked'] is False
    except (KeyError,TypeError,ValueError):
        raise DeskError('BAD_CREDENTIAL')
    return {'valid':root_ok and imprint_ok and active,'root_ok':root_ok,'imprint_ok':imprint_ok,
            'revoked':not active,'run':head.get('run'),'entry':leaf.get('entry'),
            'org':leaf.get('org'),'licensed':leaf.get('licensed')}
