from copy import deepcopy
from hashlib import sha256

from app.certificate import tree
from app.vault.record import encode, volume


def stamped(client):
    run = client.post('/api/volumes',json={'sample':'dirty'}).json['run_id']
    imprint = client.post(f'/api/volumes/{run}/stamp').json['imprint']
    return run, imprint


def pickup(client, run, entry, org=None):
    headers = {} if org is None else {'Authorization':f'Bearer {tree.pickup_token(org)}'}
    return client.get(f'/api/volumes/{run}/permits/{entry}',headers=headers)


def test_branch_downloads_own_permit_without_foreign_pages(client):
    run, imprint = stamped(client)
    reply = pickup(client,run,'C02','00123')
    assert reply.status_code==200
    assert reply.headers['Content-Disposition'].startswith('attachment;')
    data = reply.json
    assert data['imprint']==imprint
    assert data['permit']['leaf']['entry']=='C02'
    assert data['permit']['leaf']['org']=='00123'
    assert data['permit']['leaf']['revoked'] is False
    body = reply.get_data(as_text=True)
    for foreign in ('C01','C03','C04','C05','C06','C07','C08','C10','C11','R01','DUP','34001','00007'):
        assert foreign not in body


def test_branch_verifies_permit_against_original_imprint(client):
    run, imprint = stamped(client)
    data = pickup(client,run,'C02','00123').json
    result = client.post('/api/permits/verify',json=data).json
    assert result['valid'] is True
    assert (result['root_ok'],result['imprint_ok'],result['revoked'])==(True,True,False)
    assert (result['entry'],result['org'],result['run'])==('C02','00123',run)


def test_altered_page_is_not_accepted_as_original(client):
    run, _ = stamped(client)
    data = pickup(client,run,'C02','00123').json
    forged = deepcopy(data)
    forged['permit']['leaf']['licensed'] += 1
    result = client.post('/api/permits/verify',json=forged).json
    assert result['valid'] is False and result['root_ok'] is False
    restruck = deepcopy(data)
    restruck['imprint'] = '0'*64
    result = client.post('/api/permits/verify',json=restruck).json
    assert result['valid'] is False and result['imprint_ok'] is False


def test_foreign_or_missing_token_rejected(client):
    run, _ = stamped(client)
    reply = pickup(client,run,'C02','00007')
    assert (reply.status_code,reply.json['error'])==(403,'PERMIT_FORBIDDEN')
    reply = pickup(client,run,'C02')
    assert (reply.status_code,reply.json['error'])==(401,'PERMIT_AUTH_REQUIRED')
    reply = pickup(client,run,'C99','00123')
    assert (reply.status_code,reply.json['error'])==(404,'PERMIT_UNKNOWN')


def test_revoked_page_is_not_a_valid_permit(client, desk):
    run, _ = stamped(client)
    reply = pickup(client,run,'C01','00123')
    assert (reply.status_code,reply.json['error'])==(410,'PERMIT_REVOKED')
    report = volume(desk.vault,run)
    leaves = tree.permit_leaves(report['stages']['pages'])
    index = next(i for i,leaf in enumerate(leaves) if leaf['entry']=='C01')
    head = client.get(f'/api/volumes/{run}/export').json['header']
    credential = {'run_id':run,'imprint':tree.seal(head),'header':head,
                  'permit':{'index':index,'leaf':leaves[index],'proof':tree.merkle_proof(leaves,index)}}
    result = client.post('/api/permits/verify',json=credential).json
    assert result['root_ok'] is True
    assert (result['revoked'],result['valid'])==(True,False)


def test_retry_keeps_issuance_basis(client):
    run, imprint = stamped(client)
    first = pickup(client,run,'C02','00123')
    assert first.get_data()==pickup(client,run,'C02','00123').get_data()
    assert first.json['imprint']==imprint
    restamp = client.post(f'/api/volumes/{run}/stamp').json
    assert restamp['reused'] is True and restamp['imprint']==imprint
    assert pickup(client,run,'C02','00123').get_data()==first.get_data()


def test_librarian_rechecks_whole_volume_with_original_seal(client):
    run, imprint = stamped(client)
    export = client.get(f'/api/volumes/{run}/export').json
    assert export['verified'] is True
    head = export['header']
    assert sha256(encode(head).encode()).hexdigest()==imprint
    document = export['document']
    leaves = tree.permit_leaves({'copies':document['requests'],'cancelled':document['cancellations']})
    assert head['permits']['root']==tree.merkle_root(leaves)
    assert head['permits']['count']==len(leaves)
    assert head['sections']==tree.section_digests(document)


def test_pickup_requires_stamp_and_known_run(client):
    run = client.post('/api/volumes',json={'sample':'dirty'}).json['run_id']
    reply = pickup(client,run,'C02','00123')
    assert (reply.status_code,reply.json['error'])==(409,'DRAFT_ONLY')
    reply = pickup(client,'unknown','C02','00123')
    assert (reply.status_code,reply.json['error'])==(404,'RUN_UNKNOWN')


def test_malformed_credential_rejected(client):
    reply = client.post('/api/permits/verify',json={'header':{}})
    assert (reply.status_code,reply.json['error'])==(422,'BAD_CREDENTIAL')
