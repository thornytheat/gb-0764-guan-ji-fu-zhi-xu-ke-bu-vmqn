from hashlib import sha256
import hmac

from app.settings import STAMP_SECRET
from app.vault.record import encode

LEAF_DOMAIN = b'\x00permit-leaf:'
NODE_DOMAIN = b'\x01permit-node:'
HEADER_VERSION = 'permit-header-1'
LEAF_VERSION = 'permit-leaf-1'


def permit_leaf(row, cancelled):
    return {'entry':row['entry'],'org':row['org'],'received':row['received'],
            'license':row['license'],'pool':row['pool'],'requested':row['requested'],
            'licensed':row['licensed'],'granted':row['granted'],'revoked':row['entry'] in cancelled}


def permit_leaves(pages):
    cancelled = set(pages['cancelled'])
    return [permit_leaf(row,cancelled) for row in pages['copies']]


def leaf_digest(leaf):
    return sha256(LEAF_DOMAIN+encode(leaf).encode()).digest()


def node_digest(left, right):
    return sha256(NODE_DOMAIN+left+right).digest()


def pair_level(nodes):
    return [node_digest(nodes[i],nodes[i+1]) if i+1 < len(nodes) else nodes[i]
            for i in range(0,len(nodes),2)]


def merkle_root(leaves):
    nodes = [leaf_digest(leaf) for leaf in leaves]
    if not nodes:
        return None
    while len(nodes) > 1:
        nodes = pair_level(nodes)
    return nodes[0].hex()


def merkle_proof(leaves, index):
    nodes = [leaf_digest(leaf) for leaf in leaves]
    proof = []
    while len(nodes) > 1:
        if index%2 == 0:
            if index+1 < len(nodes):
                proof.append({'side':'right','hash':nodes[index+1].hex()})
        else:
            proof.append({'side':'left','hash':nodes[index-1].hex()})
        nodes = pair_level(nodes)
        index //= 2
    return proof


def merkle_check(leaf, proof, root):
    node = leaf_digest(leaf)
    for step in proof:
        sibling = bytes.fromhex(step['hash'])
        left,right = (node,sibling) if step['side']=='right' else (sibling,node)
        node = node_digest(left,right)
    return node.hex() == root


def section_digests(document):
    return {name:sha256(encode(document[name]).encode()).hexdigest() for name in sorted(document)}


def header(run, document, leaves):
    return {'document':'馆际复制签发凭证','version':HEADER_VERSION,'run':run,
            'sections':section_digests(document),
            'permits':{'tree':'merkle-sha256','leaf':LEAF_VERSION,'count':len(leaves),
                       'root':merkle_root(leaves)}}


def seal(head):
    return sha256(encode(head).encode()).hexdigest()


def pickup_token(org):
    return hmac.new(STAMP_SECRET.encode(),f'permit-pickup:{org}'.encode(),sha256).hexdigest()
