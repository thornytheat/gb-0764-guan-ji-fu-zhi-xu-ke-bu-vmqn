from flask import Blueprint, current_app, jsonify, request

from app.certificate.slip import certificate, check, permit, stamp
from app.problem import DeskError
from app.source import read_request
from app.vault.record import deposit, index, volume
from app.workflow import steps

rights = Blueprint('rights',__name__)


def review(name):
    return steps(read_request(),name)[name]


@rights.route('/api/intake',methods=['GET','POST'])
def intake():
    return review('intake')


@rights.route('/api/registry',methods=['GET','POST'])
def registry():
    return review('registry')


@rights.route('/api/licenses',methods=['GET','POST'])
def choose():
    return review('licenses')


@rights.route('/api/pages',methods=['GET','POST'])
def pages():
    return review('pages')


@rights.route('/api/balance',methods=['GET','POST'])
def balance():
    return review('balance')


@rights.get('/api/volumes')
def volumes():
    return {'volumes':index(current_app.vault)}


@rights.post('/api/volumes')
def file():
    result = deposit(current_app.vault,read_request())
    return result,200 if result['reused'] else 201


@rights.get('/api/volumes/<run>')
def get_volume(run):
    return volume(current_app.vault,run)


@rights.post('/api/volumes/<run>/stamp')
def issue(run):
    return stamp(current_app.vault,run)


@rights.get('/api/volumes/<run>/export')
def download(run):
    result = jsonify(certificate(current_app.vault,run))
    result.headers['Content-Disposition'] = f'attachment; filename="license-{run}.json"'
    return result


@rights.get('/api/volumes/<run>/permits/<entry>')
def pickup(run, entry):
    token = None
    auth = request.headers.get('Authorization','')
    if auth.startswith('Bearer '):
        token = auth[7:].strip() or None
    result = jsonify(permit(current_app.vault,run,entry,token))
    result.headers['Content-Disposition'] = f'attachment; filename="permit-{run[:12]}-{entry}.json"'
    return result


@rights.post('/api/permits/verify')
def recheck():
    data = request.get_json(silent=True)
    if not isinstance(data,dict):
        raise DeskError('BAD_CREDENTIAL')
    return check(data)
