import os
from pathlib import Path

CATALOG = Path(__file__).resolve().parents[1] / 'sample_data'
LEDGER = os.environ.get('LICENSE_DB', 'var/licenses.sqlite')
STAMP_SECRET = os.environ.get('STAMP_SECRET', 'desk-dev-secret')
EDITION = 'rights-1.0'
