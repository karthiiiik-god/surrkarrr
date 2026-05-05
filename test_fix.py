import sys
sys.path.insert(0, '.')
from core.storage.database import Database
from core.storage.models import Vulnerability

db = Database('vulnerabilities.db')
vuln = Vulnerability.new(
    host='test-host',
    port=80,
    service='http',
    vulnerability_name='Test Vuln',
    description='Test description',
    cvss_score=5.0,
    severity='Medium',
    source_tool='nmap'
)
try:
    db.insert_vulnerability(vuln)
    print('SUCCESS: insert_vulnerability worked without IntegrityError')
except Exception as e:
    print(f'FAILED: {type(e).__name__}: {e}')
finally:
    db.conn.execute('DELETE FROM vulnerabilities WHERE vuln_id = ?', (vuln.vuln_id,))
    db.conn.commit()
    db.close()

