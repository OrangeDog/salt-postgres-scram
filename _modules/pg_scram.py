import base64
import hashlib
import hmac
import re
import secrets

# Need to bypass module loader in order to access private functions
from salt.modules import postgres


def __init__(opts):
    postgres.__grains__ = __grains__
    postgres.__opts__ = opts
    postgres.__salt__ = __salt__


def _kwargs(kwargs):
    """
    Used to forward common arguments for postgres module
    """
    return {k: v for k, v in kwargs.items() if k in (
        'user', 'host', 'port', 'maintenance_db', 'password', 'runas')}


def check(name, password, iterations=4096, **kwargs):
    """
    Check whether the role already has the password using SCRAM
    """
    user = postgres.role_get(name, return_password=True, **_kwargs(kwargs))
    match = re.match(r'^SCRAM-SHA-256\$\d+:([^\$]+?)\$', user['password'])
    if match:
        salt = base64.b64decode(match.group(1))
        expected = scram_sha_256(password, salt=salt, iterations=iterations)
        return user['password'] == expected
    else:
        return False


def update(name, password, iterations=4096, **kwargs):
    """
    Update the role with the password using SCRAM
    """
    encoded = scram_sha_256(password, iterations=iterations)
    sql = "ALTER ROLE %s WITH PASSWORD '%s'" % (name, encoded)
    ret = postgres._psql_prepare_and_run(['-c', sql], **_kwargs(kwargs))
    return ret['retcode'] == 0


def scram_sha_256(password, salt=None, iterations=4096):
    """
    Build a SCRAM-SHA-256 password verifier.
    Ported from https://doxygen.postgresql.org/scram-common_8c.html
    """
    if not isinstance(password, (bytes, bytearray)):
        password = password.encode('utf8')
    if salt is None:
        salt = secrets.token_bytes(16)

    salted_password = hashlib.pbkdf2_hmac('sha256', password, salt, iterations)
    stored_key = hmac.new(salted_password, b'Client Key', 'sha256').digest()
    stored_key = hashlib.sha256(stored_key).digest()
    server_key = hmac.new(salted_password, b'Server Key', 'sha256').digest()
    return 'SCRAM-SHA-256$%d:%s$%s:%s' % (
        iterations,
        base64.b64encode(salt).decode('ascii'),
        base64.b64encode(stored_key).decode('ascii'),
        base64.b64encode(server_key).decode('ascii')
    )
