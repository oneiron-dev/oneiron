"""Regenerate valid and CMS-corrupt document-timestamp fixtures with pinned pyHanko."""
from datetime import datetime, timedelta, timezone
from io import BytesIO
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from asn1crypto import x509 as ax509, keys
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.signers import PdfTimeStamper
from pyhanko.sign.timestamps import DummyTimeStamper
from pyhanko.sign.validation import ValidationContext

HERE = Path(__file__).resolve().parent
original = (HERE / 'fixtures/endobj-control.pdf').read_bytes()
now = datetime.now(timezone.utc)
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'timestamp test anchor')])
cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(days=365))
        .not_valid_after(now+timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]), critical=True)
        .sign(key, hashes.SHA256()))
cert_asn1 = ax509.Certificate.load(cert.public_bytes(serialization.Encoding.DER))
key_asn1 = keys.PrivateKeyInfo.load(key.private_bytes(
    serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
    serialization.NoEncryption()))
out = BytesIO()
PdfTimeStamper(DummyTimeStamper(cert_asn1, key_asn1), field_name='DocumentTimestamp').timestamp_pdf(
    IncrementalPdfFileWriter(BytesIO(original), strict=True), 'sha256',
    validation_context=ValidationContext(trust_roots=[cert_asn1], allow_fetching=False), output=out)
data = out.getvalue()
assert data[:len(original)] == original
(HERE / 'fixtures/signed-with-document-timestamp.pdf').write_bytes(data)
reader = PdfFileReader(BytesIO(data), strict=True)
timestamp = reader.embedded_signatures[-1]
a, b, c, d = map(int, timestamp.byte_range)
cms = bytearray(bytes.fromhex(data[b+1:c-1].decode('ascii')))
value = timestamp.signed_data['signer_infos'][0]['signature'].native
at = bytes(cms).find(value)
assert at >= 0 and bytes(cms).count(value) == 1
cms[at+len(value)-1] ^= 1
corrupt = data[:b+1] + bytes(cms).hex().encode('ascii') + data[c-1:]
assert len(corrupt) == len(data) and corrupt[:len(original)] == original
(HERE / 'fixtures/corrupt-document-timestamp.pdf').write_bytes(corrupt)
