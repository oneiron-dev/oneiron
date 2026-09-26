from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from io import BytesIO

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign import signers
from pyhanko.sign.signers.pdf_signer import PdfSigner, PdfSignatureMetadata

root = Path(__file__).resolve().parents[2]
source = (root / 'crates/oneiron-seal/tests/fixtures/pdf-input/interop_1page.pdf').read_bytes()
now = datetime.now(timezone.utc)
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Wave8 multi-revision probe')])
cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(days=365))
        .not_valid_after(now+timedelta(days=3650)).add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256()))
p12 = pkcs12.serialize_key_and_certificates(b'probe', key, cert, None,
        serialization.BestAvailableEncryption(b'probe-pass'))

def sign(data, field):
    with TemporaryDirectory() as td:
        p12_path = Path(td) / 'probe.p12'
        p12_path.write_bytes(p12)
        signer = signers.SimpleSigner.load_pkcs12(p12_path, passphrase=b'probe-pass')
        writer = IncrementalPdfFileWriter(BytesIO(data), strict=True)
        out = BytesIO()
        PdfSigner(PdfSignatureMetadata(field_name=field), signer=signer).sign_pdf(writer, output=out)
        return out.getvalue()

first = sign(source, 'ProbeSignature1')
second = sign(first, 'ProbeSignature2')
out = Path(__file__).resolve().parent / 'fixtures' / 'multi-signed.pdf'
out.write_bytes(second)
print(f'input={len(source)} first_signed={len(first)} multi_signed={len(second)} output={out}')

# Mutate only the second CMS signature value, preserving both signed byte ranges.
from pyhanko.pdf_utils.reader import PdfFileReader
reader = PdfFileReader(BytesIO(second), strict=True)
sigs = reader.embedded_signatures
assert len(sigs) == 2
sig = sigs[1]
a, b, c, d = map(int, sig.byte_range)
assert second[b:b+1] == b'<' and second[c-1:c] == b'>'
cms = bytearray(bytes.fromhex(second[b+1:c-1].decode('ascii')))
signature_value = sig.signed_data['signer_infos'][0]['signature'].native
at = bytes(cms).find(signature_value)
assert at >= 0 and bytes(cms).count(signature_value) == 1
cms[at+len(signature_value)-1] ^= 1
corrupt = second[:b+1] + bytes(cms).hex().encode('ascii') + second[c-1:]
assert len(corrupt) == len(second) and corrupt[:len(first)] == first
(out.parent / 'second-signature-corrupt.pdf').write_bytes(corrupt)
