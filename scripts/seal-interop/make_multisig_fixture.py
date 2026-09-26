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

# A structural PDFium counterexample: both signed spans are empty, while
# the original revision EOF and form dictionaries remain parseable.
import re

def with_empty_signed_ranges(pdf, earlier_only=False):
    data = bytearray(pdf)
    matches = list(re.finditer(rb"/ByteRange\s*\[([^\]]+)\]", pdf))
    assert len(matches) == 2
    for match in matches[:1] if earlier_only else matches:
        a, b, c, d = map(int, match.group(1).split())
        replacement = f"0 0 {c+d} 0".encode().ljust(len(match.group(1)), b" ")
        assert len(replacement) == len(match.group(1))
        data[match.start(1):match.end(1)] = replacement
    assert len(data) == len(pdf)
    return bytes(data)

(out.parent / 'empty-ranges.pdf').write_bytes(with_empty_signed_ranges(second))
(out.parent / 'empty-earlier-range.pdf').write_bytes(
    with_empty_signed_ranges(second, earlier_only=True)
)

# A nonempty but misplaced gap excludes almost the entire earlier revision,
# rather than the first signature's /Contents interval.
misplaced = bytearray(second)
match = next(re.finditer(rb"/ByteRange\s*\[([^\]]+)\]", second))
a, b, c, d = map(int, match.group(1).split())
replacement = f"0 1 {c+d-1} 1".encode().ljust(len(match.group(1)), b" ")
assert len(replacement) == len(match.group(1))
misplaced[match.start(1):match.end(1)] = replacement
(out.parent / 'nonempty-earlier-range.pdf').write_bytes(misplaced)

# Form field order differs from signing chronology: the last enumerated
# field holds the earlier revision; the first enumerated field signs last.
from pyhanko.sign.fields import append_signature_field, SigFieldSpec
writer = IncrementalPdfFileWriter(BytesIO(source), strict=True)
append_signature_field(writer, SigFieldSpec(sig_field_name='ProbeSignature2'))
append_signature_field(writer, SigFieldSpec(sig_field_name='ProbeSignature1'))
unsigned = BytesIO()
writer.write(unsigned)
reverse_first = sign(unsigned.getvalue(), 'ProbeSignature1')
reverse_last = sign(reverse_first, 'ProbeSignature2')
(out.parent / 'reverse-fields.pdf').write_bytes(reverse_last)

# An earlier signed revision with an object-identity trap: escaped PDF name
# /Con#74ents denotes /Contents in signature object 6; the equal literal
# blob in unrelated object 7 must never count as the signature's gap.
hex_contents = re.search(rb'/Contents\s*(<[0-9A-Fa-f]+>)', second).group(1)
placeholder = b'[' + b' '.join([b'0'*10]*4) + b']'

def contents_binding_fixture(name, escaped, decoy):
    key = b'/Con#74ents' if escaped else b'/Contents'
    objects = [
        b'<< /Type /Catalog /Pages 2 0 R /AcroForm 4 0 R >>',
        b'<< /Type /Pages /Count 1 /Kids [3 0 R] >>',
        b'<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>',
        b'<< /Fields [5 0 R] /SigFlags 3 >>',
        b'<< /FT /Sig /T (ProbeSignature) /V 6 0 R >>',
        b'<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /adbe.pkcs7.detached '
        + key + b' ' + hex_contents + b' /ByteRange ' + placeholder + b' >>',
        b'<< /Contents ' + hex_contents + b' >>' if decoy else b'<< /Note (control) >>',
    ]
    data = bytearray(b'%PDF-1.7\n')
    offsets = [0]
    for index, obj in enumerate(objects, 1):
        offsets.append(len(data))
        data += f'{index} 0 obj\n'.encode() + obj + b'\nendobj\n'
    xref = len(data)
    data += b'xref\n0 8\n0000000000 65535 f \n'
    for offset in offsets[1:]:
        data += f'{offset:010d} 00000 n \n'.encode()
    data += f'trailer\n<< /Size 8 /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n'.encode()
    end = len(data)
    actual_b = data.index(hex_contents, offsets[6])
    gap_b = data.index(hex_contents, offsets[7]) if decoy else actual_b
    gap_c = gap_b + len(hex_contents)
    values = [0, gap_b, gap_c, end - gap_c]
    data = data.replace(placeholder, b'[' + b' '.join(f'{v:010d}'.encode() for v in values) + b']')
    assert len(data) == end
    info = len(data)
    data += b'8 0 obj\n<< /Producer (unsigned metadata revision) >>\nendobj\n'
    next_xref = len(data)
    data += (f'xref\n8 1\n{info:010d} 00000 n \ntrailer\n'
             f'<< /Size 9 /Root 1 0 R /Info 8 0 R /Prev {xref} >>\n'
             f'startxref\n{next_xref}\n%%EOF\n').encode()
    (out.parent / name).write_bytes(data)

contents_binding_fixture('normal-contents.pdf', False, False)
contents_binding_fixture('escaped-normal-contents.pdf', True, False)
contents_binding_fixture('literal-duplicate.pdf', False, True)
contents_binding_fixture('escaped-contents-decoy.pdf', True, True)

# A comment between the real key and value is legal whitespace; a second
# /Contents text in a comment is not a dictionary entry. Exercise both.
def comment_binding_fixture(name, comment_between, comment_decoy):
    real_key = (b'/Contents % a legal PDF comment before the value\n'
                if comment_between else b'/Contents ')
    sig_dict = (b'<< /Type /Sig /Filter /Adobe.PPKLite '
                b'/SubFilter /adbe.pkcs7.detached ' + real_key + hex_contents
                + b' /ByteRange ' + placeholder)
    if comment_decoy:
        sig_dict += b'\n% /Contents ' + hex_contents + b'\n'
    sig_dict += b' >>'
    objects = [
        b'<< /Type /Catalog /Pages 2 0 R /AcroForm 4 0 R >>',
        b'<< /Type /Pages /Count 1 /Kids [3 0 R] >>',
        b'<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>',
        b'<< /Fields [5 0 R] /SigFlags 3 >>',
        b'<< /FT /Sig /T (ProbeSignature) /V 6 0 R >>', sig_dict,
    ]
    data = bytearray(b'%PDF-1.7\n')
    offsets = [0]
    for index, obj in enumerate(objects, 1):
        offsets.append(len(data))
        data += f'{index} 0 obj\n'.encode() + obj + b'\nendobj\n'
    xref = len(data)
    data += b'xref\n0 7\n0000000000 65535 f \n'
    for offset in offsets[1:]:
        data += f'{offset:010d} 00000 n \n'.encode()
    data += f'trailer\n<< /Size 7 /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n'.encode()
    end = len(data)
    actual_b = data.index(hex_contents, offsets[6])
    gap_b = data.index(hex_contents, actual_b + len(hex_contents)) if comment_decoy else actual_b
    gap_c = gap_b + len(hex_contents)
    values = [0, gap_b, gap_c, end - gap_c]
    data = data.replace(placeholder, b'[' + b' '.join(f'{v:010d}'.encode() for v in values) + b']')
    assert len(data) == end
    info = len(data)
    data += b'7 0 obj\n<< /Producer (unsigned metadata revision) >>\nendobj\n'
    next_xref = len(data)
    data += (f'xref\n7 1\n{info:010d} 00000 n \ntrailer\n'
             f'<< /Size 8 /Root 1 0 R /Info 7 0 R /Prev {xref} >>\n'
             f'startxref\n{next_xref}\n%%EOF\n').encode()
    (out.parent / name).write_bytes(data)

comment_binding_fixture('normal-gap.pdf', False, False)
comment_binding_fixture('unhidden-comment-decoy.pdf', False, True)
comment_binding_fixture('comment-contents-decoy.pdf', True, True)

# Dictionary order is not semantic. Sign with /Reason before /Contents, then
# include the word endobj inside that *signed* literal string in one case.
from pyhanko.pdf_utils.generic import pdf_name
from pyhanko.sign.signers.pdf_byterange import SignatureObject
original_init = SignatureObject.__init__
def reason_first(self, *args, **kwargs):
    original_init(self, *args, **kwargs)
    reason = self.raw_get('/Reason')
    items = list(self.items())
    self.clear()
    self[pdf_name('/Reason')] = reason
    self.update(items)
SignatureObject.__init__ = reason_first
try:
    for filename, reason in (
        ('endobj-control.pdf', 'harmless signing reason'),
        ('endobj-in-reason.pdf', 'harmless endobj text'),
    ):
        with TemporaryDirectory() as td:
            key_path = Path(td) / 'probe.p12'
            key_path.write_bytes(p12)
            signer = signers.SimpleSigner.load_pkcs12(key_path, passphrase=b'probe-pass')
            writer = IncrementalPdfFileWriter(BytesIO(source), strict=True)
            output = BytesIO()
            PdfSigner(PdfSignatureMetadata(field_name='BoundarySignature', reason=reason),
                      signer=signer).sign_pdf(writer, output=output)
            (out.parent / filename).write_bytes(output.getvalue())
finally:
    SignatureObject.__init__ = original_init
