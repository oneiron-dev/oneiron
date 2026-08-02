#!/usr/bin/env python3
"""
Generate DER fixtures for pkix-chain verify_tls_server integration tests.

Each test wants both a valid chain AND a leaf with (or without) a SAN
matching the target identity. pkix-identity's own fixtures are
self-signed, which is fine for that crate's pure-identity tests but
won't pass `verify_chain` here. So we generate a small two-cert chain:

  - root.der: self-signed CA (BasicConstraints CA=true, keyCertSign)
  - leaf-san-www-example.der: EE signed by root, SAN=DNS:www.example.com
  - leaf-no-san.der:          EE signed by root, no SAN extension

Validity 2000-01-01 to 2050-01-01. P-256 ECDSA throughout (matches
DefaultVerifier's P-256 support).

Oracle: pyca/cryptography. The Rust verifier under test never
participates in fixture creation.

Run from this directory:

    /home/mark/PROJECT/PKIX/pkix-difftest/python/.venv/bin/python3 gen.py

(or any other Python environment with cryptography installed).
"""

import datetime
import ipaddress
from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import NameOID, ObjectIdentifier
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

# RFC 8398 §3 id-on-SmtpUTF8Mailbox.
OID_SMTP_UTF8_MAILBOX = ObjectIdentifier("1.3.6.1.5.5.7.8.9")


def utf8_string_der(s: str) -> bytes:
    """DER-encode a UTF8String (tag 0x0c) carrying `s`.

    Short-form length only; tests never need >127-byte mailboxes.
    """
    data = s.encode("utf-8")
    if len(data) >= 128:
        raise NotImplementedError("UTF8String >127 bytes not used by fixtures")
    return bytes([0x0C, len(data)]) + data


def utf8_string_der_bytes(raw: bytes) -> bytes:
    """DER-encode a UTF8String with raw value bytes — caller chooses validity.

    Used to construct an `otherName(SmtpUTF8Mailbox)` SAN entry whose
    inner UTF8String value is intentionally not valid UTF-8 (RFC 8398
    §3 violation), so that the consumer-side parser surfaces the error.
    """
    if len(raw) >= 128:
        raise NotImplementedError("UTF8String >127 bytes not used by fixtures")
    return bytes([0x0C, len(raw)]) + raw

OUT = Path(__file__).parent
NOT_BEFORE = datetime.datetime(2000, 1, 1, tzinfo=datetime.timezone.utc)
NOT_AFTER = datetime.datetime(2050, 1, 1, tzinfo=datetime.timezone.utc)


def build_root():
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "pkix-chain test root")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(NOT_BEFORE)
        .not_valid_after(NOT_AFTER)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    return key, cert


def build_leaf(root_key, root_cert, *, sans, serial, eku=None, eku_critical=False,
               ocsp_no_check=False, key_usage=None):
    """Build a P-256 EE signed by `root_key`. Defaults EKU to serverAuth, non-critical.

    When ``ocsp_no_check=True``, attach the RFC 6960 §4.2.2.2.1 OCSPNoCheck
    extension (OID 1.3.6.1.5.5.7.48.1.5) to the leaf.

    When ``key_usage`` is provided, it MUST be an ``x509.KeyUsage`` instance;
    it replaces the default ``digitalSignature + keyEncipherment`` KU bits.
    Used by the TSA fixtures to comply with RFC 3161 §2.1 / §2.3 (TSA keys
    are used only for signing — the corresponding KU shape is
    ``digitalSignature`` and/or ``nonRepudiation``).
    """
    if eku is None:
        eku = [x509.ExtendedKeyUsageOID.SERVER_AUTH]
    if key_usage is None:
        key_usage = x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=True,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        )
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "pkix-chain test leaf")])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(root_cert.subject)
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(NOT_BEFORE)
        .not_valid_after(NOT_AFTER)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(key_usage, critical=True)
        .add_extension(
            x509.ExtendedKeyUsage(eku),
            critical=eku_critical,
        )
    )
    if sans is not None:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(sans),
            critical=False,
        )
    if ocsp_no_check:
        # RFC 6960 §4.2.2.2.1: presence of this extension on an OCSP
        # responder cert signals "do not check revocation status of this
        # cert" (avoids infinite OCSP loop). The extension is informational
        # and SHOULD be non-critical.
        builder = builder.add_extension(x509.OCSPNoCheck(), critical=False)
    return builder.sign(root_key, hashes.SHA256())


def write_der(name, cert):
    path = OUT / name
    path.write_bytes(cert.public_bytes(serialization.Encoding.DER))
    print(f"wrote {path.relative_to(OUT.parent.parent)}")


def main():
    root_key, root_cert = build_root()
    write_der("root.der", root_cert)

    leaf_san = build_leaf(
        root_key, root_cert,
        sans=[x509.DNSName("www.example.com")],
        serial=2,
    )
    write_der("leaf-san-www-example.der", leaf_san)

    leaf_no_san = build_leaf(
        root_key, root_cert,
        sans=None,
        serial=3,
    )
    write_der("leaf-no-san.der", leaf_no_san)

    # S/MIME signer leaf: SAN rfc822Name + EKU emailProtection.
    leaf_smime = build_leaf(
        root_key, root_cert,
        sans=[x509.RFC822Name("alice@example.com")],
        serial=4,
        eku=[x509.ExtendedKeyUsageOID.EMAIL_PROTECTION],
    )
    write_der("leaf-san-alice-example.der", leaf_smime)

    # Code-signing leaf: no SAN, EKU codeSigning.
    leaf_codesign = build_leaf(
        root_key, root_cert,
        sans=None,
        serial=5,
        eku=[x509.ExtendedKeyUsageOID.CODE_SIGNING],
    )
    write_der("leaf-codesigning.der", leaf_codesign)

    # Time Stamping Authority leaf: RFC 3161 §2.3 -- EKU MUST be critical
    # and contain ONLY id-kp-timeStamping. KU is restricted to
    # digitalSignature (and/or nonRepudiation) — a TSA key only signs
    # time-stamp tokens (RFC 3161 §2.1 #10). Matches OpenSSL's
    # `-purpose timestampsign` enforcement.
    tsa_key_usage = x509.KeyUsage(
        digital_signature=True,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=False,
        crl_sign=False,
        encipher_only=False,
        decipher_only=False,
    )
    leaf_tsa_ok = build_leaf(
        root_key, root_cert,
        sans=None,
        serial=6,
        eku=[x509.ExtendedKeyUsageOID.TIME_STAMPING],
        eku_critical=True,
        key_usage=tsa_key_usage,
    )
    write_der("leaf-timestamping.der", leaf_tsa_ok)

    # Negative: timeStamping EKU but NOT critical. KU is RFC 3161-compliant
    # so the criticality check is the lone reason for rejection.
    leaf_tsa_not_critical = build_leaf(
        root_key, root_cert,
        sans=None,
        serial=7,
        eku=[x509.ExtendedKeyUsageOID.TIME_STAMPING],
        eku_critical=False,
        key_usage=tsa_key_usage,
    )
    write_der("leaf-timestamping-not-critical.der", leaf_tsa_not_critical)

    # Negative: timeStamping EKU critical but NOT sole (extra EKU value).
    # KU is RFC 3161-compliant so the sole-EKU check is the lone reason
    # for rejection.
    leaf_tsa_not_sole = build_leaf(
        root_key, root_cert,
        sans=None,
        serial=8,
        eku=[
            x509.ExtendedKeyUsageOID.TIME_STAMPING,
            x509.ExtendedKeyUsageOID.CODE_SIGNING,
        ],
        eku_critical=True,
        key_usage=tsa_key_usage,
    )
    write_der("leaf-timestamping-not-sole.der", leaf_tsa_not_sole)

    # Negative: TSA-compliant EKU (critical + sole id-kp-timeStamping) but
    # KU = digitalSignature + keyEncipherment violates the RFC 3161 §2.1 #10
    # "key generated exclusively for this purpose" requirement
    # (and OpenSSL `-purpose timestampsign` enforces this as a hard reject).
    # Used by pkix-chain to verify the wrapper-side KU shape check.
    leaf_tsa_bad_ku = build_leaf(
        root_key, root_cert,
        sans=None,
        serial=11,
        eku=[x509.ExtendedKeyUsageOID.TIME_STAMPING],
        eku_critical=True,
        key_usage=x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=True,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        ),
    )
    write_der("leaf-timestamping-bad-ku.der", leaf_tsa_bad_ku)

    # OCSP responder leaf: RFC 6960 §4.2.2.2 -- delegated responder
    # cert MUST carry id-kp-OCSPSigning. The delegation (cert signed
    # by the same CA whose status it asserts) is enforced at the
    # wrapper layer by DN equality, not by an extension on the cert.
    leaf_ocsp_responder = build_leaf(
        root_key, root_cert,
        sans=None,
        serial=9,
        eku=[x509.ExtendedKeyUsageOID.OCSP_SIGNING],
    )
    write_der("leaf-ocsp-responder.der", leaf_ocsp_responder)

    # OCSP responder leaf + id-pkix-ocsp-nocheck (RFC 6960 §4.2.2.2.1).
    # Same chain shape as above; the wrapper must bypass revocation on
    # this leaf only.
    leaf_ocsp_responder_nocheck = build_leaf(
        root_key, root_cert,
        sans=None,
        serial=10,
        eku=[x509.ExtendedKeyUsageOID.OCSP_SIGNING],
        ocsp_no_check=True,
    )
    write_der("leaf-ocsp-responder-nocheck.der", leaf_ocsp_responder_nocheck)

    # Wrong-issuer root: a SECOND, structurally-valid CA cert with a
    # DIFFERENT subject DN than `root_cert`. The OCSP responder leaves
    # above are signed by `root_cert`; passing this cert as the `issuer`
    # argument to `verify_ocsp_responder` MUST fail the wrapper-level
    # delegation DN check (Error::OcspDelegation), even though the
    # chain itself validates fine against `root_cert` as anchor.
    other_root_key = ec.generate_private_key(ec.SECP256R1())
    other_root_name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "pkix-chain test root OTHER")
    ])
    other_root_cert = (
        x509.CertificateBuilder()
        .subject_name(other_root_name)
        .issuer_name(other_root_name)
        .public_key(other_root_key.public_key())
        .serial_number(101)
        .not_valid_before(NOT_BEFORE)
        .not_valid_after(NOT_AFTER)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(other_root_key, hashes.SHA256())
    )
    write_der("root-wrong-issuer.der", other_root_cert)

    # Twin-DN root: a SECOND CA cert with the SAME subject DN as
    # `root_cert` but a DIFFERENT key. The OCSP responder leaves above
    # are signed by `root_cert`; passing this twin as the `issuer`
    # argument to `verify_ocsp_responder` would PASS the DN-equality
    # gate (both sides spell "CN=pkix-chain test root") but MUST fail
    # the cryptographic delegation binding — RFC 6960 §4.2.2.2 requires
    # the responder be issued *directly* by the named CA, not merely
    # by a name-twin (PKIX-q9hv.3). Without the binding check, this
    # fixture would be silently accepted as a valid delegation, giving
    # an attacker who controls one of two cross-signed CAs with
    # colliding DNs a trust-misattribution primitive over revocation
    # status.
    twin_root_key = ec.generate_private_key(ec.SECP256R1())
    twin_root_name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "pkix-chain test root")
    ])
    twin_root_cert = (
        x509.CertificateBuilder()
        .subject_name(twin_root_name)
        .issuer_name(twin_root_name)
        .public_key(twin_root_key.public_key())
        .serial_number(102)
        .not_valid_before(NOT_BEFORE)
        .not_valid_after(NOT_AFTER)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(twin_root_key, hashes.SHA256())
    )
    write_der("root-twin-dn.der", twin_root_cert)

    # ------------------------------------------------------------------
    # PKIX-fmtv.23: curated RFC 8398 mailbox corpus.
    #
    # Each leaf below carries id-kp-emailProtection so it passes the
    # BasicSmimeProfile EKU check; the SAN payload varies to exercise
    # the verify_smime_signer / verify_smime_recipient binding rules.
    # ------------------------------------------------------------------
    EMAIL_PROT = [x509.ExtendedKeyUsageOID.EMAIL_PROTECTION]

    # rfc822Name = user@example.com — baseline positive / mismatch fixture.
    leaf_mailbox_user = build_leaf(
        root_key, root_cert,
        sans=[x509.RFC822Name("user@example.com")],
        serial=20,
        eku=EMAIL_PROT,
    )
    write_der("mailbox-rfc822-user-example.der", leaf_mailbox_user)

    # rfc822Name = user@EXAMPLE.com — domain mixed-case SAN; matching must
    # be ASCII case-insensitive on the domain part (RFC 5321 §2.4).
    leaf_mailbox_user_mixed_domain = build_leaf(
        root_key, root_cert,
        sans=[x509.RFC822Name("user@EXAMPLE.com")],
        serial=21,
        eku=EMAIL_PROT,
    )
    write_der("mailbox-rfc822-user-EXAMPLE.der", leaf_mailbox_user_mixed_domain)

    # rfc822Name = User@example.com — local-part case differs from the
    # target's local-part. Under strict RFC 5321 §2.4 the receiving
    # domain decides; the shipped pkix-identity matcher chooses STRICT
    # (byte-equal local-part). Documented in mailbox_corpus_baseline.md.
    leaf_mailbox_user_mixed_local = build_leaf(
        root_key, root_cert,
        sans=[x509.RFC822Name("User@example.com")],
        serial=22,
        eku=EMAIL_PROT,
    )
    write_der("mailbox-rfc822-User-example.der", leaf_mailbox_user_mixed_local)

    # otherName(SmtpUTF8Mailbox) = 用户@example.com (internationalized
    # local-part). RFC 8398 §3 form; must NOT also be expressed as
    # rfc822Name (which is IA5String / ASCII-only).
    leaf_mailbox_smtputf8_only = build_leaf(
        root_key, root_cert,
        sans=[x509.OtherName(
            OID_SMTP_UTF8_MAILBOX,
            utf8_string_der("用户@example.com"),
        )],
        serial=23,
        eku=EMAIL_PROT,
    )
    write_der("mailbox-smtputf8-only.der", leaf_mailbox_smtputf8_only)

    # Mixed SANs on one leaf: rfc822Name AND otherName(SmtpUTF8Mailbox)
    # naming two different mailboxes. Either target should bind (RFC
    # 8398 §3).
    leaf_mailbox_mixed = build_leaf(
        root_key, root_cert,
        sans=[
            x509.RFC822Name("user@example.com"),
            x509.OtherName(
                OID_SMTP_UTF8_MAILBOX,
                utf8_string_der("用户@example.com"),
            ),
        ],
        serial=24,
        eku=EMAIL_PROT,
    )
    write_der("mailbox-mixed.der", leaf_mailbox_mixed)

    # Multi-mailbox: three rfc822Name SANs on one leaf. Any one of them
    # should bind; a target outside the set should NOT bind.
    leaf_mailbox_multi = build_leaf(
        root_key, root_cert,
        sans=[
            x509.RFC822Name("alpha@example.com"),
            x509.RFC822Name("beta@example.com"),
            x509.RFC822Name("gamma@example.com"),
        ],
        serial=25,
        eku=EMAIL_PROT,
    )
    write_der("mailbox-multi-rfc822.der", leaf_mailbox_multi)

    # DNS-only SAN: SAN extension is present but carries no
    # rfc822Name/SmtpUTF8 entries. verify_mailbox returns NoMatchingSan;
    # BasicSmimeProfile additionally rejects at path validation with
    # MissingRfc822San.
    leaf_mailbox_dns_only = build_leaf(
        root_key, root_cert,
        sans=[x509.DNSName("example.com")],
        serial=26,
        eku=EMAIL_PROT,
    )
    write_der("mailbox-dns-only.der", leaf_mailbox_dns_only)

    # rfc822Name SAN value that has no '@' separator: structurally a
    # valid IA5String, semantically malformed as a mailbox. The
    # verify_mailbox matcher cannot split it; result is NoMatchingSan
    # (not a parse error — the SAN itself is well-formed).
    leaf_mailbox_malformed_local = build_leaf(
        root_key, root_cert,
        sans=[x509.RFC822Name("no-at-sign")],
        serial=27,
        eku=EMAIL_PROT,
    )
    write_der("mailbox-rfc822-malformed-no-at.der", leaf_mailbox_malformed_local)

    # otherName(SmtpUTF8Mailbox) whose inner UTF8String tag is correct
    # but whose value bytes are NOT valid UTF-8. RFC 8398 §3 violation;
    # decode_utf8_string_any returns IdentityError::MalformedSan via
    # Utf8StringRef::try_from, BUT san_entry_matches_mailbox swallows
    # the error and treats this SAN entry as a non-match. The leaf is
    # therefore expected to fail with NoMatchingSan (not MalformedSan).
    # This is the shipped behavior; documented in the baseline.
    malformed_utf8 = bytes([0xFF, 0xFE, 0xFD, 0xFC])
    leaf_mailbox_bad_utf8 = build_leaf(
        root_key, root_cert,
        sans=[x509.OtherName(
            OID_SMTP_UTF8_MAILBOX,
            utf8_string_der_bytes(malformed_utf8),
        )],
        serial=28,
        eku=EMAIL_PROT,
    )
    write_der("mailbox-smtputf8-bad-utf8.der", leaf_mailbox_bad_utf8)

    # ------------------------------------------------------------------
    # PKIX-fmtv.22: curated RFC 6125 hostname-binding corpus.
    #
    # Each leaf carries id-kp-serverAuth so it passes the BasicTlsProfile
    # EKU check; the SAN varies to exercise verify_tls_server binding
    # rules per RFC 6125 §6.4.
    # ------------------------------------------------------------------
    SERVER_AUTH = [x509.ExtendedKeyUsageOID.SERVER_AUTH]

    # RFC 6125 §6.4.1 exact match: SAN DNS=foo.example.com.
    leaf_host_exact = build_leaf(
        root_key, root_cert,
        sans=[x509.DNSName("foo.example.com")],
        serial=40,
        eku=SERVER_AUTH,
    )
    write_der("host-exact-foo.der", leaf_host_exact)

    # RFC 6125 §6.4.2 leftmost wildcard: SAN DNS=*.example.com.
    leaf_host_wildcard = build_leaf(
        root_key, root_cert,
        sans=[x509.DNSName("*.example.com")],
        serial=41,
        eku=SERVER_AUTH,
    )
    write_der("host-wildcard.der", leaf_host_wildcard)

    # RFC 6125 §7.2 partial-label wildcard rejection: SAN DNS=f*o.example.com.
    leaf_host_partial = build_leaf(
        root_key, root_cert,
        sans=[x509.DNSName("f*o.example.com")],
        serial=42,
        eku=SERVER_AUTH,
    )
    write_der("host-wildcard-partial-label.der", leaf_host_partial)

    # RFC 6125 §6.4.3 leftmost-only wildcard pinning: SAN DNS=foo.*.example.com.
    leaf_host_internal_wc = build_leaf(
        root_key, root_cert,
        sans=[x509.DNSName("foo.*.example.com")],
        serial=43,
        eku=SERVER_AUTH,
    )
    write_der("host-wildcard-internal.der", leaf_host_internal_wc)

    # Public-suffix-shape wildcard rejection: SAN DNS=*.com.
    # The shipped matcher refuses to honor a wildcard whose remainder
    # has no label separator (single-label suffix). pyca accepts this
    # SAN value at the DNSName level — the rejection is consumer-side.
    leaf_host_wildcard_tld = build_leaf(
        root_key, root_cert,
        sans=[x509.DNSName("*.com")],
        serial=44,
        eku=SERVER_AUTH,
    )
    write_der("host-wildcard-tld.der", leaf_host_wildcard_tld)

    # RFC 4343 case folding: SAN DNS=FOO.example.com (uppercase first
    # label). Matching must be case-insensitive.
    leaf_host_mixed_case = build_leaf(
        root_key, root_cert,
        sans=[x509.DNSName("FOO.example.com")],
        serial=45,
        eku=SERVER_AUTH,
    )
    write_der("host-mixed-case-san.der", leaf_host_mixed_case)

    # IDN A-label SAN (RFC 5891). Real-world CAs only put A-labels in
    # SANs. Caller-side U-label normalization is the ServerName::dns_name
    # constructor's job; this fixture proves the matcher's
    # A-label-to-A-label compare path works end-to-end.
    leaf_host_idn = build_leaf(
        root_key, root_cert,
        sans=[x509.DNSName("xn--bcher-kva.example")],
        serial=46,
        eku=SERVER_AUTH,
    )
    write_der("host-idn-alabel.der", leaf_host_idn)

    # IPv4 SAN (RFC 5280 §4.2.1.6).
    leaf_host_ipv4 = build_leaf(
        root_key, root_cert,
        sans=[x509.IPAddress(ipaddress.IPv4Address("192.0.2.5"))],
        serial=47,
        eku=SERVER_AUTH,
    )
    write_der("host-ipv4.der", leaf_host_ipv4)

    # IPv6 SAN.
    leaf_host_ipv6 = build_leaf(
        root_key, root_cert,
        sans=[x509.IPAddress(ipaddress.IPv6Address("2001:db8::1"))],
        serial=48,
        eku=SERVER_AUTH,
    )
    write_der("host-ipv6.der", leaf_host_ipv6)

    # CN-only cert (no SAN extension), CN=foo.example.com. RFC 6125 §6.4.4
    # deprecated CN-fallback; verify_dns_name refuses to consult the CN.
    # Re-uses the existing leaf-no-san.der at runtime — this fixture
    # exercises the same MissingSan path, no separate file needed.

    # Multi-SAN: positive case proving the iteration covers entries past
    # the first. SAN list: api.example.com, www.example.com, *.cdn.example.com.
    leaf_host_multi = build_leaf(
        root_key, root_cert,
        sans=[
            x509.DNSName("api.example.com"),
            x509.DNSName("www.example.com"),
            x509.DNSName("*.cdn.example.com"),
        ],
        serial=49,
        eku=SERVER_AUTH,
    )
    write_der("host-multi-san.der", leaf_host_multi)

    # ------------------------------------------------------------------
    # PKIX-fmtv.11.2 (client half): clientAuth-EKU fixtures.
    #
    # The verify_tls_client_dns + verify_tls_client_mailbox wrappers
    # test identity binding end-to-end. Tests run under Rfc5280Profile
    # (no EKU enforcement) for orthogonality with the BasicTls*
    # profiles, which assert serverAuth — production callers must
    # supply a profile asserting id-kp-clientAuth.
    # ------------------------------------------------------------------
    CLIENT_AUTH = [x509.ExtendedKeyUsageOID.CLIENT_AUTH]

    # clientAuth EKU + DNS SAN — for verify_tls_client_dns identity binding.
    leaf_client_dns = build_leaf(
        root_key, root_cert,
        sans=[x509.DNSName("client.example.com")],
        serial=60,
        eku=CLIENT_AUTH,
    )
    write_der("leaf-clientauth-dns.der", leaf_client_dns)

    # clientAuth EKU + rfc822Name SAN — for verify_tls_client_mailbox.
    leaf_client_mailbox = build_leaf(
        root_key, root_cert,
        sans=[x509.RFC822Name("client@example.com")],
        serial=61,
        eku=CLIENT_AUTH,
    )
    write_der("leaf-clientauth-mailbox.der", leaf_client_mailbox)

    # ------------------------------------------------------------------
    # PKIX-zkjb.7: AIA-fetched intermediate fixtures.
    #
    # Tests verify that `Verifier::verify_one` reassembles an incomplete
    # chain by following the leaf's `id-ad-caIssuers` AIA URI to fetch
    # the missing intermediate. Three fixtures:
    #   - intermediate.der: CA cert issued by root_key (BasicConstraints
    #     CA=true, KU=keyCertSign|cRLSign). Used as the cert returned by
    #     a mock AiaFetcher.
    #   - leaf-via-intermediate.der: EE signed by intermediate_key with
    #     SAN=DNS:www.example.com (same shape as leaf-san-www-example
    #     so test policy carries over) and AIA caIssuers URI
    #     "http://example.test/intermediate.der".
    #   - leaf-via-intermediate-no-aia.der: same as above but with the
    #     AIA extension omitted, for the negative test that asserts a
    #     graceful failure when there are no URIs to follow.
    # ------------------------------------------------------------------
    intermediate_key = ec.generate_private_key(ec.SECP256R1())
    intermediate_name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "pkix-chain test intermediate")
    ])
    intermediate_cert = (
        x509.CertificateBuilder()
        .subject_name(intermediate_name)
        .issuer_name(root_cert.subject)
        .public_key(intermediate_key.public_key())
        .serial_number(100)
        .not_valid_before(NOT_BEFORE)
        .not_valid_after(NOT_AFTER)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(root_key, hashes.SHA256())
    )
    write_der("intermediate.der", intermediate_cert)

    # Helper: build a leaf signed by the *intermediate* (not root). Mirrors
    # `build_leaf` but inlined here because `build_leaf` hard-codes
    # `root_key` as the signer.
    def build_leaf_via_intermediate(*, serial, ca_issuers_uri=None):
        key = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "pkix-chain test leaf via intermediate")
        ])
        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(intermediate_cert.subject)
            .public_key(key.public_key())
            .serial_number(serial)
            .not_valid_before(NOT_BEFORE)
            .not_valid_after(NOT_AFTER)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=True,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.SERVER_AUTH]),
                critical=False,
            )
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName("www.example.com")]),
                critical=False,
            )
        )
        if ca_issuers_uri is not None:
            builder = builder.add_extension(
                x509.AuthorityInformationAccess([
                    x509.AccessDescription(
                        access_method=x509.AuthorityInformationAccessOID.CA_ISSUERS,
                        access_location=x509.UniformResourceIdentifier(ca_issuers_uri),
                    ),
                ]),
                critical=False,
            )
        return builder.sign(intermediate_key, hashes.SHA256())

    leaf_via_intermediate = build_leaf_via_intermediate(
        serial=101,
        ca_issuers_uri="http://example.test/intermediate.der",
    )
    write_der("leaf-via-intermediate.der", leaf_via_intermediate)

    leaf_via_intermediate_no_aia = build_leaf_via_intermediate(
        serial=102,
        ca_issuers_uri=None,
    )
    write_der("leaf-via-intermediate-no-aia.der", leaf_via_intermediate_no_aia)


if __name__ == "__main__":
    main()
