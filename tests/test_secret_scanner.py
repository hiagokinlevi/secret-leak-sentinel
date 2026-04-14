import tempfile
from scanners.secret_scanner import scan_file


def test_detects_aws_key():
    content = "aws_key = AKIA1234567890ABCDEF"

    with tempfile.NamedTemporaryFile("w+", delete=False) as f:
        f.write(content)
        f.flush()

        findings = scan_file(f.name)

    assert any("aws_access_key" in f["detector"] for f in findings)


def test_detects_high_entropy_token():
    token = "QWxhZGRpbjpPcGVuU2VzYW1lMTIzNDU2Nzg5MGFiY2RlZg"

    with tempfile.NamedTemporaryFile("w+", delete=False) as f:
        f.write(f"token={token}")
        f.flush()

        findings = scan_file(f.name)

    assert any(f["detector"] == "entropy" for f in findings)
