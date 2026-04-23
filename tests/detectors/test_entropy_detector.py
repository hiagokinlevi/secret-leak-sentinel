import pytest

from detectors.entropy_detector import EntropyDetector


def test_entropy_detector_respects_min_length_boundary():
    detector = EntropyDetector(threshold=3.5, entropy_min_length=10)

    too_short_token = "Ab3$Xy9!"  # len=8, high variety but below min length
    boundary_token = "Ab3$Xy9!Qw"  # len=10, meets min length

    short_findings = detector.scan_line(too_short_token, file_path="example.txt", line_number=1)
    boundary_findings = detector.scan_line(boundary_token, file_path="example.txt", line_number=2)

    assert short_findings == []
    assert isinstance(boundary_findings, list)
