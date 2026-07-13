import csv
import hashlib
from dataclasses import dataclass
from pathlib import Path


MAX_UPLOAD_SIZE_BYTES = 100 * 1024 * 1024
SUPPORTED_ENCODINGS = ("utf-8-sig", "utf-8", "cp1252")
EXPECTED_DELIMITER = ","


@dataclass(frozen=True)
class CSVDetectionResult:
    encoding: str
    delimiter: str
    sha256: str
    size_bytes: int


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def detect_csv(path: Path) -> CSVDetectionResult:
    size_bytes = path.stat().st_size
    if size_bytes > MAX_UPLOAD_SIZE_BYTES:
        raise ValueError("Le fichier dépasse la limite MVP de 100 Mo.")

    raw_sample = path.read_bytes()[:64 * 1024]
    detected_encoding = None
    decoded_sample = ""
    for encoding in SUPPORTED_ENCODINGS:
        try:
            decoded_sample = raw_sample.decode(encoding)
        except UnicodeDecodeError:
            continue
        detected_encoding = encoding
        break

    if not detected_encoding:
        raise ValueError("Encodage non supporté. Encodages acceptés : UTF-8, UTF-8-BOM, Windows-1252.")

    try:
        dialect = csv.Sniffer().sniff(decoded_sample, delimiters=",;\t")
        delimiter = dialect.delimiter
    except csv.Error:
        delimiter = EXPECTED_DELIMITER

    if delimiter != EXPECTED_DELIMITER:
        raise ValueError("Séparateur non supporté pour le MVP. Le CSV doit utiliser la virgule.")

    return CSVDetectionResult(
        encoding=detected_encoding,
        delimiter=delimiter,
        sha256=file_sha256(path),
        size_bytes=size_bytes,
    )
