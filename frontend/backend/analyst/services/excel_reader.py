import re
import zipfile
from pathlib import Path
from xml.etree import ElementTree


NS = {"m": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}


def _column_index(cell_ref: str) -> int:
    letters = re.match(r"[A-Z]+", cell_ref or "")
    if not letters:
        return 0
    value = 0
    for char in letters.group(0):
        value = value * 26 + (ord(char) - ord("A") + 1)
    return value - 1


def _shared_strings(archive: zipfile.ZipFile) -> list[str]:
    try:
        raw = archive.read("xl/sharedStrings.xml")
    except KeyError:
        return []
    root = ElementTree.fromstring(raw)
    values = []
    for item in root.findall("m:si", NS):
        texts = [node.text or "" for node in item.findall(".//m:t", NS)]
        values.append("".join(texts))
    return values


def _cell_value(cell, shared: list[str]) -> str:
    kind = cell.attrib.get("t")
    value_node = cell.find("m:v", NS)
    if value_node is None:
        inline = cell.find(".//m:t", NS)
        return inline.text if inline is not None and inline.text is not None else ""
    value = value_node.text or ""
    if kind == "s":
        try:
            return shared[int(value)]
        except (ValueError, IndexError):
            return value
    return value


def read_xlsx_rows(path: str | Path, sheet_index: int = 1) -> list[dict[str, str]]:
    path = Path(path)
    with zipfile.ZipFile(path) as archive:
        shared = _shared_strings(archive)
        sheet_name = f"xl/worksheets/sheet{sheet_index}.xml"
        root = ElementTree.fromstring(archive.read(sheet_name))
        rows = []
        for row in root.findall(".//m:sheetData/m:row", NS):
            values = {}
            for cell in row.findall("m:c", NS):
                values[_column_index(cell.attrib.get("r", ""))] = _cell_value(cell, shared).strip()
            if values:
                rows.append([values.get(index, "") for index in range(max(values) + 1)])
        if not rows:
            return []
        headers = [header.strip() for header in rows[0]]
        result = []
        for row in rows[1:]:
            item = {headers[index]: row[index].strip() if index < len(row) else "" for index in range(len(headers))}
            if any(item.values()):
                result.append(item)
        return result
