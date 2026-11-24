import argparse
import csv
import hashlib
import os
import shutil
from pathlib import Path
from tempfile import NamedTemporaryFile
from zipfile import ZipFile

from core.config import RESULTS, ROOT

ARCHIVE_MD5 = "08df8a1fde02afc3e239c777fe9e9181"


def prepare(archive, root, all_test=False):
    directory = RESULTS / "pcap"
    if all_test:
        with (directory / "split.csv").open(encoding="utf-8", newline="") as file:
            stems = {Path(row["file"]).stem for row in csv.DictReader(file) if row["split"] == "test"}
    else:
        stems = {path.stem.removesuffix("_prediction") for path in
                 (directory / "predictions").glob("*_prediction.csv")}
    with (directory / "manifest.csv").open(encoding="utf-8", newline="") as file:
        entries = [row for row in csv.DictReader(file) if Path(row["file"]).stem in stems]
    if not stems or len(entries) != len(stems):
        raise ValueError("Manifest và danh sách prediction không khớp")
    with archive.open("rb") as file:
        if hashlib.file_digest(file, "md5").hexdigest() != ARCHIVE_MD5:
            raise ValueError("MD5 archive không khớp Train_PCAP_Final")
    with ZipFile(archive) as zipped:
        for entry in entries:
            name, expected = entry["file"], entry["sha256"]
            target = (root / name).resolve()
            if not target.is_relative_to(root.resolve()):
                raise ValueError(f"Đường dẫn ngoài thư mục dữ liệu: {name}")
            if target.exists():
                with target.open("rb") as file:
                    if hashlib.file_digest(file, "sha256").hexdigest() != expected:
                        raise ValueError(f"File đã có và SHA-256 khác manifest: {name}")
                print(f"Đã có {name}", flush=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            temporary = NamedTemporaryFile(dir=target.parent, suffix=".tmp", delete=False)
            try:
                with temporary, zipped.open(name) as source:
                    shutil.copyfileobj(source, temporary, length=1024 * 1024)
                    temporary.seek(0)
                    if hashlib.file_digest(temporary, "sha256").hexdigest() != expected:
                        raise ValueError(f"SHA-256 không khớp manifest: {name}")
                os.link(temporary.name, target)
            finally:
                Path(temporary.name).unlink()
            print(f"Đã xác thực và giải nén {name}", flush=True)


def main():
    parser = argparse.ArgumentParser(description="Chuẩn bị capture demo từ ZIP Zenodo đã tải")
    parser.add_argument("archive", type=Path)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--all-test", action="store_true", help="Giải nén toàn bộ split test")
    args = parser.parse_args()
    try:
        prepare(args.archive, args.root, args.all_test)
    except (OSError, ValueError, KeyError) as exc:
        parser.exit(1, f"{exc}\n")


if __name__ == "__main__":
    main()
