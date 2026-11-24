import argparse
from pathlib import Path

from core.config import MODEL_DIR
from core.model_loader import ModelLoadError, load_model
from core.pcap_analysis import analyze_pcap


def main():
    parser = argparse.ArgumentParser(description="Phân tích PCAP/PCAPNG bằng QAE+QNN trên CPU")
    parser.add_argument("capture", type=Path, help="Đường dẫn tới capture cần phân tích")
    parser.add_argument("--models", type=Path, default=MODEL_DIR)
    parser.add_argument("--csv", type=Path, help="Lưu kết quả từng cửa sổ vào file CSV mới")
    args = parser.parse_args()
    try:
        if args.csv and args.csv.exists():
            raise FileExistsError(f"File CSV đã tồn tại: {args.csv}")
        engine = load_model(args.models)
        analysis = analyze_pcap(args.capture, engine)
        rows = analysis.results
        if args.csv:
            with args.csv.open("x", encoding="utf-8", newline="") as file:
                rows.to_csv(file, index=False)
        capture = analysis.capture
        print(f"{args.capture} | {capture.duration_s:.3f}s capture | {capture.packets:,} packets")
        print(f"{len(rows)} cửa sổ × {engine.config.window}s | {rows.packet_count.sum():,} gói trong các cửa sổ")
        for label, output in (("Binary", rows.binary_prediction), ("Multiclass", rows.prediction)):
            counts = " | ".join(f"{name}={count}" for name, count in output.value_counts().items())
            print(f"{label}: {counts}")
        print(f"QAE alerts: {rows.qae_alert.sum()} | extraction: {analysis.extraction_s:.3f}s | "
              f"inference: {rows.inference_ms.sum():.3f}ms | total: {analysis.elapsed_s:.3f}s")
        if args.csv:
            print(f"CSV: {args.csv}")
    except (ModelLoadError, OSError, ValueError) as exc:
        parser.exit(1, f"{exc}\n")


if __name__ == "__main__":
    main()
