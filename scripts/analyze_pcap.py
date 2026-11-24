import argparse
from pathlib import Path

from core.config import MODEL_DIR
from core.model_loader import ModelLoadError, load_model
from core.pcap_analysis import analyze_pcap


def main():
    parser = argparse.ArgumentParser(description="Phân tích capture bằng QAE+QNN trên CPU")
    parser.add_argument("capture", type=Path)
    parser.add_argument("--models", type=Path, default=MODEL_DIR)
    parser.add_argument("--csv", type=Path)
    args = parser.parse_args()
    try:
        analysis = analyze_pcap(args.capture, load_model(args.models))
        rows = analysis.results
        print(f"{analysis.capture.packets:,} packets | {analysis.capture.duration_s:.3f}s capture | {len(rows)} windows")
        print(rows["binary_prediction"].value_counts().to_string())
        print(f"{analysis.elapsed_s:.3f}s total | {rows.inference_ms.sum():.3f}ms inference")
        if args.csv:
            with args.csv.open("xb") as file:
                file.write(analysis.csv_bytes())
    except (ModelLoadError, OSError, ValueError) as exc:
        parser.exit(1, f"{exc}\n")


if __name__ == "__main__":
    main()
