# Nhật ký triển khai

## 1. Kiểm tra workspace

- Đọc source hai notebook, cấu hình, môi trường và schema các bảng xuất. Tạo `docs/PROJECT_AUDIT.md`.
- `git status --short` và `git rev-parse --show-toplevel` xác nhận workspace ban đầu chưa có Git. `Get-FileHash models/*,notebooks/*` ghi nhận SHA-256 của bundle gốc. `Measure-Object` thống kê 81 file kết quả, tổng 1.038.436 byte.

## 2. Cấu trúc dự án

- Tạo các package `core` và `scripts`, giữ nguyên đường dẫn model, notebook và kết quả Colab. `python -m compileall -q core scripts` kiểm tra được cấu trúc import sau khi bổ sung các module.

## 3. Môi trường

- Tạo `.gitignore`, `requirements.txt` và `scripts/check_environment.py`.
- `python -m venv .venv` tạo môi trường CPython 3.11.9. `python -m pip install -r requirements.txt` cài các gói trong môi trường dự án. Lần thử kho PyTorch từ sandbox không thấy wheel, lần cấp mạng tải được wheel Windows CPU.
- `python -m pip check` xác nhận không có dependency hỏng. `python -m scripts.check_environment` xác nhận tám phiên bản khớp metadata Colab, mô phỏng Qiskit, tensor CPU và phục hồi model đều chạy được.

## 4. Inference

- Tạo `core/config.py`, `preprocessing.py`, `qae.py`, `hybrid_model.py`, `model_loader.py`, `inference.py` và script `verify_model`, `verify_inference`.
- `python -m compileall -q core scripts` kiểm tra cú pháp. `python -m scripts.verify_model` nạp state dict trên CPU với theta (2, 3), head weight (4, 13) và bias (4,).
- `python -m scripts.verify_inference` đối chiếu 71 dòng từ 5 CSV. Nhãn và cờ QAE giống từng dòng. Sai lệch tuyệt đối cực đại lần lượt là 2,79×10⁻⁸ cho confidence, 2,83×10⁻⁸ cho attack probability và 2,22×10⁻¹⁶ cho anomaly score. Các tập CSV có cửa sổ giao nhau.

## 5. PCAP

- Tạo `pcap_reader.py`, `feature_extractor.py`, `pcap_analysis.py`, `pcap_replay.py` và các CLI `analyze_pcap`, `prepare_demo`, `verify_capture`.
- Đọc hai lượt từ nguồn có thể seek để giữ quy tắc min/max và thứ tự tích lũy của notebook. Tải `01_synthetic_data.zip` bằng `curl.exe` từ nguồn notebook, kiểm tra MD5, rồi chạy `python -m scripts.prepare_demo data/01_synthetic_data.zip --all-test` để giải nén 16 file đúng SHA-256.
- `python -m scripts.verify_capture` khớp feature và prediction cho bốn capture demo, gồm HTTP có 164.480 gói trong file 119.868.368 byte.
- `python -m scripts.verify_capture --all-test` kết thúc với mã 0. Khớp SHA-256 của 16 capture và f1–f6 của toàn bộ 83 cửa sổ test, cùng 21 dòng prediction demo và 50 dòng novel đã xuất. Một số cửa sổ xuất hiện ở cả hai nhóm prediction. Ba capture HTTP lớn cần khoảng 66–74 giây mỗi file trong lần chạy kiểm chứng toàn bộ.
- `python -m scripts.analyze_pcap data/pcap/NORMAL_30s_20260729_121618.pcap --csv data/normal-results.csv` trả 5 cửa sổ Benign từ 1.276 gói và xuất CSV. Lệnh tương ứng cho `SYN_HIGH_30s_20260729_111742.pcap` trả 6 cửa sổ Attack từ 3.264 gói.

## 6. Streamlit

- Tạo `app.py`, `.streamlit/config.toml`, `pages/charts.py`, `pages/traffic.py`, `pages/research.py` và `core/evaluation.py`.
- `python -m streamlit run app.py --server.port 8501` khởi động trên localhost. Kiểm tra `/_stcore/health` trả `ok`.
- `python -m unittest discover -s tests -p test_app.py -v` chạy 3 kiểm thử AppTest gồm điều hướng sáu trang, phân tích capture Normal, CSV, Dashboard và các nút PCAP Replay.

## 7. Kiểm thử

- Tạo `tests/test_pipeline.py` và `tests/test_app.py`. Các ca kiểm tra checkpoint, bảo toàn feature và thứ tự, preprocessing, batch CPU, parsing PCAP/PCAPNG, input lỗi và rỗng, CSV, replay và điều hướng ứng dụng.
- Hai assertion ban đầu dùng nhầm capture dài đúng 5 giây làm fixture ngắn, và yêu cầu CSV giữ dtype float32. Đã sửa fixture và kiểm tra giá trị CSV theo kiểu số được trình đọc suy ra.
- `python -m unittest discover -s tests -v` chạy 10 test với bundle và capture local, tất cả đạt. `ruff check app.py core pages scripts tests` và `python -m compileall -q app.py core scripts pages tests` cũng đạt.

## 8. Git và tài liệu

- Tạo `README.md` và `docs/DEMO_GUIDE.md`. `git init -b main` tạo repository local. `git check-ignore` xác nhận ZIP, PCAP và .venv đều được bỏ qua. File lớn nhất trong danh sách có thể theo dõi là notebook benchmark 384.318 byte. `git remote -v` trả rỗng.
- `Get-FileHash models/*,notebooks/*` ở lần kiểm tra cuối cho SHA-256 giống lần audit đầu. Git chạy được trong workspace và cảnh báo quyền đọc đối với cấu hình ignore toàn cục của Windows.
- Giám sát phạm vi thử nghiệm qua split và manifest. Bộ kết quả benchmark có bảng và hình xuất từ notebook. Điểm và nhãn theo mẫu benchmark chưa có trong bundle. Dữ liệu có nhãn từ môi trường mạng độc lập chưa có trong workspace.
