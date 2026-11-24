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

## 9. Hoàn thiện và kiểm chứng Inference Engine

- `core/config.py`, `preprocessing.py`, `model_loader.py` và `inference.py` kiểm tra thứ tự feature, kích thước và miền scaler, kiểu góc QAE, ngưỡng và kích thước batch. Có thể lấy thêm bốn cột `prob_Normal`, `prob_SYN`, `prob_HTTP`, `prob_UDP` bằng `predict(..., include_probabilities=True)`. Các caller hiện tại tiếp tục nhận schema mặc định.
- `python -m scripts.check_environment` xác nhận tám phiên bản từ Colab khớp trên Windows với Python 3.11.9. `python -m scripts.verify_model` phục hồi scaler `float64` đã fit trên 259 dòng với `clip=True` và miền [0, 1], QAE với 9 góc `float64` và operator (8, 8) `complex128`, cùng checkpoint PyTorch CPU `float32` với các shape (2, 3), (4, 13) và (4,). Model chạy ở chế độ eval.
- `tests/test_inference.py` dựng hai mạch độc lập bằng Qiskit để đối chiếu QAE và bốn xác suất VQNN. Test kiểm tra `f1–f6 → log1p → scaler`, phần ghép sáu feature và năm giá trị QAE vào tensor `N×11 float32`, trọng số nạp từ checkpoint, lỗi artifact và dữ liệu đầu vào. Cờ QAE dùng ngưỡng `0.0011343907644426237` với toán tử `>`. Phân loại binary dùng `1 − P(Normal) ≥ 0.5`. Kiểm thử điểm QAE đúng bằng ngưỡng dùng điểm tính từ một cửa sổ test thật.
- `python -m scripts.verify_inference --threads 2 --repeats 20` chạy đủ 83 cửa sổ từ 16 capture. Accuracy, macro-F1, binary F1 và binary ROC-AUC đều bằng 1,0, khớp dòng QAE+QNN trong `metrics.csv`. Năm CSV tham chiếu có 71 dòng tương ứng 55 cửa sổ duy nhất. Nhãn và cờ QAE khớp hết. Sai lệch tuyệt đối lớn nhất là 2,79×10⁻⁸ cho confidence, 2,83×10⁻⁸ cho attack probability và 2,22×10⁻¹⁶ cho anomaly score. 28 cửa sổ còn lại có nhãn trong split test để tính metrics tổng hợp. Export Colab lưu confidence, anomaly score và attack probability ở những CSV có cột tương ứng. Bộ bốn xác suất được đối chiếu giữa các batch và với mạch tham chiếu Qiskit.
- `python -m unittest discover -s tests -v` đạt 16/16 test, gồm sáu test inference mới. `ruff check app.py core pages scripts tests` và `git diff --check` đạt. Kiểm tra Git xác nhận model, notebook, dữ liệu tham chiếu và giao diện giữ nguyên.
- `python -m scripts.verify_capture data/pcap/NORMAL_30s_20260729_121618.pcap data/pcap/SYN_HIGH_30s_20260729_111742.pcap` chạy lại end-to-end trên hai PCAP local. SHA-256, feature và prediction khớp export cho 5 cửa sổ Normal và 6 cửa sổ SYN.

### Độ trễ CPU trên 83 cửa sổ

Đo trên Windows với 2 luồng PyTorch, 2 lượt warm-up và 20 lượt đo mỗi cấu hình. Đầu vào đã đọc vào bộ nhớ và model đã nạp. Cột `predict()` gồm cả việc dựng bảng kết quả.

| Batch size | `predict()` p50 (ms) | `predict()` p95 (ms) | Tiền xử lý, QAE, QNN và softmax p50 (ms) | Sai lệch xác suất tối đa so với batch 512 |
| --- | ---: | ---: | ---: | ---: |
| 1 | 117,076 | 135,570 | 89,606 | 1,19×10⁻⁷ |
| 16 | 8,920 | 9,470 | 6,792 | 0 |
| 512 | 1,557 | 1,786 | 1,172 | 0 |

## 10. Kiểm chứng pipeline PCAP từ gói tin đến dự đoán

- Đọc lại cell 8, 9, 11 và 23 của `Train_PCAP_Final`. Cửa sổ 5 giây bắt đầu từ timestamp nhỏ nhất. Chỉ giữ cửa sổ đầy đủ có gói. Giữ bộ đếm f1–f6, thứ tự feature, `log1p`, scaler và model theo notebook. Chạy trực tiếp hai hàm `extract_pcap` và `extract_reference` của cell 8 trên ba capture Normal, SYN và UDP. Cả hai khớp chương trình ở 16 cửa sổ thuộc ba capture này.
- `core/pcap_reader.py` giữ hai lượt đọc tuần tự. Bộ đọc theo dõi vị trí theo byte và phân biệt hết file ở đúng biên với packet hoặc block bị lỗi. Sửa trường hợp block PCAPNG cuối hỏng bị bỏ qua như EOF. Phần đọc block được kiểm thử với Scapy 2.8.0 của môi trường dự án.
- `python -m scripts.verify_capture --all-test` chạy trực tiếp 16 capture gốc có SHA-256 khớp manifest. Kiểm tra header xác nhận cả 16 file có định dạng PCAPNG dù mang đuôi `.pcap`. Từ 524.235 gói, pipeline trích xuất đúng 83 cửa sổ theo `file` và `window_start_s`. Sai lệch tuyệt đối lớn nhất của f5 là `9.77e-14`. Sai lệch quan sát được của năm feature còn lại là 0. Đối chiếu qua scaler → QAE → Hybrid QNN khớp 71 dòng dự đoán tham chiếu.
- `scripts/analyze_pcap.py` in số gói, số gói thuộc cửa sổ giữ lại, thời lượng capture, phân bố nhãn binary và multiclass, cờ QAE cùng thời gian trích xuất và inference. `--csv` ghi theo từng cửa sổ vào file mới. Chạy CLI trên capture Normal cho 5 cửa sổ Benign, kiểm tra CSV và xác nhận lần gọi lại giữ nguyên file xuất cũ. File 0 byte, PCAP có header hợp lệ nhưng không có gói, file sai định dạng và capture bị cắt trả mã thoát 1 và không sinh CSV.
- `python -m scripts.analyze_pcap data/pcap/HTTP_LOW_30s_20260729_112227.pcap --csv data/pcap_analysis_http_120mb.csv` đọc file 119.868.368 byte với 164.480 gói. 137.828 gói thuộc năm cửa sổ giữ lại. CLI dự đoán 5 HTTP, cả 5 cửa sổ là Attack. Lần chạy này đo 20,540 giây trích xuất, 5,136 ms inference và 20,546 giây tổng. Phép đối chiếu dùng CSV Colab sau khi đã xuất kết quả thực tế.
- Chuyển cùng capture HTTP sang PCAP cổ điển nanosecond trong thư mục tạm, giữ packet và timestamp. CLI phân tích file 116.951.862 byte trong 18,544 giây. CSV tái tạo đúng mốc cửa sổ, f1–f6 và dự đoán Colab ở cả 5 cửa sổ.
- `python -m unittest discover -s tests -v` đạt 19/19 test. Ba test mới kiểm tra biên timestamp nanosecond, block PCAPNG cuối lỗi và CLI với CSV cùng mã thoát lỗi. `ruff check app.py core pages scripts tests` và `git diff --check` đạt.

## 11. Hoàn thiện giao diện SOC QAE-QNN IDS

- Thiết kế lại sáu trang `Dashboard`, `PCAP Analysis`, `PCAP Replay`, `Benchmark Research`, `Model Evaluation` và `About` theo hệ thống dark navy, cyan, green cho Benign và red cho Attack. `pages/ui.py` tập trung theme, page header, panel, pill và empty state; `pages/charts.py` dùng chung palette cho timeline, risk gauge và event table.
- Dashboard chỉ hiển thị metric sau khi có phiên phân tích thật. Trạng thái ban đầu nêu rõ chưa có session; không sinh mock data. Analysis và Replay tiếp tục gọi pipeline PCAP và inference hiện có. Các trang nghiên cứu chỉ đọc artifact đã export.
- Tham khảo bố cục SOC, information hierarchy và cách nhóm chức năng từ bốn repository do yêu cầu cung cấp. Không sao chép source code, asset, icon hay stylesheet, vì vậy không bổ sung thành phần bên thứ ba cần phân phối theo license.
- Khởi động bản build sạch bằng `python -m streamlit run app.py --server.port 8502 --server.headless true`. Kiểm tra thật bằng Microsoft Edge headless tại 1440x1000, 1024x900 và 480x900. Desktop/laptop giữ sidebar và bố cục hai cột; viewport 480 px tự thu sidebar, chuyển nội dung sang một cột và không tràn ngang.
- `python -m unittest discover -s tests -v` đạt 19/19 test, trong đó AppTest duyệt sáu trang, phân tích PCAP demo thật và kiểm tra replay controls. `ruff check app.py core pages scripts tests`, `python -m compileall -q app.py core pages scripts tests` và `git diff --check` đều đạt. Chỉ chuẩn hóa các log console trong `verify_inference.py` sang ASCII để full suite chạy ổn định trên Windows CP1252; không thay đổi tính toán inference.
