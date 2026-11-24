# Kiểm tra workspace QAE-QNN

## Nguồn và artifact

- `notebooks/Train_PCAP_Final (1).ipynb` gồm 27 cell. Cell 8 mô tả bộ trích xuất, cell 11 lưu quy trình chuẩn hóa, cell 13 và 16 định nghĩa mạch, cell 19 đánh giá binary, cell 21 và 23 định nghĩa hợp đồng lưu và phục hồi mô hình.
- `notebooks/Train_Benchmark_Final (1).ipynb` gồm 48 cell. Phần A là V2 Lite, phần B là V4, phần C là ablation, phần D tổng hợp bảng. Các bảng binary dùng CIC-DDoS2019, CICIDS2017 và NSL-KDD, hai fold, seed 42. V4 dùng inner validation và dữ liệu train classifier ít hơn V2. Thời gian V4 có cả tìm cấu hình.
- `models/hybrid.pt` (2.392 byte) chứa PyTorch state dict. `scaler.joblib` (903 byte) chứa scaler đã fit. `qae_theta.npy` (200 byte) chứa góc QAE. `config.json` (463 byte) chứa cấu hình, `environment.json` (176 byte) chứa phiên bản Colab.
- `results/pcap/` chứa metrics, ảnh confusion, features, split, manifest SHA-256, bốn prediction CSV và các bảng thử nghiệm bổ sung. `results/benchmark/{baseline,improved,final}/` chứa kết quả theo fold, so sánh theo cặp và ablation.
- Khi bắt đầu, các thư mục ứng dụng chưa có source và workspace chưa có Git repository. Không có PCAP, PCAPNG, ZIP, dataset benchmark thô hoặc các NPZ dự đoán benchmark. Notebook xuất có chủ đích bỏ PCAP khỏi bundle. Bảng feature có 429 dòng từ 80 capture. Split test có 16 capture.
- Khi triển khai, ZIP dữ liệu tổng hợp được tải từ nguồn của notebook, xác nhận MD5 và giải nén 16 capture test vào `data/pcap/` sau khi đối chiếu SHA-256 với manifest. Các capture và ZIP nằm trong vùng dữ liệu local được Git bỏ qua. [Zenodo](https://zenodo.org/records/21705919)

## Luồng inference PCAP

Cửa sổ dài đúng 5 giây tính từ timestamp nhỏ nhất của capture. Gói tin tại mốc biên đi vào cửa sổ kế tiếp theo `int((t - start) / 5)`. Giữ các cửa sổ có gói và có chỉ số nhỏ hơn `int((max_t - min_t) / 5)`. Không xuất cửa sổ cuối chưa đầy đủ hoặc cửa sổ trống. Timestamp có thể đến không theo thứ tự. Bộ đọc dùng dpkt cho Ethernet IPv4 TCP/UDP thông thường và Scapy cho gói khác hoặc link type khác.

| Feature | Công thức theo thứ tự đầu vào |
| --- | --- |
| f1 | Tổng số gói trong cửa sổ, kể cả gói không có IPv4 |
| f2 | Số TCP có flags đúng bằng 2 chia cho max(số TCP có flags đúng bằng 18, 1) |
| f3 | Số địa chỉ nguồn IPv4 phân biệt |
| f4 | Số gói có payload TCP chứa chuỗi byte `GET` hoặc `POST` lớn nhất theo nguồn IPv4 |
| f5 | `-sum((count_src / f1) * log2(count_src / f1))` trên nguồn IPv4 theo thứ tự gặp |
| f6 | Số gói có UDP |

Kiểm tra feature hữu hạn. Áp dụng `log1p`, rồi `MinMaxScaler(clip=True).transform` với scaler đã fit. Nhãn thật và metadata không tham gia đầu vào.

QAE dùng 3 qubit, padding hai số 0, chuẩn hóa biên độ L2 và ánh xạ vector 0 sang trạng thái cơ sở 0. Một layer RX, RY, RZ trên từng qubit, sau đó CX (0,1), (1,2), (2,0). Đầu ra gồm xác suất trash q2=1 và bốn xác suất biên của q0,q1. Bộ phân loại nhận tensor float32 N×11 gồm sáu feature đã scale và năm feature QAE. VQNN dùng hai block Ry(xπ)/CX, rồi hai layer Ry/CX học được trên 3 qubit. Linear(13,4) nhận tám xác suất đo và năm feature QAE, rồi softmax theo lớp Normal, SYN, HTTP, UDP.

Nhãn multiclass dùng argmax, confidence là max softmax, điểm attack là 1−P(Normal). Cờ QAE dùng so sánh lớn hơn 0.0011343907644426237. Đánh giá binary của cell 19 dùng 1−P(Normal) ≥ 0,5. Hai quy tắc có vai trò riêng. Qiskit và PyTorch mô phỏng mạch trên CPU cổ điển.

## Môi trường và giới hạn

Colab ghi torch 2.14.1+cpu, sklearn 1.6.1, NumPy 2.4.6, pandas 2.2.3, Qiskit 2.6.2, Scapy 2.8.0, dpkt 1.9.8 và joblib 1.6.0. Phiên bản Python Colab chưa được ghi. Windows có CPython 3.11.9 x64, được tìm qua Python đang có trong PATH. Chỉ nạp scaler từ bundle tin cậy vì joblib dùng pickle.

Nhãn bộ PCAP được gán ở cấp capture trong môi trường kiểm soát. Phân phối lưu lượng mới, sự phụ thuộc giữa các cửa sổ, tính ổn định trên capture khác và tính tổng quát trên mạng thực cần đánh giá riêng. PCAPNG cần timestamp cho các gói tin để chia cửa sổ. Benchmark được tổng hợp từ các lần chạy khám phá đã có. Raw scores và nhãn theo mẫu benchmark cần thiết để tái tạo đường cong theo từng fold.

Kiểm tra lần lượt phiên bản Windows, checkpoint, dự đoán Colab trên cùng feature, bộ đọc PCAP, rồi Streamlit. Trạng thái và lệnh kiểm tra được ghi trong [IMPLEMENTATION_PROGRESS.md](IMPLEMENTATION_PROGRESS.md).
