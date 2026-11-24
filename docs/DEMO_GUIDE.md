# Hướng dẫn trình diễn

1. Từ thư mục dự án, chạy `.\.venv\Scripts\python.exe -m streamlit run app.py`. Mở địa chỉ localhost được Streamlit hiển thị.
2. Trên **Dashboard**, kiểm tra trạng thái CPU và thông tin về cửa sổ, lớp và ngưỡng QAE. Chỉ số xuất hiện sau khi có phiên phân tích hoặc cửa sổ replay.
3. Mở **PCAP Analysis**, chọn `NORMAL_30s_20260729_121618.pcap` từ mục demo rồi bấm **Analyze Traffic**. Xem label multiclass, kết quả binary, xác suất và số gói. Mở chi tiết một cửa sổ rồi tải CSV.
4. Chọn `SYN_HIGH_30s_20260729_111742.pcap`, `HTTP_LOW_30s_20260729_112227.pcap` hoặc `UDP_LOW_30s_20260729_120030.pcap`. Dùng filter Attack để xem timeline và so sánh f1–f6. Ground truth của demo đến từ manifest.
5. Mở **PCAP Replay**, chọn cùng capture hoặc upload rồi **Start**. Dùng **Pause**, **Resume**, **Stop** và thay tốc độ. Mốc thời gian chạy theo capture, và model chạy từng cửa sổ đầy đủ. Replay đọc capture offline và chỉ phát lại thông tin dự đoán trong giao diện.
6. Với capture độc lập, dùng file đã thu thập hợp lệ, dài từ 5 giây trở lên. Nếu có nhãn đáng tin, đối chiếu với kết quả. Bốn capture demo thuộc split test, tách khỏi train theo file. Báo cáo thử nghiệm trên dữ liệu độc lập khi có capture và nhãn tương ứng.
7. Mở **Benchmark Research**. Chọn dataset, task, nguồn bảng và metric. Hiển thị so sánh V2/V4 theo cùng fold. Giải thích thời gian nghiên cứu bao gồm công việc theo giao thức của từng phiên bản.
8. Mở **Model Evaluation**. Đọc confusion matrix xuất gốc, xem ROC/PR trên đúng tập có điểm và kiểm tra FP/FN. Chuyển qua anchor, độ sâu QAE, fusion và early stopping trong ablation.
9. Trình bày các giới hạn về lưu lượng tổng hợp, nhãn theo file, cửa sổ chưa đầy đủ, độ tổng quát trên mạng thực và phép mô phỏng lượng tử trên CPU.

Nếu thiếu demo, tải archive từ nguồn Zenodo rồi chạy `python -m scripts.prepare_demo data/01_synthetic_data.zip` từ môi trường dự án. Dùng `python -m scripts.verify_capture` để đối chiếu capture với export Colab. [Nguồn Zenodo](https://zenodo.org/records/21705919)
