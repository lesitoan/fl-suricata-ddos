# TensorBoard cho train Local và FL

Viewer chạy trên Windows, trong Python venv riêng, chỉ bind `127.0.0.1:6006`. Không cần TensorFlow, không đổi thư viện/image train và không mở cổng ra LAN. Dashboard vẫn dùng Python stdlib như trước.

Tại root dự án, cài một lần (cần Internet/Python 3.10+):

```powershell
powershell -ExecutionPolicy Bypass -File .\tools\tensorboard\setup.ps1
```

Sau đó bấm **TensorBoard** ở khối Federated Learning trên dashboard. Nút tự mở viewer host nếu chưa chạy, hoặc dùng lại tiến trình đang phục vụ đúng thư mục log. Nút không bật Docker/node/FL và không chạy train. Nếu bị chặn popup, mở `http://127.0.0.1:6006/` sau khi tác vụ hoàn tất. Cổng 6006 bị một tiến trình khác chiếm thì báo lỗi, không dừng tiến trình đó.

Chạy trực tiếp bằng terminal nếu không dùng dashboard:

```powershell
powershell -ExecutionPolicy Bypass -File .\tools\tensorboard\start.ps1
```

Giữ terminal mở, Ctrl+C để dừng viewer/exporter. Khi mở bằng dashboard, viewer chạy nền, độc lập với dashboard; đóng tab không dừng nó. Muốn dừng tiến trình nền, kiểm `runtime/tensorboard/server.pid` và CommandLine phải trỏ đúng `tools/tensorboard/serve.py`, rồi mới dừng đúng PID. Không dừng node/FL để đóng viewer.

## Chọn đường biểu diễn

- **Scalars**, lọc Runs bằng `local`: lần train Local mới nhất của từng node A/B/C; trục **Step = epoch**.
- Lọc Runs bằng `federated`: lần FL mới nhất gồm `node-a`, `node-b`, `node-c`, `server`; trục **Step = vòng FL**.
- `train/loss`: loss khi node cập nhật cục bộ; sklearn training loss có sample weighting/regularization. `validation/loss` là binary log loss không weighting; không coi hai con số là cùng một objective.
- `validation/balanced_accuracy`, `recall_attack`, `precision_attack`, `f1_macro`, `false_positive_rate`: tỷ lệ 0–1. FPR/loss càng thấp càng tốt; recall/BA/F1 càng cao càng tốt, nhưng cần xem cùng nhau.
- Với **FL**, validation ở từng node là đánh giá **Global sau FedAvg**, không phải post-fit local update hoặc baseline Local. `server/validation/mean_node_balanced_accuracy` là trung bình bằng nhau của ba node; pooled loss cân theo số mẫu validation.
- `timing/train_seconds`, `timing/round_seconds`: giây. `communication/*`: số byte model/Flower object theo report hiện có, không phải packet/network traffic thực đo.

Đặt **Smoothing = 0** để xem điểm gốc, X-axis **Step** để đọc epoch/vòng. Không trộn đường local epoch với FL round thành cùng thang tiến độ. TensorBoard không tự xác nhận hội tụ hoặc Global tốt hơn Local. Không dùng test metrics để chọn checkpoint hoặc chỉnh ngưỡng. Chưa ghi gradient, histogram trọng số, graph TensorFlow hay GPU profiler.

## Nguồn số liệu và cập nhật

Viewer chỉ đọc các metric report đã định danh: `metrics.json` của baseline A/B/C, `reports/node-a|b|c/training/<run_id>.json`, và `reports/fl/training.json` (receipt cho lịch sử cũ). Không đọc CSV/PCAP/EVE hay gửi dataset lên server. Event log nằm ở `reports/tensorboard`, trạng thái/index/venv ở `runtime/tensorboard`; cả hai được Git bỏ qua.

**Chỉ giữ lần chạy mới nhất**, tối đa 7 mục cố định: `local/node-a`, `local/node-b`, `local/node-c`, `federated/node-a`, `federated/node-b`, `federated/node-c`, `federated/server`. Khi train lại A, chỉ dữ liệu biểu đồ Local A được thay; khi chạy FL mới, bốn mục FL được thay cùng ID lần chạy. Giữ đầy đủ các epoch/vòng của lần mới nhất, không chỉ điểm cuối. Event chứa dữ liệu cũ bị xóa/truncate và cache được reset về bước 0 để không nối lẫn hai lần train. Có thể còn file event rỗng làm cầu nối cho reader đang mở; chúng không chứa số liệu cũ và được dọn khi viewer khởi động lại. Dataset/model và các report nguồn khác không bị xóa.

Lịch sử model đang có được nhập khi mở viewer; nếu có telemetry Local mới hơn thì chọn lần bắt đầu mới nhất, không nhập lại mọi file cũ. Source lỗi được báo trong status thay vì trộn dữ liệu. Những lượt cũ không lưu validation loss theo epoch thì không có đường đó; không tự suy đoán hay train lại để tạo điểm. **Wall time trong event là lúc exporter quan sát/nhập số liệu**, không phải thời điểm train cũ. `source.json` ghi ID lần hiện tại, nguồn và ý nghĩa trục. Index tránh ghi trùng khi polling/restart và báo lỗi nếu cùng ID nhưng lịch sử đã ghi bị đổi.

Lần **train Local mới** vẫn dùng lệnh Compose/entry point hiện có. Trainer ghi JSON atomic sau mỗi epoch, thêm validation log loss và run ID; writer lỗi chỉ cảnh báo, không can thiệp fit/selection. Trạng thái `epochs_complete` chỉ nói vòng train đã xong, chưa xác nhận xuất model thành công. A đã có mount reports; trainer B/C có thêm đúng mount `reports/node-b|c/training` RW, các mount train/validation/test giữ nguyên. Không cần build image lại. Chạy lại Local vẫn thay model ở đường dẫn cố định như trước; không cần chạy lại để xem lịch sử hiện có.

Lần **FL mới** dùng metrics đã được xác minh tại server; viewer cập nhật sau mỗi vòng hoàn tất (poll khoảng 2 giây, TensorBoard reload thêm khoảng 2 giây), không theo từng batch. Server thêm run ID trong `training.json` để nhận biết lúc thay biểu đồ cũ bằng lần mới. Nếu thay source FL, chuẩn bị FAB trước lần submit tiếp theo:

```powershell
python -B .\scripts\prepare_fl_deployment.py
```

Đây chỉ build bundle/check Compose, không train hoặc bật FL. Không cần tạo lại container runtime vì image/command/mount của bốn service FL không đổi.

Chỉ xuất lịch sử một lần mà không chạy web server:

```powershell
.\runtime\tensorboard\venv\Scripts\python.exe -B .\tools\tensorboard\serve.py --once
```

Không chạy `--once` đồng thời viewer; exporter có khóa hệ điều hành để tránh hai writer. Không xóa index riêng lẻ vì có thể làm ghi lặp event; muốn dọn lịch sử phải dừng viewer và xử lý cả log/index sau khi đã sao lưu.

## Kiểm tra

```powershell
.\runtime\tensorboard\venv\Scripts\python.exe -B -m unittest discover -s .\tools\tensorboard -p "test_*.py" -v
python -B -m unittest discover -s .\dashboard\tests -v
```

Tests dùng metric/process giả và roundtrip event thật trong thư mục tạm. Không train dữ liệu lab hoặc mở Docker/network tấn công. Dependencies: [TensorBoard trên PyPI](https://pypi.org/project/tensorboard/), [tài liệu chính thức](https://www.tensorflow.org/tensorboard/get_started).
