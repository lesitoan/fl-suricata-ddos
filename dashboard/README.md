# Dashboard demo trên laptop

Chạy trực tiếp bằng **Python 3.10 trở lên trên Windows**, dùng thư viện chuẩn; không cần pip, npm, build frontend hoặc container cho dashboard. Docker Desktop vẫn cần chạy cho các node/FL. Dataset, các model và phần triển khai FL phải được chuẩn bị như README gốc.

Từ root dự án:

```powershell
python -B .\dashboard\app.py --open
```

Mở `http://127.0.0.1:8765`. Có thể double-click `dashboard/start.bat`. Nếu cổng bận, dùng `python -B .\dashboard\app.py --port 8766 --open`. Dừng dashboard bằng Ctrl+C; thao tác này không tự tắt các container. Không đóng dashboard khi đang chờ báo cáo hoặc submit FL; nếu bị gián đoạn, kiểm trạng thái run trước khi gửi lại, không tự retry.

## Điều khiển

- **Local / Global**: chọn model muốn dùng, sau đó bấm **Bật node** nếu node đang tắt hoặc **Nạp local/global** nếu node đang chạy. Chọn nút radio chưa áp dụng model ngay. Nạp model chỉ tạo lại inference của node, không restart service/sensor. UI hiện mode/hash thực tế từ mount và log của container, chỉ mở nút traffic khi model khớp và các service sẵn sàng.
- **Tắt**: dừng inference, sensor và dịch vụ của đúng node; không tác động FL client. Không dùng Compose down/remove-orphans hoặc thay container của dự án cũ.
- **Benign / SYN probe / UDP load / LDAP burst**: chạy script hiện có trong container sender tạm, mạng internal của đúng node. Giới hạn A 50 SYN/10pps, B 1000 UDP/500pps qua 5 cổng tải, C 100 LDAP/20pps. B phát trong cửa sổ 2 giây, tối đa một gói mỗi slot lịch 2ms, toàn thí nghiệm 15 giây; không gửi bù các slot bị lỡ khi máy chậm, không kéo dài pha tải sau 2 giây. Nếu không gửi đủ 1000 gói, sender ghi missed_send_slots và trạng thái chưa hoàn tất; số gói/tốc độ thực tế được giữ nguyên trong report. B còn 15 request benign kiểm tra riêng (5 trước/trong/sau), không nằm trong 1000 gói tải. Không có trường nhập target/count/rate tùy ý. Thao tác cùng node bị khóa tới khi ghép báo cáo; có thể chạy các node khác nhau song song.
- **Bật FL**: bật SuperLink trước, rồi SuperNode A/B/C, kiểm đăng ký bằng checker hiện có. Không train. **Tắt FL** dừng đúng bốn service, bị chặn khi có run/lock đang hoạt động.
- **Chạy FL**: chọn 1–50 vòng, mặc định 5. Cần đủ bốn service healthy. UI gọi scripts/run_fl.py, theo dõi receipt/training.json, không tự gửi lại. Run thành công thay models/fl/current theo quy tắc sẵn có. Chạy FL khởi tạo từ seed chung, không resume. Khi global mới có, bấm Nạp global ở node để triển khai; dashboard không tự đổi model đang demo.
- **Phiên mới**: làm mới danh sách hoạt động/kết quả, giữ log và bằng chứng trên đĩa. Chỉ thực hiện khi không có tác vụ đang chạy.
- **Xuất phiên**: tải JSON gồm các thao tác và kết quả hiện tại.

## Log và báo cáo

### Test dataset: so sánh Local và Global

Ở thẻ A/B/C, bấm **Test dataset · Local vs Global**. Không cần bật node, bật FL hoặc bấm Nạp model: thao tác này luôn nạp cả baseline Local của node và checkpoint Global hiện tại, rồi chấm **toàn bộ cùng một `test.csv` của node đó**. Docker Desktop và image `ddos-fl-laptop-fl:step1` phải có sẵn. Chỉ chạy một lượt dataset tại một thời điểm; Chạy FL bị khóa trong lúc đánh giá để tránh thay checkpoint.

Dashboard mở tab **Test có nhãn**, hiển thị tiến độ rồi kết quả mới gồm precision, recall, F1, balanced accuracy, false positive rate và hai confusion matrix. Bảng mẫu hiện nhãn thật cùng xác suất/dự đoán của cả hai model; chọn Local hoặc Global để lọc **FP** (benign bị báo attack) hoặc **FN** (attack bị bỏ sót). Bảng phân trang 50 mẫu, còn nút CSV tải toàn bộ prediction, JSON tải báo cáo tổng hợp. Dropdown phân biệt lượt vừa chạy với báo cáo A/B/C đã lưu; job lỗi không được thay bằng kết quả cũ. Hash trong báo cáo xác định model đã chấm, cảnh báo nếu Global hiện tại đã thay đổi.

Worker tạm chạy `network none`, chỉ đọc test/manifest của node được chọn và hai model, ghi vào thư mục report riêng. Nó dùng lại evaluator/biến đổi đặc trưng của dự án, kiểm hash trước/sau và đếm lại metrics từ prediction. Không huấn luyện, chỉnh ngưỡng, phát traffic hay ghi vào EVE; không thay model đang chạy live. Đây là đánh giá trên test pilot đã từng được xem, không phải phép đo ngày ghi hình độc lập hoặc bằng chứng DDoS live. Không dùng kết quả test để chọn checkpoint/ngưỡng.

Kết quả mới lưu dưới `reports/dashboard/sessions/<session>/<job>/dataset/`: `plan.json` đóng băng hash đầu vào; `node-a` (hoặc b/c) chứa `metrics.json` và `predictions.csv`; `comparison.csv` so sánh hai model; `summary.json` chỉ xuất sau khi xác minh thành công. Nếu ứng dụng bị đóng giữa lượt, kiểm job và container tạm có tên `ddos-fl-laptop-dataset-*` trước khi thử lại; không tự xóa lock `runtime/dashboard/.dataset-evaluation-lock` khi worker còn chạy. Khởi động lại dashboard không tự retry job.

Log cập nhật khoảng 2,5 giây/lần; mặc định EVE chỉ hiện flow, có thể bỏ chọn để xem mọi event. Các tab Local/Global đọc file prediction riêng; Inference đọc phần cuối Docker log; Lệnh chạy hiện stdout/stderr gần nhất. Nhấn dòng JSON để mở chi tiết. Đây là phần cuối file có giới hạn kích thước, không phải toàn bộ lịch sử.

**Xóa màn hình** chỉ ẩn các dòng đang xem. **Xóa log live** xóa nội dung các file đã định danh của node, chỉ khi sensor/inference đã dừng và người dùng xác nhận. Không xóa dataset/model/report/Flower SQLite/FAB/receipt/lock. Không đi qua symlink/junction khi xóa. Khuyến nghị dùng Phiên mới cho demo tiếp theo để giữ evidence.

Báo cáo live được tạo sau sender: ghép flow theo thời gian/5-tuple/source ports, prediction theo event_signature_sha256 + model hash + threshold + mode live. Chờ tối đa 90 giây vì Suricata cần timeout mới xuất completed flow. Với A benign, script chưa ghi source ports nên báo cáo quan sát ít nhất 55 giây, không tuyên bố đối chiếu đầy đủ từng request. B load dùng 5 socket tải, thường có 5 flow/prediction, mỗi flow khoảng 200 gói; 3 socket benign kiểm tra tạo flow riêng và bị loại khỏi phép ghép tải. C probe dùng một socket, thường là một flow gộp. Báo cáo B cũ 100 gói/một socket vẫn được giữ và ghi rõ UDP burst (cũ). Thiếu cổng/flow hoặc sender lỗi được báo chưa đầy đủ; không che các dự đoán benign ở lượt probe.

Mọi lượt probe là traffic tổng hợp; không có nhãn attack xác thực và không tự khẳng định saturation. B bổ sung phép đo tải có kiểm soát: lịch gửi độc lập nhận echo, tốc độ thực tế, đối chiếu từng cổng, số echo chưa nhận và median/P95 RTT/timeout từ 5 request benign mỗi giai đoạn. Thiếu echo không xác định vị trí mất gói. Suricata stats delta có thể bao gồm thời gian chờ flow và control probes; thiếu/reset snapshot hiện —, không tự coi là 0. Các thẻ B Local/Global mới nhất hiện riêng để so sánh số đo. B/C gửi request hợp lệ có reply. Biểu đồ live là tỷ lệ **được dự đoán attack**, không phải recall/accuracy DDoS. Local/global phát ở hai lượt riêng, thời gian/đặc trưng có thể khác nhau. Tab **Test có nhãn** còn giữ lựa chọn báo cáo A/B/C cố định trong reports/fl/test-evaluation/summary.json; mở tab không tự chạy đánh giá.

Artifacts được lưu dưới:

```text
runtime/dashboard/state.json                 # phiên đang chọn
reports/dashboard/sessions/<session>/<job>/
  job.json                                  # trạng thái, tham số, kết quả
  command.log                               # lệnh cố định + stdout/stderr
  sender.json                               # traffic jobs
  report.json                               # tổng hợp live
  matched-flows.json
  matched-predictions.json
  sent.pcap                                 # SYN A nếu sender tạo
```

Dashboard chỉ bind 127.0.0.1, kiểm Host/Origin và token POST, không cung cấp terminal/API đường dẫn tùy ý. Backend dùng subprocess argument lists, không shell. Không mount Docker socket vào container. Trình duyệt không gọi trực tiếp Docker. Chạy trong tài khoản Windows đang dùng Docker Desktop.

## Kiểm tra không tác động lab

```powershell
python -B -m unittest discover -s .\dashboard\tests -v
```

Tests dùng Docker runner, sender và EVE giả; HTTP chỉ localhost. Kiểm scope command, chuyển mode/reload, readiness/hash, lock/concurrency, ghép nguồn/port/hash, JSONL dở dòng, giới hạn xóa log, phiên mới giữ evidence và Host/Origin/token. Không chạy Docker, phát traffic hoặc train FL thật.
