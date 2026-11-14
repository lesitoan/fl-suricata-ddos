# Suricata + Federated Learning Lab

Môi trường thực hành phát hiện DDoS trên một máy cá nhân: Suricata phân tích traffic, Python trích đặc trưng và mô hình MLP phân loại flow thành `benign` hoặc `attack`. Docker tách dịch vụ, sensor và chương trình suy luận để có thể tái lập môi trường.

**Bản hiện tại có baseline MLP local A/B/C và Flower FedAvg chạy bằng một server cùng ba client Docker.** Đã chạy smoke/pilot5vòng và đánh giá global/local trên test A/B/C. Global còn yếu ở B/C; kết quả hiện tại chưa xác nhận hội tụ, dữ liệu ghi độc lập hoặc phát hiện live bằng global. Các lệnh bên dưới dành cho Windows PowerShell và Docker Linux containers; dataset/model/reports cần chuẩn bị riêng, không có sẵn khi clone Git.

## Hệ thống làm gì?

```text
Huấn luyện:
PCAP → Suricata → EVE → đặc trưng + nhãn tham chiếu
     → train / validation / test → MLP local

Suy luận:
Request trong mạng Docker → Web A → Suricata → EVE mới
                                               ↓
                                         MLP → prediction
```

- Suricata xuất EVE JSON và giám sát giao diện mạng của dịch vụ web.
- Chín đặc trưng flow được biến đổi thành 13 đầu vào; MLP có kiến trúc **13 → 32 → 16 → 1**.
- Model được chọn bằng validation rồi mới đánh giá trên test. Flow chưa ghép được nhãn không được tự coi là benign.
- Inference hỗ trợ đọc EVE có sẵn (`--once`) hoặc theo dõi log mới (`--follow`).

## Yêu cầu

| Thành phần | Yêu cầu |
|---|---|
| Docker | Docker Desktop chạy Linux containers; bật backend phù hợp với máy |
| Docker Compose | **2.20.3 trở lên**, cần hỗ trợ `include` |
| Python trên Windows | Python 3.10+ cho phần chuẩn bị dữ liệu; chỉ dùng thư viện chuẩn |
| Terminal | Windows PowerShell 5.1 hoặc PowerShell 7 |
| RAM | Khuyến nghị 16 GB cho pilot; worker ghép nhãn có giới hạn 4 GiB |
| Ổ đĩa | Chừa chỗ cho image Docker, PCAP, EVE và CSV; giải nén chọn lọc thay vì toàn dataset |

NumPy/scikit-learn được cài **trong image ML**, không cần cài vào Python của Windows. Build image cần Internet; các bước train/inference chạy được với mạng container bị tắt. MLP pilot dùng CPU, không yêu cầu GPU.

Tham khảo [cài Docker Desktop](https://docs.docker.com/desktop/setup/install/windows-install/) và [Compose include](https://docs.docker.com/compose/how-tos/multiple-compose-files/include/).

## Lấy mã nguồn và kiểm tra môi trường

Clone repository hoặc giải nén source vào thư mục bạn chọn. Mở PowerShell **tại thư mục chứa README này**; mọi lệnh dưới dùng đường dẫn tương đối, không phụ thuộc ổ đĩa của tác giả.

```powershell
docker version
docker info --format '{{.OSType}}'
docker compose version
python --version
```

`docker version` phải có cả Client/Server, OSType phải là `linux`. Khi một lệnh báo lỗi, xử lý lỗi đó trước khi chạy bước tiếp theo.

## Build image và tạo thư mục làm việc

```powershell
docker build --tag ddos-fl-laptop-node-a-sensor:step1 --file .\node-a\Dockerfile .

docker build --build-arg BASE_IMAGE=ddos-fl-laptop-node-a-sensor:step1 --tag ddos-fl-laptop-node-a-ml:step1 --file .\node-a\Dockerfile.ml .

docker run --rm --network none ddos-fl-laptop-node-a-ml:step1 python3 -c "import numpy, sklearn; print('NumPy:', numpy.__version__); print('scikit-learn:', sklearn.__version__)"
```

Phiên bản mong đợi: NumPy `2.4.3`, scikit-learn `1.8.0`. Image sensor chứa Suricata/Python; image ML kế thừa image sensor và bổ sung thư viện ML. Build chưa thực hiện train.

```powershell
$projectRoot = (Get-Location).Path

@(
    'data/node-a/dataset/pcaps/expanded',
    'data/node-a/dataset/reference',
    'data/node-a/live/eve',
    'data/node-a/live/predictions',
    'models/node-a',
    'reports/node-a'
) | ForEach-Object {
    New-Item -ItemType Directory -Force -Path $_ | Out-Null
}
```

Các biến PowerShell chỉ tồn tại trong terminal hiện tại. Nếu mở terminal mới, chuyển lại root source và khai báo lại `$projectRoot`.

## Chuẩn bị dữ liệu

**Dataset và model không được đóng gói trong Git.** Clone source không tự tạo PCAP, split hoặc checkpoint. Có thể bắt đầu theo một trong hai cách:

1. **Đã có bộ đầu vào pilot:** đặt đúng bốn PCAP và reference bên dưới, kiểm nguồn/hash, rồi sang bước xử lý offline.
2. **Tự chuẩn bị từ dataset:** tải nguồn CIC-DDoS2019 và làm phần hướng dẫn mở rộng ngay dưới cây thư mục.

```text
data/node-a/dataset/
├── pcaps/expanded/
│   ├── source-0617.pcap
│   ├── syn-a-train-window.pcap
│   ├── syn-a-val-window.pcap
│   └── syn-a-test-window.pcap
└── reference/
    └── node-a-reference.csv.gz
```

PCAP chứa gói tin; reference chứa trường ghép nhãn từ CSV của dataset. Không đưa trực tiếp đặc trưng CICFlowMeter vào model train từ Suricata. Các cửa sổ thời gian pilot được định nghĩa trong `config/node-a/node-a-expansion.json`; dùng dữ liệu khác cần thiết kế lại cấu hình và thẩm định nhãn.

<details>
<summary><strong>Tự tạo bộ đầu vào pilot từ PCAP và CSV gốc</strong></summary>

Nguồn chính thức: [CIC-DDoS2019 — UNB/CIC](https://www.unb.ca/cic/datasets/ddos-2019.html). Dataset cung cấp PCAP và CSV có nhãn. Khi sử dụng hoặc chia sẻ lại dữ liệu, trích dẫn dataset và bài báo theo hướng dẫn của nhà phát hành.

Pilot tham khảo sử dụng hai mirror đã ghim phiên bản:

- [PCAP, bencorn/CICDDoS2019](https://huggingface.co/datasets/bencorn/CICDDoS2019/tree/88b5d61acbcd41a4bb96221a6a64990a506804b8/pcaps/01-12): tải `PCAP-01-12_0500-0749.zip`.
- [CSV, baalajimaestro/CICDDoS2019](https://huggingface.co/datasets/baalajimaestro/CICDDoS2019/tree/1b3677ee26ba69caa5a9c1ba91cc75cec7ad976e/01-12): tải `Syn.csv` và `UDPLag.csv`.

Mở ZIP, chỉ giải nén các member `_0617`, `_0618`, `_0619`, đổi tên và đặt như sau. ZIP tải bằng trình duyệt là toàn archive đó; chỉ giải nén chọn lọc để tiết kiệm dung lượng.

```text
data/node-a/downloads/
├── Syn.csv
├── UDPLag.csv
└── pcaps-source/
    ├── source-0617.pcap          ← SAT-01-12-2018_0617
    ├── syn-candidate-0618.pcap   ← SAT-01-12-2018_0618
    └── source-0619.pcap          ← SAT-01-12-2018_0619
```

Nếu CSV đã được nén, dùng `Syn.csv.gz`/`UDPLag.csv.gz` tại cùng thư mục. Đoạn chuẩn bị dưới chỉ dùng thư viện Python chuẩn, kiểm hash với bản mirror đã dùng, giữ `_0617` và cắt ba cửa sổ SYN theo cấu hình. Reference chỉ giữ BENIGN/Syn từ `Syn.csv` và BENIGN từ `UDPLag.csv`; không đổi UDP-lag thành SYN.

Chạy nguyên khối tại root source. Nó từ chối ghi đè đầu vào đã chuẩn bị:

```powershell
@'
import csv, gzip, hashlib, io, json, pathlib, shutil, struct
from datetime import datetime

root = pathlib.Path.cwd()
raw = root/'data/node-a/downloads'
data = root/'data/node-a/dataset'
config = json.loads((root/'config/node-a/node-a-expansion.json').read_text(encoding='utf-8'))
expected = {
    'pcaps-source/source-0617.pcap': '692e206d38c02b1d8b2d2318a097f8c4468c4381a5415c529e57e76b1195d0ef',
    'pcaps-source/syn-candidate-0618.pcap': '6f06d83da47e1d479031787852d38c96bd0df5e807bdc1fccad8841f4b633f48',
    'pcaps-source/source-0619.pcap': '73ad9bd8c4fd42dcea5a41c8ddeb0a7f9daaa2e2b60fc8c4714660937f380e59',
    'Syn.csv': '05a272a7005be14262d3929ad16877db42fc74a03032a3a5b58d0230ab08896a',
    'UDPLag.csv': 'f67708a8462509932759ffed7eb92dca0f423267609d1be38a461708d4ea5b7e',
}
sources = {}
for name, digest in expected.items():
    path = raw/name
    if not path.exists() and path.suffix == '.csv':
        path = path.with_name(path.name+'.gz')
    opener = gzip.open if path.suffix == '.gz' else open
    h = hashlib.sha256()
    with opener(path, 'rb') as stream:
        for block in iter(lambda: stream.read(1024*1024), b''):
            h.update(block)
    if h.hexdigest() != digest:
        raise ValueError('Source hash mismatch: '+str(path))
    sources[name] = path

outputs = [root/path for path in config['captures'].values()]
reference = data/'reference/node-a-reference.csv.gz'
if any(path.exists() for path in outputs+[reference]):
    raise FileExistsError('Prepared input already exists; preserve it before a new run')
for path in outputs+[reference]:
    path.parent.mkdir(parents=True, exist_ok=True)
shutil.copy2(sources['pcaps-source/source-0617.pcap'], root/config['captures']['background-0617'])

for capture in ['syn-a-train-window', 'syn-a-val-window', 'syn-a-test-window']:
    source = sources['pcaps-source/source-0619.pcap' if capture == 'syn-a-test-window' else 'pcaps-source/syn-candidate-0618.pcap']
    left, right = next(iter(config['split_time_blocks_utc'][capture].values()))
    left, right = datetime.fromisoformat(left).timestamp(), datetime.fromisoformat(right).timestamp()
    count = 0
    with source.open('rb') as stream, (root/config['captures'][capture]).open('xb') as out:
        header = stream.read(24)
        if len(header) != 24 or header[:4] != b'\xd4\xc3\xb2\xa1':
            raise ValueError('Expected the verified classic little-endian PCAP input')
        out.write(header)
        while True:
            packet_header = stream.read(16)
            if not packet_header:
                break
            if len(packet_header) != 16:
                raise ValueError('Truncated PCAP header')
            sec, micro, size, original = struct.unpack('<IIII', packet_header)
            if size > 16*1024*1024:
                raise ValueError('Invalid packet size')
            packet = stream.read(size)
            if len(packet) != size:
                raise ValueError('Truncated PCAP packet')
            if left <= sec+micro/1e6 < right:
                out.write(packet_header+packet)
                count += 1
    if not count:
        raise ValueError('Empty capture: '+capture)
    print(capture, count, 'packets')

fields = ['Source IP','Source Port','Destination IP','Destination Port','Protocol','Timestamp','Label','Flow Duration']
labels = {'benign': 0, 'attack': 0}
with reference.open('xb') as raw_out:
    with gzip.GzipFile(filename='', fileobj=raw_out, mode='wb', mtime=0, compresslevel=6) as compressed:
        with io.TextIOWrapper(compressed, encoding='utf-8', newline='') as output:
            writer = csv.writer(output)
            writer.writerow(fields)
            for name in ['Syn.csv', 'UDPLag.csv']:
                path = sources[name]
                opener = gzip.open if path.suffix == '.gz' else open
                with opener(path, 'rt', encoding='utf-8-sig', newline='') as source:
                    reader = csv.reader(source)
                    header = [value.strip() for value in next(reader)]
                    indices = [header.index(field) for field in fields]
                    for row in reader:
                        values = [row[index].strip() for index in indices]
                        benign = values[6].upper() == 'BENIGN'
                        if not benign and not (name == 'Syn.csv' and values[6].casefold() == 'syn'):
                            continue
                        datetime.fromisoformat(values[5])
                        int(values[1]); int(values[3]); int(values[4])
                        writer.writerow(values)
                        labels['benign' if benign else 'attack'] += 1
print('Reference labels:', labels)
print('Prepared pilot inputs; next: Suricata offline')
'@ | python -X utf8 -B -
```

Hash ở đây xác nhận đúng bản mirror của pilot, không phải chứng nhận hash từ nhà phát hành gốc. Giữ nguồn, phiên bản, hash và kết quả chuẩn bị khi làm báo cáo. Timestamp dữ liệu tham khảo là năm 2018 dù tên dataset là 2019; không sửa ngày/giờ để ép ghép nhãn.

</details>

## Tạo EVE bằng Suricata offline

Chạy lần lượt bốn capture trong container không có network. Thư mục kết quả phải chưa tồn tại; nếu đã có, kiểm tra kết quả hiện có hoặc tạo run khác, không trộn log:

```powershell
$captures = Get-Content .\config\node-a\node-a-expansion.json -Raw | ConvertFrom-Json

foreach ($capture in $captures.captures.PSObject.Properties) {
    $inputPath = (Resolve-Path -LiteralPath $capture.Value).Path
    $outputPath = Join-Path $projectRoot "data\node-a\dataset\derived\suricata\$($capture.Name)"
    if (Test-Path -LiteralPath $outputPath) { throw "Output đã có: $outputPath" }
    New-Item -ItemType Directory -Path $outputPath | Out-Null

    docker run --rm --network none --memory 1g --cpus 1 `
      --mount "type=bind,source=$inputPath,target=/input.pcap,readonly" `
      --mount "type=bind,source=$outputPath,target=/output" `
      ddos-fl-laptop-node-a-sensor:step1 `
      suricata -c /etc/suricata/suricata.yaml --runmode single `
      --set flow.memcap=256mb --set stream.memcap=64mb -r /input.pcap -l /output

    if ($LASTEXITCODE -ne 0) { throw "Suricata lỗi: $($capture.Name)" }
}
```

Mỗi capture có `eve.json` và `suricata.log`. Kiểm log có EOF, packet count khớp PCAP, không emergency/memcap drop. `Stopping engine` chưa đồng nghĩa đã ghi xong mọi flow; đợi lệnh kết thúc. Với dữ liệu pilot, dùng `flow.start`/`flow.end`, vì timestamp cấp ngoài của một số event offline có thể là năm 1970.

## Trích đặc trưng, ghép nhãn và chia tập

```powershell
foreach ($capture in $captures.captures.PSObject.Properties) {
    $name = $capture.Name
    docker compose -p ddos-fl-laptop -f compose.node-a.yaml run --rm --no-deps pipeline `
      python3 -B scripts/match_suricata_reference.py `
      --capture-id $name `
      --eve "data/node-a/dataset/derived/suricata/$name/eve.json" `
      --reference-csv data/node-a/dataset/reference/node-a-reference.csv.gz `
      --output "data/node-a/dataset/derived/suricata/$name/flows-v2.csv" `
      --attack-label Syn --utc-offset-hours 4 --tolerance-seconds 3

    if ($LASTEXITCODE -ne 0) { throw "Ghép nhãn lỗi: $name" }
}

docker compose -p ddos-fl-laptop -f compose.node-a.yaml run --rm --no-deps pipeline `
  python3 -B scripts/node-a/split_node_a_pilot.py
```

Offset `4` là phép đổi timestamp reference của pilot sang UTC, không phải giờ laptop. Matcher khử trùng và ghép theo thời gian/5-tuple; flow không ghép được giữ là `unknown`. Splitter loại unknown, flow vượt block và nhóm kết nối xuyên nhiều tập. Các script từ chối ghi đè output đã có.

```text
data/node-a/work/splits/pilot-v1/
├── train.csv
├── validation.csv
├── test.csv
└── manifest.json
```

Kiểm `manifest.json`: mỗi tập có benign/attack, các `checks` đều `true` và hash hợp lệ. Đây là chia theo time blocks trong cùng ngày thu, chưa phải đánh giá trên nhiều phiên/ngày độc lập.

## Huấn luyện MLP local

```powershell
docker compose -p ddos-fl-laptop -f compose.node-a.yaml run --rm --no-deps trainer `
  python3 -B scripts/node-a/train_node_a_pilot.py `
  --root /workspace `
  --output /workspace/models/node-a/local-only-pilot-v1/laptop-01
```

Cấu hình ở `config/node-a/node-a-baseline.json`: 20 epoch, Adam, seed cố định, class weights từ train, threshold 0,5. Chọn epoch bằng validation balanced accuracy rồi mới đọc test. Chạy hết epoch không tự chứng minh hội tụ.

```text
models/node-a/local-only-pilot-v1/laptop-01/
├── model.json
├── weights.npz
├── metrics.json
└── test-predictions.csv
```

```powershell
$result = Get-Content .\models\node-a\local-only-pilot-v1\laptop-01\metrics.json -Raw | ConvertFrom-Json
$result.best_epoch
$result.test
$result.checks
```

Không tạo trước thư mục `laptop-01`; trainer tự tạo và từ chối ghi đè. Run tiếp theo dùng tên mới, ví dụ `laptop-02`. Live Compose mặc định dùng `laptop-01`; chỉ thay đường dẫn model khi chủ động triển khai checkpoint khác.

## Chạy web, Suricata và inference live

Chỉ thực hiện sau khi đã có `model.json` và `weights.npz`, hoặc đã nhận một checkpoint phù hợp từ bên cung cấp. Model phải khớp schema `flow-v2` và transform của source.

```powershell
docker compose -p ddos-fl-laptop -f compose.node-a-live.yaml config --quiet
docker compose -p ddos-fl-laptop -f compose.node-a-live.yaml up -d --wait web sensor inference
docker compose -p ddos-fl-laptop -f compose.node-a-live.yaml ps
docker compose -p ddos-fl-laptop -f compose.node-a-live.yaml logs --tail 30 sensor inference
```

Đợi web `healthy`, sensor `Engine started`, inference `status: ready`. Web ở mạng Docker internal, không publish cổng host; kiểm bằng container cùng mạng:

```powershell
docker run --rm --network ddos-fl-laptop_site-a ddos-fl-laptop-node-a-sensor:step1 `
  python3 -c "import urllib.request; print(urllib.request.urlopen('http://web:8000/lab-check', timeout=5).read().decode())"

Start-Sleep -Seconds 25
Get-Content .\data\node-a\live\predictions\predictions.jsonl -Tail 3
```

Response mong đợi có `node: A`, `status: ok`. Prediction có `flow_id`, `probability_attack`, `prediction`, model hash và `mode: live`.

Inference chỉ đọc các event mới từ cuối EVE, không train lại. Với completed-flow, cần đợi Suricata kết thúc/flush flow rồi mới có prediction. `seconds_from_flow_end_to_score` gồm chờ log và xử lý, không phải chỉ thời gian tính MLP. Alert `NODE_A LAB smoke marker` là marker benign của `/lab-check`, không phải kết luận DDoS.

## Kiểm thử benign và SYN trong lab

### Benign: 24 request

```powershell
$scenarioPath = Join-Path $projectRoot 'reports\node-a\benign-live-01.json'
if (Test-Path -LiteralPath $scenarioPath) { throw 'Report đã tồn tại; dùng tên run mới.' }

$scenario = docker run --rm --network ddos-fl-laptop_site-a `
  --mount "type=bind,source=$projectRoot\scripts\node-a\benign_traffic.py,target=/app/benign_traffic.py,readonly" `
  ddos-fl-laptop-node-a-sensor:step1 python3 -B /app/benign_traffic.py
$scenarioExit = $LASTEXITCODE
$scenario | Set-Content -LiteralPath $scenarioPath -Encoding utf8
if ($scenarioExit -ne 0) { throw 'Generator lỗi; xem report vừa lưu.' }
$scenario
```

Script gửi 24 request đến `/`, `/about`, `/download`, `/lab-check`; mong đợi `successful: 24`, `errors: []`. Đợi prediction rồi đối chiếu tuple/thời gian với EVE, signature với prediction. Không lấy toàn bộ prediction cũ để tính FPR của lượt mới.

### SYN: 50 gói, tối đa 10 pps

Lượt thử chỉ nhắm `web:8000` trong mạng internal, không đổi đích hoặc tăng tải. Kiểm mạng trước và dùng thư mục run mới:

```powershell
if ((docker network inspect ddos-fl-laptop_site-a --format '{{.Internal}}') -ne 'true') {
    throw 'Chưa xác nhận mạng internal của lab.'
}
$runDir = Join-Path $projectRoot 'reports\node-a\syn-live-01'
if (Test-Path -LiteralPath $runDir) { throw 'Run đã tồn tại; dùng tên mới.' }
New-Item -ItemType Directory -Path $runDir | Out-Null

docker run --rm --network ddos-fl-laptop_site-a --cap-drop ALL --cap-add NET_RAW `
  --memory 128m --cpus 0.25 --read-only --tmpfs /tmp `
  --mount "type=bind,source=$projectRoot\scripts\node-a\syn_probe.py,target=/app/syn_probe.py,readonly" `
  --mount "type=bind,source=$runDir,target=/output" `
  ddos-fl-laptop-node-a-sensor:step1 python3 -B /app/syn_probe.py
```

`sender.json` ghi từng source port/thời gian, `sent.pcap` là bản ghi phía gửi chứ không phải capture độc lập trên wire. Kiểm `completed`, số gói, ghép từng flow/prediction, model hash, drops/errors và health của web. Kernel có thể gửi RST; script không sửa firewall. Đây là SYN probe lưu lượng nhỏ, không phải phép đo DDoS gây quá tải hoặc botnet vật lý. Giữ nguyên threshold khi đánh giá và báo cả mẫu bỏ sót/báo động giả.

## Theo dõi và dừng

```powershell
docker compose -p ddos-fl-laptop -f compose.node-a-live.yaml logs --tail 20 inference
docker compose -p ddos-fl-laptop -f compose.node-a-live.yaml stop inference sensor web
```

Stop giữ nguyên dataset/model/log. Các service không tự restart (`restart: no`). EVE/prediction là file append; theo dõi dung lượng và mở run mới có chủ đích khi cần. Không có cơ chế rotation EVE tự động được triển khai trong bản hiện tại.

## Cấu trúc mã nguồn

```text
config/node-a/             cấu hình capture, time blocks và baseline
node-a/                    Dockerfile, Dockerfile.ml, cấu hình sensor, web
scripts/                   feature schema, model runtime, matcher, inference dùng chung
scripts/node-a/            chia tập, train, benign và SYN probe riêng A
compose.node-a-live.yaml   web + sensor + inference
compose.node-a.yaml        include live Compose, thêm pipeline/trainer theo yêu cầu
data/                     dữ liệu sinh/tải trên máy, không nằm trong Git
models/                   checkpoint trên máy, không nằm trong Git
reports/                  bằng chứng chạy trên máy, không nằm trong Git
```

Xem [vai trò từng script](scripts/README.md). Các worker `pipeline`/`trainer` mặc định chỉ in `--help` khi gọi bằng `docker compose ... run`; các lệnh train ở trên truyền command rõ ràng.

Trainer dùng chung hiện thay model tại đường dẫn `--output` sau mỗi lần train thành công. Các đường dẫn model trong ví dụ A cũng được sử dụng cố định; không cần tạo thư mục cho từng lần train.

## Kết quả pilot tham khảo và giới hạn

| Hạng mục đã kiểm | Kết quả |
|---|---|
| Split A | Train 68.928, validation 59.456, test 67.226 mẫu |
| Local test | Confusion matrix `[[454, 0], [6, 66766]]`, thứ tự benign/attack |
| Benign live | 24/24 request có prediction benign |
| SYN probe live | 50/50 flow có prediction attack |

Đây là kết quả của một checkpoint/run đã kiểm, không phải cam kết cho mọi lần cài hoặc traffic thực tế. Dataset lệch lớp, cùng ngày thu và benign/attack từ các đoạn thời gian khác nhau. Chưa có đánh giá nhiều capture độc lập, nhiều seed, tải lớn hoặc FL-vs-local. Repo không kèm checkpoint đó trong Git; người dùng cần train hoặc nhận artifact riêng.

## Lỗi thường gặp

| Hiện tượng | Cách kiểm tra |
|---|---|
| Không kết nối Docker Engine | Mở Docker Desktop, đợi engine chạy, kiểm `docker version` và OSType Linux |
| `source=` rỗng trong `--mount` | Khai báo lại `$projectRoot`/các biến đường dẫn trong terminal hiện tại |
| Không tìm thấy dataset/model | Git không chứa artifact; hoàn tất phần dữ liệu/train hoặc đặt bundle đúng cấu trúc |
| Output có file không thuộc model | Kiểm tra lại đường dẫn; trainer chỉ thay một thư mục model hợp lệ hoặc thư mục rỗng |
| Chưa có prediction live | Kiểm sensor/inference ready, gửi request mới sau khi follower chạy, đợi flow timeout |
| Benign bị dự đoán attack | Ghi nhận false positive; không đổi ground truth hoặc tune theo test để ép kết quả |
| `No module named ...` khi chạy trên Windows | Chạy train/inference trong image ML; script chuẩn bị dữ liệu chỉ cần Python chuẩn |

## Tài liệu tham khảo

- [CIC-DDoS2019 — Canadian Institute for Cybersecurity, UNB](https://www.unb.ca/cic/datasets/ddos-2019.html).
- Sharafaldin et al., *Developing Realistic Distributed Denial of Service (DDoS) Attack Dataset and Taxonomy*, IEEE ICCST, 2019; trích dẫn theo trang dataset.
- [Suricata Documentation](https://docs.suricata.io/en/suricata-7.0.10/).
- [scikit-learn MLPClassifier](https://scikit-learn.org/stable/modules/generated/sklearn.neural_network.MLPClassifier.html).
- [Flower](https://flower.ai/docs/) và [bài báo FedAvg](https://arxiv.org/abs/1602.05629), cho giai đoạn mở rộng FL.


## Node B: train và sử dụng model

B dùng cùng kiểu lệnh Docker Compose/Python như A. Có một đường dẫn model cố định:

```text
models/node-b/current/
├── weights.npz
├── model.json
├── metrics.json
└── validation-predictions.csv
```

Mỗi lần train thành công sẽ thay bộ file ở thư mục này bằng model mới. Trainer ghi và kiểm tra đầy đủ trong thư mục tạm, sau đó thay model cũ; thư mục tạm được dọn khi kết thúc. Nếu train hoặc ghi file lỗi trước khi thay, model cũ vẫn được giữ. Không tạo `runs/` hoặc các thư mục model v2/v3. Cơ chế thay model này nằm trong trainer dùng chung của cả A và B; đường dẫn model A vẫn giữ như phần hướng dẫn A.

B cần bộ chia `data/node-b/work/splits/pilot-v1/{train.csv,validation.csv,test.csv,manifest.json}`. `pilot-v1` là tên bộ chia cố định, không phải số lần train. Cấu hình B ở `config/node-b/node-b-baseline.json`. Thiết lập hiện tại vẫn là MLP 13→32→16→1, 20 epoch, threshold 0,5 và cân trọng số hai nhóm attack có/không có gói trả về theo train.

Chạy tại thư mục dự án, dùng image ML đã build:

```powershell
docker compose -p ddos-fl-laptop -f compose.node-b.yaml config --quiet

docker compose -p ddos-fl-laptop -f compose.node-b.yaml run --rm --no-deps trainer `
  python3 -B scripts/node-b/train_node_b_pilot.py `
  --root /workspace `
  --output /workspace/models/node-b/current
```

Chạy lại chính lệnh trên để cập nhật model tại cùng đường dẫn. Không cần `train.ps1` hoặc tên run. Compose B chỉ mount dữ liệu B và chỉ đọc train/validation/manifest; không mount test CSV. Entry point B mặc định validation-only.

Khi suy luận, dùng `models/node-b/current` làm model directory; trong container có thể mount chỉ đọc vào `/model` và truyền `--model-dir /model`. Inference đang chạy cần khởi động lại để nạp trọng số mới sau lần train thay model.

Model đang giữ tại thời điểm tổ chức source có validation `[[214,7],[282,933]]` (benign/attack), recall attack 76,79%, balanced accuracy 86,81%. Metadata vẫn giữ ID của lần huấn luyện gốc để truy nguyên. Đây là model thử nghiệm, đã có kiểm tra benign live bên dưới nhưng chưa có đánh giá độc lập. Nhãn family `DrDoS_UDP` trong reference có cả TCP; cấu hình hiện tại giữ nhãn dataset.


## Node B: dựng dịch vụ UDP để kiểm tra live từng bước

Dịch vụ `udp-b` là UDP echo cổng 9000, chỉ nằm trong mạng Docker internal `ddos-fl-laptop_site-b`, không publish cổng ra host. Code ở `node-b/udp_server.py`, dùng image sensor hiện có vì đã có Python; chưa cần build image mới.

```powershell
docker compose -p ddos-fl-laptop -f compose.node-b-live.yaml config --quiet

docker compose -p ddos-fl-laptop -f compose.node-b-live.yaml up -d --wait udp-b

docker compose -p ddos-fl-laptop -f compose.node-b-live.yaml ps

docker run --rm `
  --network ddos-fl-laptop_site-b `
  --memory 64m --cpus 0.25 `
  --cap-drop ALL --read-only --tmpfs /tmp `
  --mount "type=bind,source=$((Get-Location).Path)\scripts\node-b\benign_traffic.py,target=/app/benign_traffic.py,readonly" `
  ddos-fl-laptop-node-a-sensor:step1 `
  python3 -B /app/benign_traffic.py
```

Client gửi đúng 10 request nhỏ, cách nhau khoảng 0,2 giây, chỉ tới tên dịch vụ `udp-b`; chờ phản hồi tối đa 15 giây cho toàn bài kiểm tra. Kết quả mong đợi là `successful: 10`, `errors: []`. Đây là kiểm tra gửi/nhận ứng dụng, không phải đánh giá model. Suricata B được gắn ở bước dưới; sau khi xác nhận EVE mới sẽ nối inference dùng `models/node-b/current`.

Không dùng `--remove-orphans` khi thao tác từng file Compose của dự án: các container A vẫn thuộc cùng project. Chỉ gọi service B cần chạy để giữ trạng thái node A.


### Node B: gắn Suricata để ghi EVE live

Sensor riêng tên `sensor-b` dùng network namespace của `udp-b` (`network_mode: service:udp-b`) và bắt `eth0`. Dùng image sensor đã build; output riêng ở `data/node-b/live/eve/`. Khởi động khi Docker đang chạy:

```powershell
New-Item -ItemType Directory -Force -Path .\data\node-b\live\eve | Out-Null

docker compose -p ddos-fl-laptop -f compose.node-b-live.yaml up -d --wait sensor-b

docker compose -p ddos-fl-laptop -f compose.node-b-live.yaml ps
```

Đợi `udp-b` và `sensor-b` healthy rồi chạy lại client 10 request ở phần trên. Suricata ghi flow khi kết nối hết timeout; UDP hai chiều có thể cần chờ khoảng 30–60 giây. Xem EVE bằng:

```powershell
Get-Content .\data\node-b\live\eve\eve.json -Tail 5
```

Bằng chứng smoke đã kiểm ở máy phát triển: 10/10 request có phản hồi, khớp 10 flow UDP theo IP/port; mỗi flow có 1 gói đi và 1 gói về, 64 byte mỗi chiều theo bộ đếm Suricata. Chênh lệch `capture.kernel_drops` và `capture.errors` bằng 0. Đây là kiểm tích hợp sensor trên tải nhỏ, chưa đánh giá model. Inference B được nối vào EVE ở phần tiếp theo.


### Node B: nối model current với EVE live

Service `inference-b` dùng script chung `scripts/infer_eve.py`, đọc EVE và `models/node-b/current` ở chế độ chỉ đọc, ghi vào `data/node-b/live/predictions/predictions.jsonl`. Container inference không có mạng.

```powershell
New-Item -ItemType Directory -Force -Path .\data\node-b\live\predictions | Out-Null

docker compose -p ddos-fl-laptop -f compose.node-b-live.yaml up -d --wait inference-b

docker logs --tail 5 ddos-fl-laptop-inference-b-1
```

Đợi log JSON `status: ready`, kiểm `model_id` và `weights_sha256` đúng model current, rồi chạy lại client UDP 10 request ở phần dịch vụ. Follower dùng `--start-at-end`, bỏ qua EVE cũ và chỉ xử lý sự kiện mới sau khi bắt đầu. Xem kết quả:

```powershell
Get-Content .\data\node-b\live\predictions\predictions.jsonl -Tail 10
```

Benign live smoke đã kiểm: 10 request thành công → 10 flow mới → 10 prediction benign; không duplicate/invalid, capture drop/error không tăng. Xác suất attack khoảng 0,145883 tại threshold 0,5. Tính lại từ EVE và trọng số khớp trong sai số số học. Độ trễ từ flow end đến prediction khoảng 34–40 giây trong lần chạy này, bao gồm UDP flow timeout/export và polling; không phải thời gian tính toán riêng của MLP. Đây là kiểm tích hợp trên traffic nhỏ có kiểm soát, chưa chứng minh phát hiện UDP flood hay tổng quát hóa.

Model được nạp lúc inference khởi động. Sau lần train thay model ở đường dẫn cố định, tạo lại riêng inference để bind/nạp model mới:

```powershell
docker compose -p ddos-fl-laptop -f compose.node-b-live.yaml up -d --force-recreate --no-deps inference-b
```

UDP B và sensor B cần đang chạy khi dùng lệnh `--no-deps`. Không cần train lại hoặc đổi threshold để chạy smoke; ghi nhận đúng prediction quan sát được.


### Node B: UDP load có giới hạn và đo trước/trong/sau

Bài hiện tại gửi tối đa 1000 UDP datagram 64 byte qua 5 socket/cổng nguồn, mục tiêu 500 gói/giây, tới cố định `udp-b:9000` trên mạng internal `site-b`. Nhịp gửi độc lập nhận echo, trong cửa sổ 2 giây, tối đa một gói mỗi slot lịch 2ms; slot bị trễ bị bỏ qua, không gửi bù sau cửa sổ. Nếu máy chậm không đạt đủ 1000 gói, sender giữ số thực tế/missed_send_slots và báo chưa hoàn tất. Có thêm 15 request benign đo RTT/timeout (5 trước, 5 trong, 5 sau), không tính vào 1000 gói tải. Đây là synthetic UDP load để đo hành vi và kiểm tích hợp; chưa phải ground truth DrDoS_UDP/CIC-DDoS2019 hoặc bằng chứng saturation. Dịch vụ echo và model/threshold giữ nguyên. MLP hiện chấm từng flow, không quan sát trực tiếp tổng pps của cả 5 cổng; tăng tải tổng không bảo đảm nhãn attack.

Đảm bảo UDP B/sensor chạy và tạo lại riêng inference để nạp model current mới nhất, bỏ qua EVE cũ:

```powershell
docker compose -p ddos-fl-laptop -f compose.node-b-live.yaml up -d --wait udp-b sensor-b

docker compose -p ddos-fl-laptop -f compose.node-b-live.yaml up -d --force-recreate --no-deps inference-b

docker logs --tail 5 ddos-fl-laptop-inference-b-1
```

Đợi `status: ready` trước khi gửi. Tạo output riêng và chạy probe:

```powershell
$runDir = Join-Path (Get-Location).Path 'reports\node-b\udp-probe-01'
if (Test-Path -LiteralPath $runDir) { throw 'Report đã tồn tại; chọn udp-probe-02 để giữ kết quả cũ.' }
New-Item -ItemType Directory -Path $runDir | Out-Null
$probeScript = (Resolve-Path '.\scripts\node-b\udp_probe.py').Path

docker run --rm `
  --network ddos-fl-laptop_site-b `
  --memory 64m --cpus 0.25 `
  --cap-drop ALL --security-opt no-new-privileges `
  --read-only --tmpfs /tmp `
  --mount "type=bind,source=$probeScript,target=/app/udp_probe.py,readonly" `
  --mount "type=bind,source=$runDir,target=/report" `
  ddos-fl-laptop-node-a-sensor:step1 `
  python3 -B /app/udp_probe.py

python -B .\scripts\node-b\verify_udp_probe.py --run-dir $runDir
```

Verifier đợi tối đa 75 giây để flow hết timeout và prediction xuất hiện. Phiên bản UDP load hiện tại gửi tối đa 1000 gói qua 5 cổng, mục tiêu 500pps, thường tạo 5 flow/prediction; có thêm 15 request benign đo trước/trong/sau qua các cổng riêng, không gộp vào flow tải. Lịch gửi không chờ echo từng gói. Cửa sổ gửi 2 giây, toàn thí nghiệm tối đa 15 giây (gồm các phép đo benign và chờ echo); không gửi bù dồn nếu lịch CPU trễ. Có thể dùng --mode global với verifier sau khi đã nạp global; mặc định local. Verifier vẫn đọc được báo cáo burst cũ 100 gói/một cổng. Đọc packets_sent, số gói Suricata bắt được, sent_packet_count_matches_capture, predicted_attack/predicted_benign và health_checks trong verification.json; xác suất từng flow nằm trong predictions.json. Các trường probability_attack/prediction cấp báo cáo chỉ có khi đúng một prediction để tương thích báo cáo cũ. `MATCHED` nghĩa là đã ghép được pipeline, không tự khẳng định phát hiện DDoS thành công. Nếu prediction là benign, ghi nhận model không đánh dấu burst này là attack; không coi nhãn synthetic là bằng chứng attack thực tế.

`sender.json` ghi số gói/time/các cổng, tốc độ thực tế và health_checks (5 request trước/trong/sau, RTT/timeout). `flows.json`, `predictions.json`, `verification.json` lưu đối chiếu; báo cáo cũ một flow vẫn có thêm flow.json/prediction.json. Dashboard hiển thị thẻ số đo B riêng cho local/global, kiểm số gói từng cổng và stats capture drops/errors nếu có snapshot phù hợp. Không coi echo thiếu là bằng chứng vị trí mất gói hoặc RTT thay đổi là saturation. Dịch vụ vẫn echo bình thường; không đổi model/ngưỡng để ép dự đoán attack. Suricata không bắt buộc có event `alert`; ML dùng event `flow`. Script có count/nhịp/deadline cố định, không có tùy chọn đích bên ngoài.


### Node B: đối chiếu PCAP UDP có nhãn chưa dùng trong pilot

Máy hiện có một PCAP B `source-0592.pcap`, đã xử lý bằng Suricata thành source EVE/features. Có thể đánh giá bổ sung trên flow UDP chưa dùng; đây vẫn là cùng capture/ngày thu, không phải recording độc lập. Bài kiểm tra offline này không phát gói vào mạng live.

`prepare_udp_evaluation.py` xác minh hash dataset/reference và toàn bộ split A/B, rồi chọn tất cả UDP có nhãn reference, loại unknown, các nhóm kết nối xuất hiện trong mọi tập train/validation/test A/B, nhóm của bài smoke offline 100 flow trước đây và flow giao các khoảng thời gian B đã dùng. Việc chọn chỉ dựa vào quy tắc dữ liệu, không dựa vào prediction. Danh sách cố định và hash model/inputs lưu ở `data/node-b/work/evaluation/labeled-udp/selection.json`.

Lần đầu chuẩn bị selection tại root dự án:

```powershell
python -B .\scripts\node-b\prepare_udp_evaluation.py
```

Nếu selection đã được chuẩn bị, giữ nguyên để dùng. Script từ chối ghi đè; model hoặc inputs thay đổi sau khi cố định selection cũng làm evaluator dừng để kiểm tra provenance.

Chấm bằng model current, chỉ mount dữ liệu B và không có mạng:

```powershell
docker compose -p ddos-fl-laptop -f compose.node-b.yaml run --rm --no-deps udp-evaluator `
  python3 -B /app/node-b/evaluate_udp_dataset.py `
  --output /reports/udp-dataset-eval
```

Evaluator đọc raw EVE, tính lại chín đặc trưng và so khớp với từng dòng CSV có nhãn đã chọn, rồi dự đoán theo batch bằng trọng số current. Không fit model/scaler hoặc chỉnh threshold. Kết quả ở `reports/node-b/udp-dataset-eval/{metrics.json,predictions.csv}`; output đã có thì dừng để giữ bằng chứng.

Đọc `confusion_matrix`, `recall_attack` và nhất là `subgroups.attack_no_return`/`attack_has_return`; số lượng giữa hai nhóm chênh lệch lớn. Selection hiện có khoảng 90.442 attack UDP và 9 benign. Benign rất ít nên chưa đủ đánh giá tỷ lệ báo nhầm đáng tin cậy. Kết quả tốt ở cùng PCAP chưa chứng minh tổng quát hóa; đánh giá cuối vẫn cần capture/tập độc lập chưa dùng lựa chọn.


## Node C: dữ liệu LDAP và chia tập

Input C nằm riêng ở `data/node-c/dataset`: ba PCAP `pcaps/expanded/source-{392,401,430}.pcap` và reference `reference/node-c-reference.csv.gz`. Reference hiện dùng projection có nhãn DrDoS_LDAP/BENIGN và provenance trong manifest dữ liệu; không phải model hoặc feature table sao chép từ lần train trước.

Xử lý mỗi PCAP bằng image Suricata hiện có vào `derived/suricata/node-c-source-<id>/eve.json`. Với từng capture, gọi script ghép nhãn chung:

```powershell
$id = 392  # lặp lại với 401 và 430
python -B .\scripts\match_suricata_reference.py `
  --capture-id "node-c-source-$id" `
  --eve "data/node-c/dataset/derived/suricata/node-c-source-$id/eve.json" `
  --reference-csv data/node-c/dataset/reference/node-c-reference.csv.gz `
  --output "data/node-c/dataset/derived/suricata/node-c-source-$id/flows-v2.csv" `
  --attack-label DrDoS_LDAP --utc-offset-hours 4 --tolerance-seconds 3
```

Sau khi cả ba báo cáo ghép nhãn đã kiểm tra, chia C trên host bằng Python chuẩn:

```powershell
python -B .\scripts\node-c\split_node_c_pilot.py
```

Cấu hình `config/node-c/node-c-expansion.json` cố định 392→train, 401→validation, 430→test theo các cửa sổ thời gian. Script kiểm hash toàn bộ A/B split và nguồn C, loại unknown, nhóm có trong bất kỳ tập A/B, nhóm giao nhiều tập C và observation trùng; yêu cầu cả hai lớp đủ tối thiểu 30 dòng mỗi tập. Không dùng prediction để chọn dữ liệu.

Kết quả nằm ở `data/node-c/work/splits/pilot-v1/{train.csv,validation.csv,test.csv,manifest.json}` và `reports/node-c/split-pilot.json`. Script từ chối ghi đè split đã có hoặc còn dở. Ba đoạn thuộc cùng một ngày/recording; chia theo capture này chưa tạo bằng chứng tổng quát hóa độc lập. Mốc này chuẩn bị dữ liệu C; chưa huấn luyện C hoặc FL.


### Node C: script train local MLP bằng Docker

C dùng trainer chung `scripts/train_mlp.py` qua entry point `scripts/node-c/train_node_c_pilot.py`. Cấu hình ở `config/node-c/node-c-baseline.json`: MLP13→32→16→1, seed20261018, 20epoch, threshold0,5, trọng số cân lớp chỉ tính từ train. Chọn checkpoint bằng validation trước khi đánh giá test. Đây là baseline cục bộ LDAP/BENIGN theo nhãn reference, chưa có FL hoặc xác minh LDAP reflection live.

Dùng image ML sẵn có; kiểm tra Compose và CLI trước khi train:

```powershell
docker compose -p ddos-fl-laptop --profile tools -f compose.node-c.yaml config --quiet

docker compose -p ddos-fl-laptop -f compose.node-c.yaml run --rm --no-deps trainer
```

Lệnh mặc định chỉ in `--help`. Khi thực sự train, truyền command rõ ràng:

```powershell
docker compose -p ddos-fl-laptop -f compose.node-c.yaml run --rm --no-deps trainer `
  python3 -B scripts/node-c/train_node_c_pilot.py `
  --root /workspace `
  --output /workspace/models/node-c/current
```

Container không có mạng, chỉ đọc script/config và bốn file split C; chỉ thư mục model C được ghi. Không mount dữ liệu A/B. Kết quả cố định `models/node-c/current/{weights.npz,model.json,metrics.json,test-predictions.csv}`. Train thành công thay model cũ bằng bộ file mới; lỗi trước khi thay giữ model cũ. Không tạo thư mục cho từng phiên bản/run. Nếu đang phát triển cấu hình sau baseline, dùng `--validation-only` để không chấm lại test trong vòng lựa chọn.

Lúc chuẩn bị source, trainer đã được kiểm tra bằng dữ liệu giả về CLI/config/schema, chọn checkpoint/export, portable inference và thay model/giữ model cũ khi lỗi; chưa chạy dữ liệu C thật. Không suy ra hội tụ hoặc khả năng tổng quát hóa từ việc script chạy xong.


Kết quả baseline C do người dùng chạy và đã đối chiếu: train đủ20epoch, chọn epoch1 vì validation balanced accuracy bằng nhau và lấy epoch sớm nhất. Test33.199flow có confusion `[[110,8],[14,33067]]` (benign/attack), recall attack99,9577%, balanced accuracy96,5890%, FPR6,7797% trên118benign. Cả14attack có gói trả về trong test bị bỏ sót (9UDP/5TCP theo nhãn reference); nhóm33.067attack không có gói trả về đều được phát hiện. Kết quả tổng bị chi phối bởi nhóm attack lớn; chưa kiểm LDAP live, hội tụ hoặc khả năng tổng quát hóa. Model C current đã nạp và tái tính prediction bằng inference runtime chung, sai số tối đa0.0 so với file đã lưu. Xem báo cáo/model tại các thư mục artifact riêng trên máy; không đưa artifact vào Git.


### Node C: smoke test EVE → inference trước live

Dùng helper chung `scripts/check_eve_model.py` để lấy tối đa100flow từ tập test đã đánh giá, chọn theo UID/nhãn/nhóm có hoặc không có gói trả về. Đây là mẫu kiểm tích hợp có chủ đích bao phủ trường hợp, không phải tập test mới hoặc ước lượng độ chính xác toàn bộ. Các metric test đầy đủ trong model current vẫn là baseline chính.

Chuẩn bị mẫu (chỉ lần đầu cho một thư mục report):

```powershell
python -B .\scripts\check_eve_model.py prepare --node c --run-dir reports/node-c/eve-smoke
```

Helper kiểm hash model/manifest/split/source EVE, ghép source row UID và đối chiếu chín đặc trưng, rồi tạo `sample.eve.json` và `expected.json`. Mẫu C hiện gồm50benign,36attack không có gói trả về,14attack có gói trả về. Nhãn/expected probability không nằm trong EVE đưa vào model; expected dùng để xác minh sau.

Chạy shared inference bằng Docker:

```powershell
$projectRoot = (Get-Location).Path
$runDir = Join-Path $projectRoot 'reports\node-c\eve-smoke'

docker run --rm `
  --network none --memory 512m --cpus 0.75 `
  --read-only --tmpfs /tmp --cap-drop ALL `
  --mount "type=bind,source=$projectRoot\scripts,target=/app,readonly" `
  --mount "type=bind,source=$projectRoot\models\node-c\current,target=/model,readonly" `
  --mount "type=bind,source=$runDir\sample.eve.json,target=/input.eve.json,readonly" `
  --mount "type=bind,source=$runDir,target=/output" `
  ddos-fl-laptop-node-a-ml:step1 `
  python3 -B /app/infer_eve.py `
  --eve /input.eve.json --model-dir /model `
  --output /output/predictions.jsonl --once `
  > (Join-Path $runDir 'inference.log')

python -B .\scripts\check_eve_model.py verify --run-dir $runDir
```

Kết quả ở `reports/node-c/eve-smoke/verification.json`: cần đủ số prediction/signature, model hash và xác suất khớp bản export đã lưu. `PASS integration` không yêu cầu mọi nhãn đều được dự đoán đúng; phải giữ nguyên lỗi đã biết. Không chạy append lại inference vào cùng output: dùng report folder mới nếu cần lặp và giữ bằng chứng trước. Bước này không gửi traffic mạng, không train hoặc chỉnh threshold; sau đó mới chuẩn bị dịch vụ LDAP/sensor live cho C.


### Node C: dịch vụ LDAP/UDP và kiểm tra query/reply

C dùng fixture LDAP tối giản trên UDP/389, phục vụ truy vấn rootDSE ẩn danh với filter `(objectClass=*)`, scope baseObject và các thuộc tính cố định của lab. Đây là một phần giao thức phục vụ kiểm tích hợp, không phải LDAP directory/Active Directory đầy đủ. Cách đóng gói phản hồi `SearchResultEntry` rồi `SearchResultDone` theo [Microsoft LDAP Search Over UDP](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/3fad0ec9-414c-432a-ba0b-837c74091dd6), với BER từ [RFC 4511](https://www.rfc-editor.org/rfc/rfc4511.html). Không suy ra LDAP reflection hoặc DDoS từ bài kiểm này.

Source gồm `scripts/ldap_protocol.py` dùng chung để mã hóa/đọc thông điệp, `node-c/ldap_server.py` phục vụ rootDSE và `scripts/node-c/benign_traffic.py` gửi đúng10query, nghỉ0,2giây giữa query, deadline15giây. Client kiểm message ID, result code và giá trị thuộc tính trong phản hồi. Không chỉ kiểm port389 hoặc echo payload.

Dùng image sensor sẵn có, không cần build thêm. Chạy tại root dự án:

```powershell
docker compose -p ddos-fl-laptop -f compose.node-c-live.yaml config --quiet
docker compose -p ddos-fl-laptop -f compose.node-c-live.yaml up -d --wait ldap-c
docker compose -p ddos-fl-laptop -f compose.node-c-live.yaml ps ldap-c
```

`ldap-c` cần trạng thái `healthy`. Network `ddos-fl-laptop_site-c` là internal và service không publish port ra host. Compose C chính cũng include file live này; trainer chỉ chạy khi gọi rõ service/profile tools. Vì A/B/C dùng các file Compose riêng trong cùng project, cảnh báo orphan có thể xuất hiện; giữ các container đó, không dùng `--remove-orphans`.

Gửi10truy vấn hợp lệ từ container tạm trong đúng mạng C:

```powershell
$projectRoot = (Get-Location).Path
docker run --rm `
  --network ddos-fl-laptop_site-c --memory 64m --cpus 0.25 `
  --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges `
  --mount "type=bind,source=$projectRoot\scripts,target=/app,readonly" `
  ddos-fl-laptop-node-a-sensor:step1 `
  python3 -B /app/node-c/benign_traffic.py

docker compose -p ddos-fl-laptop -f compose.node-c-live.yaml logs --tail 15 ldap-c
```

Cần `requests:10`, `successful:10`, `errors:[]`; mỗi query trong cấu hình hiện tại gửi77byte, nhận91byte, message ID khớp, result code0. Log server có `rootdse_search` với IP/port của client. Bài kiểm ban đầu đã đạt10/10; bằng chứng tại `reports/node-c/ldap-service-smoke-01/verification.json` trên máy thực hiện. Báo cáo không được đưa vào Git.

Mốc query/reply ban đầu chỉ xác minh dịch vụ LDAP. Phần dưới hướng dẫn gắn Suricata để ghi flow; model inference là bước tiếp theo. Không train lại hoặc thay threshold từ kết quả smoke.


### Node C: Suricata live ghi flow LDAP

`compose.node-c-live.yaml` hiện có `sensor-c` dùng chung network namespace với `ldap-c`, bắt trên `eth0` và ghi `data/node-c/live/eve/{eve.json,suricata.log}`. Sensor dùng image Suricata hiện có, giới hạn768MiB/1CPU; không mount dataset hoặc model. Healthcheck yêu cầu engine đã khởi động và EVE tiếp tục cập nhật.

Chuẩn bị thư mục output và khởi động riêng sensor C:

```powershell
New-Item -ItemType Directory -Force -Path .\data\node-c\live\eve | Out-Null
docker compose -p ddos-fl-laptop -f compose.node-c-live.yaml config --quiet
docker compose -p ddos-fl-laptop -f compose.node-c-live.yaml up -d --wait sensor-c
docker compose -p ddos-fl-laptop -f compose.node-c-live.yaml ps ldap-c sensor-c
```

Khi cả hai service healthy, chạy lại lệnh gửi10query ở phần trước. Flow UDP chỉ được ghi sau khi hết timeout, vì vậy chờ khoảng30–45giây hoặc lâu hơn nếu hệ thống bận, rồi xem các bản ghi flow mới nhất:

```powershell
Get-Content .\data\node-c\live\eve\eve.json -Tail 200 |
  Select-String -Pattern '"event_type"\s*:\s*"flow"' |
  Select-Object -Last 10 |
  ForEach-Object { $_.Line | ConvertFrom-Json } |
  Select-Object flow_id,src_ip,src_port,dest_ip,dest_port,proto,
    @{n='to_server';e={$_.flow.pkts_toserver}},
    @{n='to_client';e={$_.flow.pkts_toclient}}
```

Đối chiếu IP/port và thời gian với JSON sender, không chỉ đếm các flow bất kỳ trong EVE. Trong bài kiểm ban đầu:10query thành công, đủ10flow UDP, mỗi flow1gói tới server và1gói trả về,119/133byte tương ứng (payload77/91byte cộng Ethernet/IPv4/UDP). Client đã kiểm cấu trúc LDAP/message ID/thuộc tính; Suricata bản hiện tại ghi `app_proto:failed`, vì vậy không dùng trường này để khẳng định parser đã nhận diện LDAP. Chín feature `flow-v2` vẫn tính hợp lệ từ counter và thời gian của EVE.

Bằng chứng cố định tại `reports/node-c/ldap-sensor-smoke-01/{sender.json,verification.json,matched.eve.jsonl,flow-features.json}`. Trong khoảng kiểm tra, kernel drops/capture errors/decoder invalid không tăng. Các container A/B và service LDAP C không bị recreate/restart, model C giữ nguyên hash. Mốc sensor này chỉ kiểm thu thập flow của traffic benign có kiểm soát. Phần dưới ghi cách nối shared inference với model `models/node-c/current`; chưa kiểm tấn công LDAP.


### Node C: dự đoán live từ EVE bằng model current

`inference-c` trong `compose.node-c-live.yaml` dùng shared `scripts/infer_eve.py` và image ML sẵn có. Container không có mạng, chỉ đọc source chung, model `models/node-c/current` và EVE C; ghi `data/node-c/live/predictions/predictions.jsonl`. Không mount dataset hoặc dữ liệu A/B. Model không được fit lại trong inference.

Chuẩn bị output và khởi động:

```powershell
New-Item -ItemType Directory -Force -Path .\data\node-c\live\predictions | Out-Null
docker compose -p ddos-fl-laptop -f compose.node-c-live.yaml config --quiet
docker compose -p ddos-fl-laptop -f compose.node-c-live.yaml up -d --wait inference-c
docker compose -p ddos-fl-laptop -f compose.node-c-live.yaml logs --tail 5 inference-c
```

Lúc bắt đầu, log cần có `status:ready`, `model_id:node-c-laptop-local-only-pilot`, đúng SHA256 weights trong model contract và `mode:follow`. `ldap-c`/`sensor-c` phải healthy, inference chạy liên tục. Chế độ `--follow --start-at-end` chỉ theo dõi flow ghi mới sau khi tiến trình bắt đầu; không tự chấm toàn bộ EVE lịch sử. Chạy lại lệnh gửi10query LDAP ở trên sau khi inference ready.

Chờ flow UDP hết timeout và xem prediction:

```powershell
Get-Content .\data\node-c\live\predictions\predictions.jsonl -Tail 10 |
  ForEach-Object { $_ | ConvertFrom-Json } |
  Select-Object flow_id,probability_attack,threshold,prediction,
    seconds_from_flow_end_to_score,model_id
```

Prediction không chứa label của scenario. Muốn đối chiếu phải ghép query với EVE bằng IP/port/thời gian, rồi ghép prediction bằng `event_signature_sha256` và kiểm model hash; không chỉ dựa vào10dòng cuối. `probability_attack` so với threshold0,5 quyết định nhãn dự đoán; đây không phải accuracy.

Bài kiểm live ban đầu đạt10query/10flow/10prediction khớp signature, cả10dự đoán benign, p_attack khoảng0,405140–0,405143. Tính lại batch từ đúng EVE/model có sai số tối đa1,67e-16; không fit/tune. Delay cuối flow→score31,03–40,42giây (trung bình35,17giây) gồm thời gian Suricata đợi flow hết timeout, không phải thời gian model tính toán riêng. Kernel drops/capture errors/decoder invalid không tăng. Bằng chứng tại `reports/node-c/ldap-live-smoke-01/{verification.json,matched.eve.jsonl,matched.predictions.jsonl,numeric-verification.json}` trên máy kiểm tra.

Kết quả này xác minh pipeline live với10query benign có kiểm soát, chưa đánh giá tấn công LDAP, tổng quát hóa hoặc FL. Baseline test đầy đủ và lỗi attack có gói trả về đã biết vẫn giữ nguyên.

Model được nạp một lần khi inference khởi động. Sau khi train lại thành công vào cùng thư mục current, tạo lại riêng inference C để nạp bộ weights mới và cập nhật bind mount:

```powershell
docker compose -p ddos-fl-laptop -f compose.node-c-live.yaml up -d --no-deps --force-recreate inference-c
```

Kiểm lại log ready/model hash trước khi gửi traffic mới. Không cần tạo model v2/v3 hoặc đổi output path.


## FL bước 1: cấu hình chung và kiểm tra đầu vào

`config/fl/fedavg.json` khai báo hợp đồng MLP/feature, lịch smoke1/pilot5/main50round, local1epoch,3client A/B/C, trọng số FedAvg theo số dòng train và mapping đường dẫn baseline/split. Dự kiến `fl-client-a/b/c` nằm trong file Compose của từng node, profile `fl`; `compose.fl.yaml` sẽ chứa server và mạng FL chung. Mốc bước1 chỉ tạo cấu hình và preflight; image runtime Flower được chuẩn bị ở bước2 bên dưới. Các service FL chưa được tạo.

Chạy từ root dự án bằng Python trên Windows, không cần NumPy hoặc Flower trên host:

```powershell
python -B .\scripts\check_fl_inputs.py
```

Cần thấy `result: PASS FL input preflight`, `total_train_rows:114301` với bộ dữ liệu hiện tại và `cross_partition_row_and_group_overlap:false`. Script kiểm hash config/manifest/CSV/model artifacts, schema, labels/counts, feature hữu hạn, transform, kiến trúc và các tensor float64 hữu hạn; kiểm không giao row UID hoặc connection group giữa chín tập train/validation/test A/B/C. Lưu ý: cùng group có thể có nhiều observation trong cùng một tập; đó không phải giao giữa các tập.

Script chỉ đọc dữ liệu, không fit model, không đánh giá xác suất mới hoặc chọn hyperparameter bằng test. Đây là công cụ kiểm tra trên host, không phải FL Server chứa dữ liệu ba node. Test được kiểm hash/identity/schema cho provenance, không dùng để train hoặc chọn checkpoint. Giữ nguyên class_balanced ở A/C và class_and_attack_response ở B; local sample_weight khác với trọng số FedAvg. Đường dẫn A vẫn dùng baseline hiện có; không cần di chuyển model để theo cấu hình.

Muốn lưu một báo cáo mới dưới reports/fl:

```powershell
python -B .\scripts\check_fl_inputs.py --output reports/fl/preflight.json
```

Output đã tồn tại thì script dừng để giữ bằng chứng; bỏ `--output` để chạy kiểm lại trên console. Bản kiểm ban đầu đã đạt, báo cáo tại reports/fl/preflight.json. Dữ liệu/model được ghim hash trong config; nếu chủ động thay inputs cần kiểm lại provenance và cập nhật cấu hình, không bỏ qua lỗi hash để chạy tiếp. `PASS` chưa chứng minh Flower đã được cài, client kết nối, FedAvg hoạt động hoặc model hội tụ. Bước tiếp theo là image/runtime FL với phiên bản được ghim sau kiểm tương thích.


## FL bước 2: build image Flower dùng chung

Image `ddos-fl-laptop-fl:step1` kế thừa image ML hiện có, thêm [Flower1.43.0](https://pypi.org/project/flwr/1.43.0/). Giữ NumPy2.4.3/scikit-learn1.8.0/SciPy1.18.1 và các package ML nền. `fl/requirements.txt` ghim57package runtime/ML đã giải trên Linux/Python3.13; không cài extra simulation/Ray. Dockerfile chỉ copy dependency list và runtime checker, không copy dataset/model vào image. Image này sẽ dùng cho server và ba client ở các bước sau.

Sau khi đã build image ML ở phần cài đặt, chạy tại root dự án:

```powershell
docker build --tag ddos-fl-laptop-fl:step1 --file .\fl\Dockerfile .
```

Build cần Internet để tải package. Bước kiểm tra chạy được khi tắt mạng và không mount dữ liệu:

```powershell
docker run --rm `
  --network none --memory 512m --cpus 0.75 `
  --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges `
  ddos-fl-laptop-fl:step1
```

Lệnh mặc định chỉ chạy `fl/check_runtime.py`, rồi container tự xóa. Cần thấy `result:PASS FL runtime image`, `pip_check:PASS`, versions flwr1.43.0/numpy2.4.3/scikit-learn1.8.0, `numpy_arrayrecord_roundtrip:true`. Script kiểm import ServerApp/ClientApp/FedAvg, CLI executables, support sample_weight trong MLP.partial_fit và chuyển mảng NumPy qua ArrayRecord không đổi dữ liệu. Không fit model hoặc mở server.

Có thể xem lệnh điều phối sẽ dùng ở bước sau:

```powershell
docker run --rm --network none ddos-fl-laptop-fl:step1 flower-superlink --help
docker run --rm --network none ddos-fl-laptop-fl:step1 flower-supernode --help
```

Dockerfile tắt telemetry và tự cài dependencies lúc chạy app; các dependency cần thiết được cài sẵn khi build. Image nền/tag và các container local hiện tại giữ nguyên. Báo cáo kiểm image thực tế ở reports/fl/runtime-image.json. Image đã có thư viện nhưng chưa có chương trình train FL, service Compose, mạng FL hoặc kết nối client/server. Bước tiếp theo sẽ chuẩn bị chương trình/app và runtime tối thiểu theo từng phần, client nằm trong Compose của node tương ứng.


## FL bước 3: bộ xử lý MLP dùng chung cho client/server

`fl/mlp_adapter.py` giữ hợp đồng13→32→16→1 và dùng lại transform, portable predictor, cách cân mẫu và metric từ scripts chung. Module chưa kết nối mạng hoặc đọc dataset; nó nhận các mảng được truyền vào. Các thao tác gồm khởi tạo global weights chung theo seed, kiểm sáu tensor hệ số/bias, nạp weights không fit giả, train một local update và đánh giá không fit.

Mỗi lần `train_round` tạo estimator/Adam mới, nạp đúng global weights rồi gọi partial_fit theo local_epochs. Các epoch bên trong một vòng dùng cùng optimizer; đầu vòng sau reset optimizer theo cấu hình. A/C dùng class_balanced; B dùng class_and_attack_response, tính weights chỉ từ labels/data train truyền vào. `num_examples` là số dòng train thật, không nhân local_epochs hoặc lấy tổng sample_weight. Mảng global đầu vào không bị sửa tại chỗ. Hash tensor chuẩn hóa dùng kiểm chu trình khác với SHA256 của file weights.npz khi export.

Để không dùng bước train giả lúc nạp weights, adapter có một đoạn khởi tạo nội bộ được khóa cho scikit-learn1.8.0; không tự nâng phiên bản mà bỏ kiểm tra tương thích. Chưa lưu checkpoint hoặc thay model local trong bước này.

Kiểm tra bằng256dòng dữ liệu giả trong Docker, không cần build lại image:

```powershell
$projectRoot = (Get-Location).Path
docker run --rm `
  --network none --memory 512m --cpus 0.75 `
  --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges `
  --mount "type=bind,source=$projectRoot\fl,target=/app/fl,readonly" `
  --mount "type=bind,source=$projectRoot\scripts,target=/app/scripts,readonly" `
  --mount "type=bind,source=$projectRoot\config\fl,target=/app/config/fl,readonly" `
  ddos-fl-laptop-fl:step1 `
  python3 -B /app/fl/check_mlp_adapter.py
```

Cần `result:PASS FL MLP adapter`, `initialization_without_fit:true`, `optimizer_reset_each_round_verified:true` và `flower_array_roundtrip:true`. Checker xác minh initialization tái lập/seed khác đổi weights, nạp chính xác weights dù local seed khác, portable inference khớp sklearn, Flower ArrayRecord không đổi tensor, cập nhật một batch khớp gradient/Adam tính độc lập và round2 nhận global mới/reset moment. Đồng thời kiểm output count/weighting A/B/C, evaluation không đổi weights và từ chối tensor sai shape/dtype/NaN/thiếu mảng.

Lần kiểm ban đầu đạt993tham số, portable error0, gradient/Adam error tối đa6,94e-17. Bằng chứng tại reports/fl/mlp-adapter.json. Đây là kiểm thuật toán bằng dữ liệu giả; không mount dataset hoặc baseline A/B/C, không chạy federation hoặc chứng minh chất lượng model. Các file Python được mount read-only nên chưa cần thêm vào image; bước tiếp theo mới chuẩn bị ClientApp đọc đúng train/validation của node và ServerApp điều phối FedAvg.


## FL bước 4: ClientApp dùng chung cho A/B/C

`fl/client_app.py` là một Flower1.43 ClientApp dùng chung; node-id và project-root lấy từ cấu hình SuperNode cục bộ. Khi import, module chỉ đăng ký handler, không mở kết nối hoặc tự train. `fl/local_data.py` kiểm manifest/schema/hash và chỉ đọc đúng train.csv/validation.csv của node. Ba service client sẽ được đặt trong Compose A/B/C ở bước tích hợp sau; bước này chưa thêm service hoặc chạy federation.

Ba thao tác đã chuẩn bị:

| Message | Client thực hiện | Phản hồi |
|---|---|---|
| query.properties | Kiểm config/manifest của node, không đọc CSV | ID, schema/hash, cách cân mẫu, số dòng train/validation khai báo |
| train | Kiểm global weights/hash; đọc train.csv và gọi shared MLP adapter | Weights cập nhật, số dòng train thật, loss/thời gian và metadata đối chiếu |
| evaluate | Đọc validation.csv, đánh giá global weights nhận được, không fit | Validation loss/BA/F1/recall/FPR, confusion counts, attack response subgroup counts |

Client không nạp baseline model, không đọc test.csv hoặc dữ liệu node khác. Eval sau mỗi round dùng validation; đánh giá test sẽ là job riêng sau khi chọn model. Weights sáu tensor được đọc theo key0..5, không phụ thuộc thứ tự map. Phản hồi không chứa từng dòng dữ liệu hoặc prediction theo flow.

Hợp đồng message dành cho bước viết ServerApp: content train/evaluate gồm ArrayRecord `arrays` và ConfigRecord `config`; config có `schema-version`, `fl-config-sha256`, `server-round`, `parameters-sha256`, và có thể có `local-epochs` đúng giá trị đã chốt. query.properties chỉ có config với schema-version/fl-config-sha256. Đường dẫn, node-id, split hoặc hyperparameter khác không được server override qua message. Config hash là SHA256 của file config; parameter hash là canonical tensor hash từ adapter, không phải hash NPZ.

Chạy kiểm bằng dữ liệu giả, không cần build lại image:

```powershell
$projectRoot = (Get-Location).Path
docker run --rm `
  --network none --memory 512m --cpus 0.75 `
  --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges `
  --mount "type=bind,source=$projectRoot\fl,target=/app/fl,readonly" `
  --mount "type=bind,source=$projectRoot\scripts,target=/app/scripts,readonly" `
  --mount "type=bind,source=$projectRoot\config\fl,target=/app/config/fl,readonly" `
  ddos-fl-laptop-fl:step1 `
  python3 -B /app/fl/check_client_app.py
```

Cần `result:PASS FL ClientApp`. Với mỗi node giả, checker tạo256train/64validation và một test.csv bị cấm đọc trong /tmp, dispatch message Flower trực tiếp (metadata giả, không chạy network runtime), kiểm properties/train/evaluate/round2, đúng số mẫu và trọng số so với adapter. Guard theo dõi file access đảm bảo train chỉ đọc train, evaluate chỉ đọc validation, không đọc test/node khác/baseline; evaluate không gọi train. Có39case từ chối sai hash/schema/epoch/round hoặc đường dẫn và server override không hợp lệ. Checker còn cố đảo thứ tự array map để kiểm decoding theo key.

Báo cáo kiểm thực tế tại reports/fl/client-app.json. Đây là kiểm chức năng bằng files/message giả, chưa kiểm kết nối SuperNode→SuperLink, app bundle hoặc huấn luyện trên dataset thật. Bước tiếp theo: ServerApp FedAvg tương thích hợp đồng message này, sau đó mới ghép Docker/Compose và chạy một vòng kiểm thử.


## FL bước 5: ServerApp FedAvg và checkpoint global

`fl/server_app.py` đăng ký Flower ServerApp, khởi tạo một global MLP chung và dùng `StrictFedAvg`, lớp kế thừa [FedAvg của Flower](https://flower.ai/docs/framework/main/en/ref-api/flwr.serverapp.strategy.FedAvg.html). Server chỉ đọc config FL, không đọc dataset/EVE/PCAP hoặc baseline của node. Source chưa được đóng gói thành app bundle hay đưa vào service Compose trong bước này.

Trước train, server đợi đúng ba SuperNode và query.properties để lập mapping transportID→A/B/C; kiểm nodeID duy nhất, hash config/manifest và chính sách cân mẫu. Mỗi round yêu cầu đủ3train reply và3validation reply đúng schema/hash/round/số mẫu; weights phải đủ6tensor float64 đúng shape và hữu hạn. Thiếu, trùng, lỗi, sai count hoặc sai global hash làm run dừng, không lặng lẽ gộp phần client còn lại. Phép gộp model dùng implementation Flower FedAvg với num-examples là số dòng train thật.

Checkpoint chọn theo trung bình balanced accuracy validation của ba node (mỗi node một phiếu), hòa chọn round sớm. Báo cáo pooled cộng TN/FP/FN/TP rồi tính lại metric, không lấy trung bình tỷ lệ rồi gọi là pooled. Server kiểm tỷ lệ validation khớp confusion/subgroup counts. Không đưa test vào selection hoặc tự kết luận hội tụ từ số round.

Kiểm server bằng client giả, không cần build lại image:

```powershell
$projectRoot = (Get-Location).Path
docker run --rm `
  --network none --memory 768m --cpus 0.75 `
  --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges `
  --mount "type=bind,source=$projectRoot\fl,target=/app/fl,readonly" `
  --mount "type=bind,source=$projectRoot\scripts,target=/app/scripts,readonly" `
  --mount "type=bind,source=$projectRoot\config\fl,target=/app/config/fl,readonly" `
  ddos-fl-laptop-fl:step1 `
  python3 -B /app/fl/check_server_app.py
```

Cần `result:PASS FL ServerApp`, `weighted_fedavg_matches_reference:true`, `strict_three_clients_verified:true`, `two_round_clientapp_serverapp_integration:true` và `failed_run_preserves_previous_global_model:true`. Bài kiểm có18negative cases; dùng fake Grid push/pull và task identity/messageID giả cho Flower1.43. Tất cả files train/validation/checkpoint phục vụ bài kiểm nằm trong /tmp; không mount dataset/model thật. Server role có file access guard riêng để phát hiện đọc nhầm dữ liệu node.

Checker kiểm phép gộp với n=2/3/5 so phép tính độc lập, macro-node khác pooled khi kích thước validation khác nhau, tie checkpoint, hai round với ClientApp, nạp export bằng live inference runtime và hash tensor export khớp round được chọn. Nó còn kiểm run bị lỗi giữ nguyên global model cũ, run thành công seed mới thay cùng current mà không sinh model v2/v3. Bằng chứng thực tế ở reports/fl/server-app.json. Các số liệu synthetic chỉ xác minh chương trình, không phải accuracy DDoS hoặc bằng chứng networking.

Khi chạy qua deployment runtime ở bước sau, ServerApp dùng run-config `project-root` (mặc định /workspace), `num-rounds` (không vượt config.training.rounds) và `timeout-seconds` (mặc định300). Chỉ sau khi toàn bộ round yêu cầu hoàn tất train+validation hợp lệ, server mới publish bộ3file models/fl/current/{weights.npz,model.json,metrics.json} bằng cơ chế thay bundle an toàn. Baseline A/B/C giữ nguyên. History/trạng thái từng round lưu reports/fl/training.json; lock .server-run-lock chặn hai run ghi chung output. Run mới khởi tạo lại từ seed; bước này chưa có resume sau khi tiến trình bị tắt đột ngột.

History chứa identity/hash, metrics theo node, thời gian vòng, raw model array bytes và byte của cây object Flower đã serialize cho train/evaluate. Đây là byte logic, chưa đo HTTP/TLS/cache/network overhead hoặc discovery/app-bundle transfer. Lần kiểm hiện tại không tạo global model/report training thật trên host: mọi artifact mô phỏng ở /tmp bị xóa khi checker kết thúc.

Bước tiếp theo: đóng gói app chỉ gồm source/config, sau đó thêm fl-server vào compose.fl.yaml và fl-client-a/b/c trong Compose từng node (profile fl), rồi kiểm kết nối mạng và một round thật. Không chạy50round khi mới chỉ kiểm source.


## FL bước 6: đóng gói app và chuẩn bị Compose

Root `pyproject.toml` khai báo ServerApp/ClientApp và allowlist tệp cho Flower App Bundle (FAB). `fl/build_bundle.py` chỉ đọc đúng11tệp source/config đã duyệt, không duyệt thư mục dataset, rồi kiểm danh sách ZIP, giải nén/import hai app từ gói. FAB hiện khoảng75KB, gồm11tệp và .info/CONTENT, không có PCAP/EVE/CSV/weights hoặc báo cáo. Mặc định app là1round smoke; config/fl vẫn cho phép run chính tối đa50round khi chủ động chọn sau này. `local-lab` là nhãn publisher của bundle cục bộ; bước này không publish Flower Hub.

Theo bố trí đã chốt:

| File | Dịch vụ FL bổ sung |
|---|---|
| compose.fl.yaml | fl-server (SuperLink, subprocess ServerApp) |
| compose.node-a.yaml | fl-client-a (SuperNode, subprocess ClientApp A) |
| compose.node-b.yaml | fl-client-b (SuperNode, subprocess ClientApp B) |
| compose.node-c.yaml | fl-client-c (SuperNode, subprocess ClientApp C) |

Cả bốn dùng image ddos-fl-laptop-fl:step1 và profile fl; không tự chạy khi dùng profile tools hoặc chạy local pipeline. Không inherit worker mount của node A. Server chỉ có configfl read-only và runtime/model/report FL riêng; mỗi client chỉ có configfl và đúng3file train.csv/validation.csv/manifest.json của node read-only, runtime riêng writable. Không mount test, dataset thô, baseline hoặc Docker socket. Source sẽ được gửi qua FAB; không mount cả source/dataset vào server/client.

Mạng ddos-fl-laptop_federation được khai báo internal ở Compose server, không publish port ra host/LAN. Client dùng external:true để tham chiếu chính mạng do server tạo; external ở đây không có nghĩa kết nối Internet. Bốn service chỉ nối mạng federation, tách site-a/b/c. FLWR_HOME trỏ vào mount runtime riêng; server dùng SQLite ở runtime để lưu trạng thái Flower. Profile fl chưa đồng nghĩa đã train: SuperLink/SuperNode chỉ chạy app khi nhận lệnh submit run.

Chạy tại root dự án bằng Python trên Windows; không cần cài Flower/NumPy trên host hoặc rebuild image:

```powershell
python -B .\scripts\prepare_fl_deployment.py
```

Script sẽ kiểm lại inputs, tạo thư mục runtime/output, gọi container tạm networknone để build/kiểm FAB, lưu reports/fl/bundles/ddos-fl-laptop.fab, rồi chạy docker compose config cho từng file. Nó kiểm đúng image/profile/network/mount/access/identity, ghi reports/fl/deployment-check.json. Chạy lại được; bundle/report cố định chỉ được thay sau khi build/kiểm thành công. Không gọi compose up/run cho các service FL hoặc submit train. Việc kiểm dùng một container tạm để đóng gói; container đó tự xóa.

Cần thấy `result:PASS FL bundle and Compose`, `server_has_no_node_data_mounts:true`, `clients_mount_only_own_train_validation_manifest:true`, `services_started:false`, `training_started:false`. Bản kiểm ban đầu đạt; cấu hình các dịch vụ/mạng local trước đó đã đối chiếu giữ nguyên. File fl/connection.toml có kết nối CLI tên docker trỏ fl-server:8000; đã kiểm đọc được trong container networknone, chưa kiểm kết nối.

Không gộp các Compose node/server vào một lệnh nhiều -f: các node có tool service trùng tên và quy ước network ownership khác nhau. Bước khởi động sau sẽ tạo server/mạng trước, rồi gọi riêng từng Compose với đúng tên fl-client, giữ nguyên container orphan của node khác. Healthcheck hiện kiểm TCP runtime API; số client thực sự đăng ký và app execution sẽ được kiểm riêng ở bước sau.

Đây là chuẩn bị gói và cấu hình tĩnh, chưa xác minh startup bốn container, kết nối qua mạng hoặc chạy một round dataset thật. Bước tiếp theo là khởi động server/ba client và kiểm kết nối trước khi submit smoke1round. Không chạy50round ngay sau bước này.

Tham khảo [FAB allowlist](https://flower.ai/docs/framework/how-to-configure-pyproject-toml.html) và [Flower Configuration/FLWR_HOME](https://flower.ai/docs/framework/1.43/en/ref-flower-configuration.html). Runtime image vẫn ghim Flower1.43.0, và bundle dùng format0 được phiên bản này hỗ trợ; không tự thay license hoặc phiên bản model hiện có.


## FL bước 7: khởi động bốn dịch vụ và kiểm kết nối

Sau khi bước6 PASS, khởi động server trước để tạo mạng federation, rồi chỉ định đúng client ở từng Compose. Các lệnh này không submit app hoặc train:

```powershell
docker compose -p ddos-fl-laptop --profile fl -f compose.fl.yaml up -d --no-deps --wait fl-server

docker compose -p ddos-fl-laptop --profile fl -f compose.node-a.yaml up -d --no-deps --wait fl-client-a
docker compose -p ddos-fl-laptop --profile fl -f compose.node-b.yaml up -d --no-deps --wait fl-client-b
docker compose -p ddos-fl-laptop --profile fl -f compose.node-c.yaml up -d --no-deps --wait fl-client-c
```

Giữ nguyên cảnh báo orphan, không thêm --remove-orphans. Với explicit service và --no-deps, các lệnh không bật lại web/UDP/LDAP/sensor/inference local. FL train offline dùng CSV đã chuẩn bị nên không yêu cầu chạy lại Suricata để bắt đầu federation.

Kiểm kết nối thực bằng Python trên host:

```powershell
python -B .\scripts\check_fl_connection.py
```

Cần `result:PASS FL connectivity`, `online_clients:3`, cả4service running/healthy, `network_internal:true` và `runtime_mount_isolation_verified:true`. Ở mốc trước lần train đầu tiên cần `registered_runs:0`, `no_runs_registered:true`. Checker kiểm Docker inspect/health/image/network và mounts thực, gọi Flower CLI đọc server online list, đối chiếu ID online với SuperNode ID trong log A/B/C. Node ID là chuỗi số64bit do Flower cấp, không phải A/B/C cố định; sau khi restart có thể thay đổi. Không giả định thứ tự server list là thứ tự node.

Checker chỉ dùng container CLI tạm và không gửi run. Nó không start/stop/recreate các service. Sau các lần train sau này, registered_runs có thể lớn hơn0; kết nối vẫn PASS nếu các client còn online. Để lưu snapshot mới có thể dùng --output reports/fl/connectivity.json; file có sẵn thì giữ lại, bỏ --output để kiểm trên console.

Lần khởi động ban đầu đã kiểm đạt qua HTTP Control/Fleet API:4service healthy,3online ID khớp A/B/C,0run; mạng internal/không host ports và mount đúng. Bằng chứng reports/fl/connectivity.json, kèm startup audit trong cùng thư mục reports/fl. Model baseline, config và FAB hash không đổi; chưa tạo models/fl/current. Các container local cũ giữ nguyên trạng thái, không bị restart bởi bước này.

Có thể xem trạng thái/log khi cần:

```powershell
docker ps --filter label=com.docker.compose.project=ddos-fl-laptop
docker compose -p ddos-fl-laptop --profile fl -f compose.fl.yaml logs --tail 30 fl-server
docker compose -p ddos-fl-laptop --profile fl -f compose.node-a.yaml logs --tail 20 fl-client-a
```

Đây mới là kiểm runtime kết nối; app chưa được submit để chạy trên dữ liệu thật. Bước tiếp theo sẽ submit đúng1round smoke, kiểm global weights/validation/output và lỗi runtime nếu có, rồi mới cân nhắc pilot5round hoặc run chính. Không suy ra app đã train/hội tụ từ trạng thái healthy.


## FL bước 8: một vòng train thật và kiểm model global

Chỉ bắt đầu sau khi bước7 có đủ3client online. Chạy tại root dự án. Có thể kiểm đầu vào và gói app trước, không gửi run:

```powershell
python -B .\scripts\run_fl.py --rounds 1 --check-only
```

Cần `PASS FL submission inputs`, `training_started:false`. Lệnh dùng preflight trên host để kiểm tính toàn vẹn/không trùng partitions, rồi giải nén FAB đã kiểm hash trong container networknone. Preflight có đọc test để kiểm provenance/overlap; không tính metric test hoặc dùng test để train/chọn model.

Khi chủ động muốn train, lệnh sau tạo **một run mới từ seed chung**, không tiếp tục checkpoint trước. Không chạy lại nếu chỉ muốn xem kết quả run đã hoàn tất:

```powershell
python -B .\scripts\run_fl.py --rounds 1
```

Số vòng phải được ghi rõ; script không mặc định chạy50round. Nó kiểm kết nối, từ chối run đang hoạt động/lock output, chỉ mount FAB source-only, biên bản đóng gói và cấu hình kết nối vào container CLI tạm. Flower1.43 nhận đường dẫn source app: gói FAB được giải nén trong /tmp rồi gọi `flwr run ... docker --run-config num-rounds=1`. Container submit không mount dữ liệu train hoặc model. Không có cơ chế retry tự động; nếu mất phản hồi sau submit, kiểm run đang tồn tại trước khi gửi lại.

Phản hồi có `success:true` và `run-id` nghĩa là server đã nhận run, chưa có nghĩa train xong. Biên nhận được lưu cố định tại reports/fl/last-submission.json. Xem tiến trình trong reports/fl/training.json hoặc log fl-server. Khi `status:complete`, kiểm kết quả bằng:

```powershell
python -B .\scripts\check_fl_result.py
```

Cần `PASS FL trained checkpoint` và `run_status:finished:completed`. Checker đối chiếu số vòng, đủ A/B/C, số mẫu train thật, hash artifacts, quy tắc chọn checkpoint và trạng thái Flower. Sau đó ba container đánh giá độc lập, mỗi container chỉ mount validation/manifest của chính node và cùng global model read-only, networknone; không mount train/test. `fl/check_global_model.py` kiểm portable inference khớp sklearn và tính lại confusion/loss/BA/recall/FPR khớp validation của round được chọn, không fit. Lệnh check không train lại hoặc thay checkpoint. Có thể dùng `--output reports/fl/<ten-moi>.json` để lưu báo cáo mới, không ghi đè bằng chứng đã có.

Sau run thành công, output cố định là:

```text
models/fl/current/
├── weights.npz
├── model.json
└── metrics.json
```

Run thành công sau thay bộ current này; không tạo model v2/v3. Baseline local A/B/C giữ nguyên. Checkpoint chỉ publish sau đủ tất cả round yêu cầu, chọn mean balanced accuracy validation của ba node, hòa giữ round sớm. Chưa đưa global vào các dịch vụ inference live.

Lần kiểm thật đầu tiên ngày11/11/2026 đã hoàn tất đúng1round, mỗi node1local epoch, FedAvg theo số dòng train A68928/B11796/C33577. Run ID7941808649286261911, global weights SHA256 `cf9d41214902b2a7901f4b38378d3ef73c1de086c2fc7df7e63b94bb91aa7004`. Thời gian phần round khoảng24,77giây; toàn bộ ServerApp khoảng42,46giây. Đây là số đo của lần chạy này, không phải cam kết thời gian cho máy khác.

| Validation trên global sau round1 | Số dòng | Balanced accuracy | Recall attack | False positive rate |
|---|---:|---:|---:|---:|
| A | 59456 | 94,78% | 89,84% | 0,28% |
| B | 1436 | 65,74% | 33,74% | 2,26% |
| C | 33214 | 92,03% | 84,06% | 0,00% |

Mean balanced accuracy theo node là84,18%. Kết quả xác nhận luồng client→FedAvg→validation→export hoạt động; recall B còn thấp và chưa đủ bằng chứng hội tụ hoặc tốt hơn local baseline. Chưa đánh giá test global hoặc dữ liệu ghi độc lập. Bước tiếp theo là pilot5round có chủ đích, xem diễn biến validation và checkpoint trước khi chạy dài hơn; không tự tăng số vòng hay chỉnh threshold từ kết quả test.

Bằng chứng máy hiện tại nằm ở reports/fl/training.json, smoke-one-round.json và smoke-one-round-audit.json. Model export đã được chấm lại trên cả3validation, portable/sklearn error0. Audit xác nhận14hash config/FAB/artifacts baseline không đổi và13container hiện có giữ nguyên ID/trạng thái/start/finish/restart;4service FL vẫn healthy. Bộ scripts kiểm và README thuộc source; dataset/model/reports là artifacts riêng được Git bỏ qua.


## FL bước 9: pilot 5 vòng và xem diễn biến validation

Sau smoke1round PASS, chạy pilot với số vòng ghi rõ. Đây là run mới khởi tạo lại từ seed chung; không cộng thêm5vòng vào checkpoint smoke:

```powershell
python -B .\scripts\run_fl.py --rounds 5
```

Lệnh trả biên nhận sau submit; đợi reports/fl/training.json có status complete rồi kiểm checkpoint bằng `python -B .\scripts\check_fl_result.py`. Nếu chỉ muốn xem lại model hiện có thì dùng lệnh check, không gửi lại run. Sau thành công, global/current được thay bằng checkpoint được chọn; baseline A/B/C giữ nguyên. Không cần build lại image, FAB hoặc chạy lại Suricata khi source/config/dataset không đổi.

Lần pilot ngày11/11/2026 đã hoàn tất5/5vòng qua cả3client, mỗi node1epoch/vòng, run ID6618119074863593551. Giữ nguyên seed, manifests,9features, transform, kiến trúc, threshold0,5 và FedAvg theo số dòng train. Tổng phần xử lý5round khoảng94,92giây trong lần đo này. Kết quả validation:

| Vòng | Mean balanced accuracy theo node | Recall tấn công B | Validation loss B |
|---|---:|---:|---:|
| 1 | 84,184242% | 33,74% | 1,0570 |
| 2 | 86,745989% | 42,30% | 1,7027 |
| 3 | 86,745989% | 42,30% | 2,2546 |
| **4 — được chọn** | **86,746553%** | **42,30%** | **2,5427** |
| 5 | 86,746271% | 42,30% | 3,0156 |

Server chọn vòng4 theo balanced accuracy trung bình cao nhất. Vòng4 và5 rất sát nhau nhưng không bằng nhau; quy tắc giữ vòng sớm chỉ dùng khi điểm bằng nhau. Global weights hiện tại SHA256 `40852d1ec9497aa9bd6849eecb91ecb04f863ec2264c13203d2db7976fde62c7`.

| Validation của checkpoint vòng4 | Balanced accuracy | Recall attack | False positive rate |
|---|---:|---:|---:|
| A | 99,85% | 99,98% | 0,28% |
| B | 70,02% | 42,30% | 2,26% |
| C | 90,37% | 84,06% | 3,33% |

Mean BA tăng2,56điểm phần trăm so vòng1, nhưng cải thiện khác nhau giữa các node. B vẫn bỏ sót701/1215attack validation:230/626mẫu không có gói chiều về và471/589mẫu có gói chiều về. Recall B không tăng từ vòng2đến5, trong khi loss tăng; chưa thể kết luận đã hội tụ hoặc chỉ cần tăng số vòng là khắc phục được. C có4false positives trên120benign, vì vậy FPR3,33% được tính từ số mẫu benign ít.

Trên cùng validation1436dòng với manifest đã pin, baseline local B đã ghi recall76,79% và BA86,81%; global vòng4 đạt recall42,30% và BA70,02%. Đây là đối chiếu kết quả trên cùng split, không phải benchmark công bằng về lượng huấn luyện vì local/global có ngân sách train khác nhau. Nguyên nhân có thể liên quan dữ liệu khác phân phối và ảnh hưởng của từng client; pilot này chưa chứng minh nguyên nhân. Bước tiếp theo là phân tích lỗi B và đối chiếu local/global trước khi quyết định thay đổi thí nghiệm hoặc chạy dài hơn.

Kiểm checkpoint/export thực tế đã PASS: chấm lại từng validation trong container riêng, portable/sklearn error0 và confusion/metrics khớp vòng4. Audit xác nhận14hash config/FAB/baselineartifacts và13container giữ nguyên,4serviceFL healthy. Không đánh giá test global, chỉnh threshold, phát traffic hoặc đưa global vào inference live trong pilot này.

Evidence được lưu cố định tại reports/fl/pilot-five-rounds.json, pilot-five-rounds-training.json, pilot-five-rounds-audit.json và pilot-five-rounds-diagnostics.json. Báo cáo smoke1round trước đó vẫn được giữ riêng; models chỉ có một thư mục global/current.


## FL bước 10: đánh giá global trên test A/B/C và so với local

Đây là job đánh giá offline tách khỏi FL ClientApp. Chạy sau khi đã chốt checkpoint bằng validation, không dùng test để chọn lại round hoặc threshold:

```powershell
python -B .\scripts\evaluate_fl_test.py
```

Lệnh đóng băng hash config/manifest/test/model trong plan trước khi chấm. Mỗi node có một container networknone, chỉ đọc test.csv và manifest của chính node, global đã chốt cùng baseline local tương ứng. Train/validation và dữ liệu node khác không được mount. Script không yêu cầu các dịch vụ FL đang chạy, không gửi Flower run, không fit hoặc sửa model. Ngưỡng0,5 lấy từ hai bộ model cố định.

`fl/evaluate_test.py` dùng portable inference và các hàm metric chung; `fl/check_test_evaluation.py` kiểm bằng4mẫu giả với confusion tính tay, cấm fit và truy cập train/validation/node khác, từ chối sai hash/threshold/checkpoint/path. `scripts/evaluate_fl_test.py` điều phối trên host, kiểm lại mọi metric phân loại bằng cách đếm độc lập từ predictions.csv rồi mới publish thư mục báo cáo. Các file dùng chung, không thêm bản riêng cho từng node.

Output mặc định:

```text
reports/fl/test-evaluation/
├── plan.json
├── summary.json
├── REPORT.md
├── comparison.csv
├── node-a/{metrics.json,predictions.csv}
├── node-b/{metrics.json,predictions.csv}
└── node-c/{metrics.json,predictions.csv}
```

Nếu output đã tồn tại, script giữ kết quả cũ. Kiểm lại model/input/report và confusion/metric từ các dự đoán đã lưu bằng:

```powershell
python -B .\scripts\evaluate_fl_test.py --verify
```

Cần `PASS frozen test evaluation artifacts`. Lệnh verify không chấm lại hoặc train. Có thể chỉ định --output tới một thư mục mới dưới reports/fl khi chủ động thực hiện đánh giá khác; không sửa checkpoint sau khi xem test rồi gọi đó là đánh giá test độc lập. Artifacts test nằm trong reports, bộ model và báo cáo training giữ nguyên. `test_evaluated:false` trong metrics của model mô tả giai đoạn train; job riêng này ghi `test_evaluated:true` trong summary.json.

Ngày11/11/2026 đã chấm104742dòng test: A67226 (66772attack/454benign), B4317 (4152attack/165benign), C33199 (33081attack/118benign). Global chốt vòng4 của run6618119074863593551, weights SHA256 `40852d1ec9497aa9bd6849eecb91ecb04f863ec2264c13203d2db7976fde62c7`.

| Node | Model | Precision attack | Recall attack | F1 attack | Balanced accuracy | FPR |
|---|---|---:|---:|---:|---:|---:|
| A | Global | 99,99% | 99,99% | 99,99% | 99,33% | 1,32% |
| A | Local | 100,00% | 99,99% | 100,00% | 100,00% | 0,00% |
| B | Global | 99,94% | 41,57% | 58,72% | 70,48% | 0,61% |
| B | Local | 99,95% | 99,23% | 99,59% | 99,01% | 1,21% |
| C | Global | 99,91% | 83,97% | 91,25% | 81,39% | 21,19% |
| C | Local | 99,98% | 99,96% | 99,97% | 96,59% | 6,78% |

Số phần trăm làm tròn2chữ số; xem confusion/raw metrics để tránh hiểu100,00% là không có lỗi. Confusion matrix theo thứ tự `[[TN, FP], [FN, TP]]`:

| Node | Global | Local |
|---|---|---|
| A | [[448,6],[6,66766]] | [[454,0],[6,66766]] |
| B | [[164,1],[2426,1726]] | [[163,2],[32,4120]] |
| C | [[93,25],[5302,27779]] | [[110,8],[14,33067]] |

Mean balanced accuracy theo node của global là83,74%, bộ3local là98,53%. Pooled global BA94,11%, recall92,56% không thay thế các số theo node: A có nhiều mẫu hơn và làm số pooled cao. Aggregate local chỉ gộp prediction của ba model local trên node của mình, không phải một model local chung.

Đánh giá đã hoàn tất, nhưng chưa thể coi global đạt chất lượng triển khai: B bỏ sót2426attack; C bỏ sót5302attack và báo nhầm25/118benign. Không tự tune từ kết quả này. Local/global có lượng huấn luyện khác nhau nên đây là đối chiếu trên cùng test, chưa cô lập hiệu quả FL. Các test vẫn thuộc recording pilot hiện có; A/C đã được xem trước đó khi phát triển local, không phải recording/ngày độc lập.

Bằng chứng tại thư mục output, gồm REPORT.md dễ đọc, comparison.csv để tổng hợp và predictions.csv có row_uid/nhãn thật/xác suất/dự đoán cả hai model. Audit máy hiện tại thêm audit.json: toàn bộ global/local files, config/manifest/test hash và13container giữ nguyên;4service FL healthy. Bước này hoàn thành đánh giá test offline, chưa chuyển global vào inference live.


## FL bước 11: chuẩn bị demo global tại node A

`compose.node-a-global.yaml` là override dùng cùng `compose.node-a-live.yaml`, chỉ đổi hai bind mount của service inference: `/model` đọc models/fl/current read-only, `/predictions` ghi vào data/node-a/live/predictions-global. Web, sensor, mạng site-a và code suy luận dùng lại bản local. Chọn override để chạy global, bỏ override để dùng lại baseline; hai lựa chọn dùng cùng service inference nên không chạy đồng thời hai model trong service đó.

Kiểm cấu hình và khả năng nạp global trước khi bật dịch vụ:

```powershell
python -B .\scripts\node-a\prepare_global_demo.py
```

Cần `PASS node A global demo preparation`, đúng hash checkpoint đang chọn và `services_started:false`, `traffic_sent:false`. Script kiểm Compose hiệu lực đúng project/mount/access/network, giữ nguyên cấu hình gốc và model files; tạo thư mục predictions-global nếu chưa có. Một container tạm networknone nạp global bằng infer_eve.py và chấm một EVE flow giả, output chỉ nằm trong /tmp container rồi tự xóa. Không dùng EVE thật, mở socket hoặc tạo prediction demo giả trên host. Báo cáo chuẩn bị lưu reports/node-a/global-demo-preparation.json và được cập nhật khi kiểm lại thành công.

Khi chuẩn bị PASS, bước khởi động demo là:

```powershell
docker compose -p ddos-fl-laptop -f compose.node-a-live.yaml -f compose.node-a-global.yaml up -d --wait web sensor inference

docker compose -p ddos-fl-laptop -f compose.node-a-live.yaml -f compose.node-a-global.yaml logs --tail 20 inference
```

Giữ cảnh báo orphan, không thêm --remove-orphans: các container B/C/FL thuộc cùng project nhưng không nằm trong hai file chọn cho demo A. Không dùng compose down cho bước này. Khởi động chỉ gồm ba dịch vụ node A, không submit FL hoặc train. Nếu inference được đổi từ local sang global, Compose sẽ tạo lại service inference theo mounts đã chọn.

Trong log inference cần thấy `status:ready`, `model_id:laptop-fedavg-mlp`, `threshold:0.5`, `mode:follow` và weights_sha256 đúng model đang demo. Với checkpoint hiện tại, SHA256 là `40852d1ec9497aa9bd6849eecb91ecb04f863ec2264c13203d2db7976fde62c7`. Inference nạp model lúc khởi động; nếu thay global/current sau đó thì cần kiểm/nạp lại trước khi phát traffic demo.

Kết quả global sẽ nằm tại data/node-a/live/predictions-global/predictions.jsonl. --start-at-end chỉ theo dõi các dòng EVE mới; sau khi ba dịch vụ sẵn sàng mới phát request/probe. Cần đợi Suricata xuất completed flow rồi mới có prediction. Thư mục predictions cũ của local được giữ riêng.

Để quay về inference local, dùng lại compose.node-a-live.yaml không kèm override và khởi động rõ service inference:

```powershell
docker compose -p ddos-fl-laptop -f compose.node-a-live.yaml up -d --no-deps inference
```

Lần chuẩn bị ngày11/11/2026 đã PASS qua Docker Compose thực và scorer trong image ML: nạp đúng global vòng4, flow giả đi qua trích đặc trưng→portable predictor→JSONL thành công. Hash cấu hình gốc/model và13container trước/sau giữ nguyên. Mốc source FL/test trước demo đã ở commit8b3ab82. Chưa bật dịch vụ hoặc phát traffic ở bước chuẩn bị này; kết quả chưa chứng minh bắt gói live hoặc chất lượng phát hiện DDoS. Bước kế tiếp mới khởi động node A, gửi request bình thường rồi SYN probe giới hạn trong mạng Docker lab và đối chiếu EVE/prediction.


## FL bước 12 · Demo global live tại node B và C

Khởi động từng node bằng file live và override global tương ứng.

```powershell
New-Item -ItemType Directory -Force -Path .\data\node-b\live\predictions-global, .\data\node-c\live\predictions-global | Out-Null

docker compose -p ddos-fl-laptop -f compose.node-b-live.yaml -f compose.node-b-global.yaml up -d --wait udp-b sensor-b inference-b
docker compose -p ddos-fl-laptop -f compose.node-c-live.yaml -f compose.node-c-global.yaml up -d --wait ldap-c sensor-c inference-c
```

Hai override mount `models/fl/current` ở chế độ chỉ đọc và ghi prediction vào thư mục của từng node. Đọc log inference để kiểm tra hash checkpoint sau khi khởi động. Chạy `benign_traffic.py` của từng node trong container trên mạng site nội bộ tương ứng rồi đối chiếu request, flow EVE và prediction theo cổng nguồn, thời gian, chữ ký sự kiện và hash model.

Node B trả đủ 10 UDP echo và node C trả đủ 10 truy vấn LDAP rootDSE qua UDP. Global vòng 4 chấm cả 20 flow là `benign`. Khoảng từ lúc flow kết thúc tới lúc ghi prediction là 31,33–40,72 giây tại B và 31,52–40,04 giây tại C trong lần kiểm này. Báo cáo nằm tại `reports/node-b/global-live-benign-check.json` và `reports/node-c/global-live-benign-check.json`.


### Node C: LDAP burst giới hạn cho demo local/global

`scripts/node-c/ldap_probe.py` phát traffic thật tới hostname cố định `ldap-c`, UDP/389, trên mạng Docker `ddos-fl-laptop_site-c`. Script dùng codec LDAP chung, gửi tối đa 100 truy vấn rootDSE qua một socket, tối đa 20 gói/giây và có ngân sách gửi 10 giây. Nó kiểm tra message ID, BER/result code và thuộc tính phản hồi. Trước khi gửi, đích phải là host riêng khác trong subnet của `eth0`; script không có tham số đổi đích, số gói hoặc tốc độ.

Đây là kịch bản `bounded_ldap_burst` dùng ở lượt attack demo, chưa phải mẫu DrDoS_LDAP đã xác thực. Script không giả mạo IP hay thực hiện reflection, và không tự đặt nhãn ground truth là attack. Burst dùng cùng truy vấn hợp lệ như benign, nhưng tăng số lượng/nhịp và gom vào một socket. Dự đoán có thể là benign; không dùng kết quả này để tính recall tấn công dataset hoặc khẳng định gây quá tải. Model nhận các đặc trưng flow, không đọc trực tiếp payload LDAP.

Chỉ chạy lệnh dưới khi đã chủ động bật `ldap-c`, `sensor-c` và `inference-c` với model muốn demo, kiểm inference báo ready và đúng hash. Việc đặt `$mode` chỉ đặt tên thư mục báo cáo, không chuyển model. Không cần build lại image hoặc train lại. Chạy tại root dự án:

```powershell
$projectRoot = (Get-Location).Path
$mode = 'local' # Đổi thành global sau khi đã chọn Compose override global.
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$runDir = Join-Path $projectRoot "reports\node-c\ldap-probe-$mode-$stamp"
if (Test-Path -LiteralPath $runDir) { throw 'Report folder already exists' }
New-Item -ItemType Directory -Path $runDir | Out-Null

docker run --rm `
  --network ddos-fl-laptop_site-c --memory 64m --cpus 0.25 `
  --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges `
  --mount "type=bind,source=$projectRoot\scripts,target=/app,readonly" `
  --mount "type=bind,source=$runDir,target=/report" `
  ddos-fl-laptop-node-a-sensor:step1 `
  python3 -B /app/node-c/ldap_probe.py

if ($LASTEXITCODE -ne 0) { throw "Probe failed; inspect $runDir\sender.json" }
```

`sender.json` được tạo độc quyền, không ghi đè kết quả cũ. Kết quả mong đợi phía sender là `completed:true`, `packets_sent:100`, `valid_responses:100`, `errors:[]`. Các trường này xác minh gửi/nhận LDAP, chưa xác minh Suricata hoặc model. Báo cáo lưu IP/cổng nguồn, IP/cổng đích, thời gian và từng message ID để ghép với EVE. Lỗi gửi/nhận làm lệnh thoát khác 0 và vẫn giữ báo cáo đã thu được.

Chờ khoảng 30–45 giây hoặc lâu hơn nếu hệ thống bận để Suricata xuất flow UDP. Dùng IP/cổng và khoảng thời gian trong sender để tìm event flow mới ở `data/node-c/live/eve/eve.json`. Một socket thường tạo một flow gộp, không phải 100 prediction. Ghép flow với prediction qua chữ ký sự kiện và kiểm hash model. Prediction local nằm ở `data/node-c/live/predictions/predictions.jsonl`, global ở `data/node-c/live/predictions-global/predictions.jsonl`. Không chỉ lấy dòng cuối vì EVE có thể chứa các lượt demo trước.

Muốn lặp với model còn lại, chuyển inference bằng Compose như phần global, kiểm ready/hash, rồi chạy lại với `$mode` và thư mục report mới. Chưa có phép kiểm live được thực hiện khi bổ sung script; kiểm tra chuẩn bị chỉ dùng socket/clock/interface giả, không phát traffic hoặc thay model.


## Dashboard điều khiển demo trên Windows

Có thể xem thông số train bằng **TensorBoard trên Windows**, độc lập với Docker: cài một lần `powershell -ExecutionPolicy Bypass -File .\tools\tensorboard\setup.ps1`, rồi bấm **TensorBoard** trên dashboard để mở `http://127.0.0.1:6006`. Có lịch sử Local A/B/C theo epoch và FL theo vòng, loss/validation metrics/timing. Nhập lịch sử hiện tại không cần train lại; chỉ giữ lần Local mới nhất của từng node và lần FL mới nhất (tối đa 7 mục), các lần train sau thay biểu đồ cũ. Xem [tools/tensorboard/README.md](tools/tensorboard/README.md) về nguồn số liệu, cách đọc và giới hạn. Không cài TensorFlow hoặc đổi thuật toán/train image.

Dashboard chạy bằng Python trực tiếp trên máy, không dùng Docker cho web UI và không cần pip/npm. Tại root dự án chạy:

```powershell
python -B .\dashboard\app.py --open
```

Mở `http://127.0.0.1:8765`, hoặc double-click `dashboard/start.bat`. Có thể đổi cổng bằng `--port 8766`. Cần Docker Desktop đang chạy và các model/dataset đã chuẩn bị trước. Dashboard chỉ kiểm trạng thái lúc mở, không tự bật node, gửi traffic hoặc train.

UI có bật/tắt A/B/C, chọn và nạp Local/Global, gửi benign/probe giới hạn, bật/tắt bốn service FL, chọn số vòng và submit FL, log EVE/prediction/container cập nhật tự động, báo cáo live và tab test dataset đã lưu. Chọn Local/Global rồi bấm Bật/Nạp để áp dụng. Nút Chạy FL tạo run mới từ seed chung và có thể thay global/current sau thành công; inference cần nạp lại để dùng global mới. Không dừng FL trong lúc run còn hoạt động.

Phiên mới/Xóa màn hình chỉ làm mới phần hiển thị, giữ evidence. Xóa log live yêu cầu node đã dừng và chỉ xóa nội dung các file log của node, không xóa reports/fl, dataset hoặc model. Báo cáo burst live không được coi là attack recall có ground truth. Artifacts dashboard nằm trong reports/dashboard và runtime/dashboard, đã thuộc vùng Git ignore hiện có.

Xem [dashboard/README.md](dashboard/README.md) để biết cách dùng, giới hạn và lệnh kiểm tra bằng Docker/sender giả. Dừng dashboard bằng Ctrl+C không tự dừng lab.

Mỗi node có nút **Test dataset · Local vs Global** để chấm cả hai model trên cùng toàn bộ tập test riêng của node, không cần bật node hoặc nạp model live. Kết quả xuất hiện ở **Test có nhãn**: metrics, confusion matrix, bảng prediction có bộ lọc FP/FN và tải CSV/JSON. Worker Docker tạm không có mạng, không train/chỉnh ngưỡng hoặc ghi EVE. Các lượt có report/hash riêng trong `reports/dashboard/sessions`; báo cáo A/B/C cũ vẫn có lựa chọn riêng. Không chạy FL đồng thời khi đánh giá dataset. Kết quả từ tập test pilot đã xem không thay thế kiểm chứng traffic live hoặc đánh giá trên ngày ghi hình độc lập.

Hai nút **Attack từ …** trên mỗi node kiểm thử chéo. Ví dụ **Attack từ B** trên thẻ A dùng các dòng có nhãn `attack` trong `test.csv` của B để so sánh Local A với Global hiện tại. Tab **Test có nhãn** hiện số phát hiện, bỏ sót và recall của hai model. Chạy offline, không cần bật các node.
