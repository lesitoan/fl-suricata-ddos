# Suricata + Federated Learning Lab

Môi trường thực hành phát hiện DDoS trên một máy cá nhân: Suricata phân tích traffic, Python trích đặc trưng và mô hình MLP phân loại flow thành `benign` hoặc `attack`. Docker tách dịch vụ, sensor và chương trình suy luận để có thể tái lập môi trường.

**Bản hiện tại có node A local-only, pipeline train offline và dịch vụ UDP riêng cho node B.** Node B chọn model v2 để test, đã đánh giá trên train/validation; node C và FL Server/FedAvg chưa được triển khai trong bản cài này. Các lệnh bên dưới dành cho Windows PowerShell và Docker Linux containers.

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


### Node B: UDP burst probe có giới hạn

Bài này gửi 100 UDP datagram 64 byte, tối đa khoảng 20 gói/giây trong khoảng 5 giây, bằng một socket tới cố định `udp-b:9000` trên mạng internal `site-b`. Đây là synthetic burst nhỏ để kiểm tra pipeline/phân loại; chưa phải ground truth CIC-DDoS2019 hoặc phép đo DDoS gây quá tải. Dịch vụ echo vẫn phản hồi bình thường. Không thay model hoặc threshold để ép kết quả attack.

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

Verifier đợi tối đa 75 giây để flow hết timeout và prediction xuất hiện. Một socket thường tạo một aggregated flow/prediction, không phải 100 prediction. Đọc `packets_sent`, số gói Suricata bắt được, `sent_packet_count_matches_capture`, `probability_attack`, `threshold`, `prediction` trong `verification.json`. `MATCHED` nghĩa là đã ghép được pipeline, không tự khẳng định phát hiện DDoS thành công. Nếu prediction là benign, ghi nhận model không đánh dấu burst này là attack; không coi nhãn synthetic là bằng chứng attack thực tế.

`sender.json` ghi số gói/time/port; `flow.json`, `prediction.json`, `verification.json` lưu đối chiếu. Suricata không bắt buộc có event `alert`; ML dùng event `flow`. Script có count/nhịp/deadline cố định, không có tùy chọn đích bên ngoài.


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
