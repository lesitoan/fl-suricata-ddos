'use strict';
const $ = id => document.getElementById(id);
const escapeHTML = value => String(value ?? '').replace(/[&<>"']/g, character => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[character]));
const activeStatuses = new Set(['queued', 'running', 'waiting']);
const datasetActions = new Set(['dataset.test', 'dataset.cross_attack']);
const descriptions = {a: ['HTTP / TCP', 'SYN probe', '50 SYN · 10 gói/s'], b: ['UDP echo', 'UDP load', '1.000 UDP · 500 gói/s · 2 giây'], c: ['LDAP / UDP', 'LDAP burst', '100 LDAP · 20 gói/s']};
const choices = {};
let token = '', latest = null, logKind = 'eve', reportKind = 'live', logPaused = false, toastTimer;
let currentLog = null, hiddenLogLines = new Set(), logRequest = 0;
let datasetSelection='archive', datasetPage=1, datasetLoadedKey='', datasetRequest=0;
const pct = value => Number.isFinite(Number(value)) && value !== null ? (Number(value)*100).toFixed(2)+'%' : '—';
const number = value => Number.isFinite(Number(value)) && value !== null ? Number(value).toLocaleString('vi-VN') : '—';
const clock = value => { const date = new Date(value); return Number.isNaN(+date) ? '—' : date.toLocaleTimeString('vi-VN', {hour12:false}); };
const hash = value => value ? value.slice(0, 12)+'…' : '—';

function toast(message, error = false) {
  $('toast').textContent = message;
  $('toast').className = 'toast'+(error ? ' error' : '');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => $('toast').classList.add('hidden'), error ? 9000 : 4000);
}

async function api(path, options) {
  const response = await fetch(path, {cache:'no-store', ...options});
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || `HTTP ${response.status}`);
  return data;
}

async function action(payload) {
  try {
    const result = await api('/api/action', {method:'POST', headers:{'Content-Type':'application/json', 'X-Dashboard-Token':token}, body:JSON.stringify(payload)});
    if(datasetActions.has(payload.action)) {
      datasetSelection=result.job; datasetPage=1; datasetLoadedKey=''; reportKind='test';
      document.querySelectorAll('#report-tabs button').forEach(item=>item.classList.toggle('active',item.dataset.report==='test'));
    }
    toast(result.session ? 'Đã mở phiên mới. Các file bằng chứng cũ được giữ lại.' : 'Đã nhận thao tác. Theo dõi tiến độ ở Hoạt động.');
    await refresh();
  } catch (error) { toast(error.message, true); }
}

function activeJobs(node) {
  return (latest?.jobs || []).filter(job => activeStatuses.has(job.status) && (!node || job.node === node));
}

function nodeCard(node, state) {
  if (!choices[node]) choices[node] = state.mode || 'local';
  const mode = choices[node], busy = activeJobs(node).length > 0;
  const [service, sensor, inference] = Object.values(state.services);
  const anyRunning = Object.values(state.services).some(item => item.running);
  const ready = state.ready;
  const title = ready ? 'Sẵn sàng' : state.stale ? 'Cần nạp lại' : anyRunning ? 'Chưa sẵn sàng' : 'Đã dừng';
  const badge = ready ? 'good' : anyRunning ? 'warn' : 'muted';
  const selected = mode === 'global' ? state.global_model : state.local_model;
  const runningMode = state.mode ? state.mode.toUpperCase() : '—';
  const blockedGlobal = latest.fl.busy && mode === 'global';
  const disabled = (!latest.docker.ok || busy) ? 'disabled' : '';
  const canLoad = service.running && sensor.running && selected.exists && !blockedGlobal;
  const canTest = !disabled && state.local_model.exists && state.global_model.exists && !latest.fl.busy && !latest.dataset_busy;
  const crossButtons = Object.keys(descriptions).filter(source=>source!==node).map(source=>`
    <button class="button secondary" data-do="cross" data-source="${source}"
      title="Chấm mẫu attack có nhãn của node ${source.toUpperCase()} bằng Local và Global"
      ${canTest && latest.nodes[source].dataset_available ? '' : 'disabled'}>Attack từ ${source.toUpperCase()}</button>`).join('');
  return `<article class="node-card" data-node="${node}">
    <div class="node-title"><div class="node-name"><span class="node-avatar">${node.toUpperCase()}</span><div><h2>Node ${node.toUpperCase()}</h2><small>${descriptions[node][0]}</small></div></div><span class="pill ${badge}">${busy ? 'Đang thao tác' : title}</span></div>
    <div class="mode-row"><span>Chọn mô hình</span><div class="segmented"><button data-mode="local" class="${mode==='local'?'active':''}" ${busy?'disabled':''}>Local</button><button data-mode="global" class="${mode==='global'?'active':''}" ${busy?'disabled':''}>Global</button></div></div>
    <div class="model-info">Model gắn vào node: <b>${runningMode}</b> · <code title="${escapeHTML(state.loaded_hash)}">${escapeHTML(hash(state.loaded_hash))}</code><br><span title="${escapeHTML(state.loaded_id)}">${escapeHTML(state.loaded_id || 'Chưa có inference sẵn sàng')}</span>${!selected.exists ? '<br><span class="danger">Thiếu model '+mode+' hợp lệ</span>' : ''}</div>
    <div class="service-dots">${[[service,'Dịch vụ'],[sensor,'Suricata'],[inference,'Inference']].map(([item,label])=>`<span><i class="dot ${item.running ? (item.health === 'unhealthy' || item.health === 'starting' ? 'warn' : 'on') : ''}"></i>${label}</span>`).join('')}</div>
    <div class="node-power"><button class="button secondary" data-do="start" ${disabled || (!selected.exists || blockedGlobal ? 'disabled':'')}>⏻ Bật node</button><button class="button subtle" data-do="stop" ${disabled || (!anyRunning?'disabled':'')}>Tắt</button><button class="button secondary" data-do="mode" ${disabled || (!canLoad?'disabled':'')}>↻ Nạp ${mode}</button></div>
    <div class="traffic-actions"><button class="button benign" data-do="benign" ${disabled || (!ready || (latest.fl.busy && state.mode==='global')?'disabled':'')}>↗ Benign</button><button class="button attack" data-do="attack" ${disabled || (!ready || (latest.fl.busy && state.mode==='global')?'disabled':'')}>ϟ ${descriptions[node][1]}</button></div>
    <button class="button dataset-test-button" data-do="dataset" title="Chấm cùng tập test bằng cả Local và Global; không cần bật dịch vụ live" ${disabled || (!state.dataset_available || !state.local_model.exists || !state.global_model.exists || latest.fl.busy || latest.dataset_busy?'disabled':'')}>▤ Test dataset · Local vs Global</button>
    <div class="traffic-actions cross-test-actions" aria-label="Test chéo trên dataset">${crossButtons}</div>
    <div class="node-footer">${descriptions[node][2]} · chỉ trong mạng lab Docker</div>
  </article>`;
}

function renderNodes() { $('nodes').innerHTML = Object.entries(latest.nodes).map(([node,state])=>nodeCard(node,state)).join(''); }

function flChart(history) {
  const values = history.map(item => ({round:item.round, value:item.validation_summary?.['balanced-accuracy-macro-node']})).filter(item=>Number.isFinite(item.value));
  if (!values.length) return '<span class="empty-state">Biểu đồ validation sẽ xuất hiện sau mỗi vòng.</span>';
  const low = Math.max(0, Math.min(...values.map(item=>item.value))-.02), high = Math.min(1, Math.max(...values.map(item=>item.value))+.02);
  const points = values.map((item,index)=>({x:14+index*280/Math.max(1,values.length-1), y:49-(item.value-low)/Math.max(.01,high-low)*37, ...item}));
  return `<svg viewBox="0 0 320 82" role="img" aria-label="Balanced accuracy validation theo vòng"><text x="12" y="9" class="chart-caption">VALIDATION · MEAN NODE BALANCED ACCURACY</text><polyline points="${points.map(item=>`${item.x},${item.y}`).join(' ')}" class="chart-line"/>${points.map(item=>`<circle cx="${item.x}" cy="${item.y}" r="3" class="chart-dot"><title>Vòng ${item.round}: ${pct(item.value)}</title></circle><text x="${item.x}" y="66" text-anchor="middle" class="chart-caption">R${item.round}</text>`).join('')}<text x="312" y="80" text-anchor="end" class="chart-caption">Cuối: ${pct(values.at(-1).value)} · không tự kết luận hội tụ</text></svg>`;
}

function renderFL() {
  const fl = latest.fl, services = latest.docker.services;
  const names = ['fl-server','fl-client-a','fl-client-b','fl-client-c'];
  const healthy = names.filter(name=>services[name]?.running && services[name]?.health==='healthy').length;
  $('fl-services').innerHTML = names.map(name=>`<span class="service-chip"><i class="dot ${services[name]?.running ? (services[name].health==='healthy'?'on':'warn'):''}"></i>${name==='fl-server'?'Server':'Client '+name.at(-1).toUpperCase()}</span>`).join('');
  $('fl-badge').className = 'pill '+(fl.busy ? 'warn' : healthy===4 ? 'good' : 'muted');
  $('fl-badge').textContent = fl.busy ? 'Đang chạy FL' : `${Math.max(0,healthy-(services['fl-server']?.health==='healthy'?1:0))}/3 client healthy`;
  const busy = latest.jobs.some(job=>job.action.startsWith('fl.') && activeStatuses.has(job.status));
  $('fl-start').disabled = !latest.docker.ok || busy || fl.busy;
  $('fl-stop').disabled = !latest.docker.ok || busy || fl.busy || !names.some(name=>services[name]?.running);
  $('fl-run').disabled = !latest.docker.ok || busy || fl.busy || latest.dataset_busy || healthy!==4 || latest.jobs.some(job=>job.mode==='global' && activeStatuses.has(job.status));
  $('rounds').disabled = busy || fl.busy;
  const job = latest.jobs.findLast(item=>item.action==='fl.run' && activeStatuses.has(item.status));
  const report = fl.training || {};
  const total = job ? job.request.rounds : report.rounds_requested || 5;
  const completed = job ? job.progress || 0 : report.completed_rounds || 0;
  $('fl-progress').max = total; $('fl-progress').value = completed;
  $('fl-progress-label').textContent = job ? job.message : report.status==='complete' ? `Run đã hoàn tất · chọn checkpoint R${report.selected_round}` : report.status==='failed' ? 'Run trước thất bại' : report.status || 'Chưa có run';
  $('fl-progress-number').textContent = `${completed} / ${total}`;
  $('fl-note').textContent = fl.busy ? 'Chờ run hoàn tất trước khi tắt FL hoặc nạp global. Không tự gửi lại job.' : 'Mỗi lần chạy FL khởi tạo lại từ seed chung. Global mới cần bấm “Nạp global” ở node để sử dụng.';
  $('fl-chart').innerHTML = flChart(report.history || []);
}

const actionNames = {'tensorboard.start':'Mở TensorBoard','node.start':'Bật node', 'node.stop':'Dừng node', 'node.mode':'Nạp model', 'traffic':'Gửi traffic', 'dataset.test':'Test dataset · Local/Global', 'dataset.cross_attack':'Test chéo attack', 'fl.start':'Bật hệ thống FL', 'fl.stop':'Dừng hệ thống FL', 'fl.run':'Huấn luyện FL', 'logs.clear':'Xóa log live'};
const jobNode = job => job.source_node ? job.source_node.toUpperCase()+' → '+job.node.toUpperCase() : job.node?.toUpperCase() || '';
const statusNames = {queued:'Đang xếp hàng',running:'Đang chạy',waiting:'Đang chờ',complete:'Hoàn tất',failed:'Thất bại',interrupted:'Bị gián đoạn'};
function renderActivity() {
  const jobs = latest.jobs.slice().reverse();
  $('activity-count').textContent = jobs.length;
  $('activity-list').innerHTML = jobs.length ? jobs.map(job=>`<article class="activity" data-job="${escapeHTML(job.id)}"><div class="activity-title"><span>${actionNames[job.action] || job.action}${job.node?' · '+jobNode(job):''}</span><time>${clock(job.created_at)}</time></div><p>${escapeHTML(job.scenario ? `${job.scenario.toUpperCase()} / ${job.mode?.toUpperCase()} · ` : '')}${escapeHTML(job.error || job.message || '')}</p><span class="pill ${job.status==='complete'?'good':job.status==='failed'?'bad':activeStatuses.has(job.status)?'warn':'muted'}">${statusNames[job.status] || job.status}</span></article>`).join('') : '<div class="empty-state"><span>↗</span>Thao tác của phiên demo sẽ hiện tại đây.<br>Dashboard không tự gửi traffic.</div>';
}

function bars(nodes, metric, label) {
  return nodes.map(node=>`<div class="bar-card"><b>NODE ${node.toUpperCase()} · ${label}</b>${['local','global'].map(mode=>{
    const value=metric(node,mode), width=Number.isFinite(value)?Math.max(0,Math.min(100,value*100)):0;
    return `<div><span>${mode==='local'?'Local':'Global'}</span><div class="bar-track"><svg viewBox="0 0 100 6" preserveAspectRatio="none"><rect class="bar-fill ${mode}" width="${width}" height="6" rx="3"/></svg></div><span>${pct(value)}</span></div>`;
  }).join('')}</div>`).join('');
}

function renderUDPMetrics() {
  const cards=[];
  const ms=value=>typeof value==='number' && Number.isFinite(value)?value.toFixed(2)+' ms':'—';
  for(const mode of ['local','global']) {
    const job=latest.jobs.findLast(item=>item.node==='b' && item.mode===mode && item.report?.udp_load);
    if(!job) continue;
    const load=job.report.udp_load, counters=load.capture_observation?.delta || {};
    const rows=['before','during','after'].map((phase,index)=>{
      const item=load.health_checks?.[phase] || {};
      return `<tr><td>${['Trước tải','Trong tải','Sau tải'][index]}</td><td>${number(item.successful)} / ${number(item.planned_requests || 5)}</td><td>${number(item.timeouts)}</td><td>${ms(item.median_rtt_ms)}</td><td>${ms(item.p95_rtt_ms)}</td></tr>`;
    }).join('');
    cards.push(`<article class="udp-metric-card"><h3>Node B · UDP load<span class="model-label ${mode}">${mode.toUpperCase()}</span></h3><p>${load.rate_limit_pps?`Mục tiêu ${number(load.planned_packets)} gói · ${number(load.rate_limit_pps)} gói/s · ${number(load.target_sending_seconds)} giây<br>`:"Cấu hình đã lưu trước cập nhật<br>"}Gửi <b>${number(load.packets_sent)}</b> · nhận echo <b>${number(load.valid_echoes)}</b> · chưa nhận echo ${number(load.echoes_missing_after_observation)}<br>Tốc độ thực tế <b>${typeof load.observed_send_pps==='number'?load.observed_send_pps.toFixed(2):'—'} gói/s</b> · ${load.planned_flows || 5} cổng tải · ${typeof load.sending_wall_seconds==='number'?load.sending_wall_seconds.toFixed(2):'—'} giây<br>Suricata: ${job.report.captured_packets_toserver} đi / ${job.report.captured_packets_toclient} về · <span class="${load.sent_packet_count_matches_capture?'':'metric-warning'}">${load.sent_packet_count_matches_capture?'Số gói gửi/thu khớp':'Số gói gửi/thu chưa khớp'}</span></p><table><thead><tr><th>REQUEST KIỂM TRA</th><th>OK</th><th>TIMEOUT</th><th>MEDIAN RTT</th><th>P95 RTT</th></tr></thead><tbody>${rows}</tbody></table><p class="capture-note">Capture delta: drops ${number(counters.kernel_drops)} · errors ${number(counters.capture_errors)} · decoder invalid ${number(counters.decoder_invalid)}. Khoảng stats bao gồm thời gian chờ flow và request kiểm tra; “—” là chưa có số đo phù hợp.<br>Mỗi giai đoạn chỉ 5 request. Echo thiếu không xác định vị trí mất gói; các số đo không tự chứng minh saturation. ${clock(job.created_at)} · model ${hash(job.weights_sha256)}</p></article>`);
  }
  $('udp-measurements').classList.toggle('hidden',reportKind!=='live' || !cards.length);
  $('udp-measurements').innerHTML=cards.join('');
}

function renderDatasetControls() {
  const visible=reportKind==='test';
  $('dataset-controls').classList.toggle('hidden',!visible);
  const jobs=latest.jobs.filter(job=>datasetActions.has(job.action)).slice().reverse();
  const select=$('dataset-run');
  const optionKey=jobs.map(job=>job.id+':'+job.status).join('|');
  if(select.dataset.optionsKey!==optionKey) {
    select.innerHTML='<option value="archive">Báo cáo A/B/C đã lưu trước đây</option>'+jobs.map(job=>`<option value="${escapeHTML(job.id)}">${job.source_node?'Attack '+jobNode(job):'Node '+jobNode(job)} · ${clock(job.created_at)} · ${statusNames[job.status] || job.status}</option>`).join('');
    select.dataset.optionsKey=optionKey;
  }
  select.value=datasetSelection;
  const job=jobs.find(item=>item.id===datasetSelection), summary=job?.dataset_summary;
  const complete=visible && job?.status==='complete' && summary;
  $('dataset-csv').disabled=$('dataset-json').disabled=!complete;
  const cross = job?.action==='dataset.cross_attack';
  $('dataset-confusion').classList.toggle('hidden',!complete || cross);
  $('dataset-samples').classList.toggle('hidden',!complete);
  if(!complete) return;
  const filter = $('dataset-filter');
  for(const option of filter.options) option.disabled = cross && ['benign','fp'].includes(option.value);
  if(filter.selectedOptions[0]?.disabled) filter.value='all';
  if(cross) { refreshDatasetRows(); return; }
  const metrics=summary.nodes[summary.node].models;
  $('dataset-confusion').innerHTML=['local','global'].map(model=>{
    const matrix=metrics[model].confusion_matrix;
    return `<article class="confusion-card"><h3>${model.toUpperCase()} · Confusion matrix</h3><p>Hàng: nhãn thật · Cột: dự đoán</p><table><thead><tr><th></th><th>Benign</th><th>Attack</th></tr></thead><tbody><tr><th>Benign</th><td class="correct">${number(matrix[0][0])}<small>TN · đúng benign</small></td><td class="mistake">${number(matrix[0][1])}<small>FP · báo nhầm</small></td></tr><tr><th>Attack</th><td class="mistake">${number(matrix[1][0])}<small>FN · bỏ sót</small></td><td class="correct">${number(matrix[1][1])}<small>TP · phát hiện</small></td></tr></tbody></table></article>`;
  }).join('');
  refreshDatasetRows();
}

async function refreshDatasetRows() {
  const job=datasetSelection, model=$('dataset-model').value, filter=$('dataset-filter').value, page=datasetPage;
  const key=[job,model,filter,page].join(':');
  if(job==='archive' || datasetLoadedKey===key) return;
  datasetLoadedKey=key;
  const request=++datasetRequest;
  $('dataset-rows').innerHTML='<tr><td colspan="6" class="report-empty">Đang đọc prediction đã xác minh…</td></tr>';
  $('dataset-prev').disabled=$('dataset-next').disabled=true;
  try {
    const data=await api(`/api/dataset/rows?job=${encodeURIComponent(job)}&model=${model}&filter=${filter}&page=${page}&size=50`);
    if(request!==datasetRequest || datasetSelection!==job) return;
    $('dataset-rows').innerHTML=data.rows.map(row=>`<tr><td title="${escapeHTML(row.row_uid)}">${row.index}</td><td>${row.true_label}</td>${['local','global'].map(name=>`<td>${row[name].probability_attack.toFixed(6)}</td><td class="${row[name].prediction!==row.true_label?'prediction-wrong':''}">${row[name].prediction}</td>`).join('')}</tr>`).join('') || '<tr><td colspan="6" class="report-empty">Không có mẫu phù hợp bộ lọc.</td></tr>';
    $('dataset-page-label').textContent=`${number(data.total)} mẫu phù hợp · trang ${data.page}/${data.pages}`;
    $('dataset-prev').disabled=data.page<=1; $('dataset-next').disabled=data.page>=data.pages;
  } catch(error) {
    if(request===datasetRequest) $('dataset-rows').innerHTML=`<tr><td colspan="6" class="report-empty">${escapeHTML(error.message)}</td></tr>`;
  }
}

function renderReports() {
  renderUDPMetrics();
  renderDatasetControls();
  $('comparison-chart').classList.remove('dataset-single');
  if (reportKind === 'test') {
    const selected=latest.jobs.find(job=>job.id===datasetSelection && datasetActions.has(job.action));
    const summary=selected?.dataset_summary;
    if(datasetSelection!=='archive' && (!summary || selected?.status!=='complete')) {
      $('report-note').textContent=selected ? `${jobNode(selected)} · ${selected.error || selected.message || 'Đang chuẩn bị…'}` : 'Chọn một lượt test ở thẻ node.';
      $('comparison-chart').innerHTML=''; $('result-head').innerHTML='';
      $('result-body').innerHTML='<tr><td class="report-empty">Kết quả sẽ hiện sau khi xác minh các mẫu và dự đoán.</td></tr>';
      return;
    }
    if(summary?.kind==='cross_attack_test') {
      renderCrossAttack(summary);
      return;
    }
    const test=summary ? {available:true,nodes:summary.nodes,global_hash:summary.global_weights_sha256,
      matches_current_global:summary.global_weights_sha256===latest.fl.global_model.hash,evaluated_at:summary.evaluated_at_utc} : latest.test;
    $('report-note').textContent = test.available ? `${summary?'Lượt test mới · node '+summary.node:'Báo cáo A/B/C đã lưu'} · ${test.evaluated_at ? new Date(test.evaluated_at).toLocaleString('vi-VN') : ''}. ${test.matches_current_global?'Hash global khớp checkpoint hiện tại.':'⚠ Global hiện tại khác model trong báo cáo này; đây là kết quả lịch sử.'} ${summary?`Test ${hash(summary.nodes[summary.node].test_csv_sha256)} · benign ${number(summary.nodes[summary.node].label_counts.benign)} / attack ${number(summary.nodes[summary.node].label_counts.attack)}. `:""}Cùng mẫu test cho hai model; không fit hoặc chỉnh ngưỡng. Ngân sách train khác nhau; chưa phải recording độc lập.` : 'Chưa có báo cáo test dataset. Bấm Test dataset ở từng node để chạy đánh giá.';
    $('comparison-chart').classList.toggle('dataset-single',Boolean(summary));
    $('comparison-chart').innerHTML = test.available ? bars(summary?Object.keys(test.nodes):['A','B','C'],(node,mode)=>test.nodes[node]?.models[mode]?.balanced_accuracy ?? null, 'BALANCED ACCURACY') : '';
    $('result-head').innerHTML = '<tr><th>NODE</th><th>MODEL</th><th>SỐ MẪU</th><th>RECALL ATTACK</th><th>F1 ATTACK</th><th>BALANCED ACC.</th><th>FPR</th><th>TN / FP / FN / TP</th></tr>';
    const rows=[];
    for (const [node,data] of Object.entries(test.nodes)) for (const mode of ['local','global']) {
      const item=data.models[mode]; if(!item) continue;
      const confusion=(item.confusion_matrix || []).flat().join(' / ');
      rows.push(`<tr><td><b>${node}</b></td><td><span class="model-label ${mode}">${mode.toUpperCase()}</span><small title="${escapeHTML(item.weights_sha256)}">${hash(item.weights_sha256)}</small></td><td>${number(data.rows)}</td><td>${pct(item.recall_attack)}</td><td>${pct(item.f1_attack)}</td><td><b>${pct(item.balanced_accuracy)}</b></td><td>${pct(item.false_positive_rate)}</td><td>${confusion}</td></tr>`);
    }
    $('result-body').innerHTML=rows.join('') || '<tr><td colspan="8" class="report-empty">Chưa có kết quả test.</td></tr>';
    return;
  }
  const jobs=latest.jobs.filter(job=>job.report);
  $('report-note').textContent='Traffic thật trong mạng Docker. Chỉ tính các flow/prediction khớp sender và hash model. Biểu đồ là tỷ lệ được dự đoán attack ở lượt probe gần nhất, không phải recall tấn công. Hai lượt local/global phát riêng nên có thể khác đặc trưng thời gian.';
  $('comparison-chart').innerHTML=jobs.length ? bars(['a','b','c'],(node,mode)=>{
    const useNewB=node==='b' && jobs.some(item=>item.node==='b' && item.report.traffic_profile==='bounded_udp_load');
    const workload=item=>{const load=item.report.udp_load || {};return [load.planned_packets ?? load.packets_sent,load.rate_limit_pps ?? 'old',load.target_sending_seconds ?? 'old'].join(':');};
    const latestB=useNewB?jobs.findLast(item=>item.node==='b' && item.report.udp_load):null;
    const job=jobs.findLast(item=>item.node===node && item.mode===mode && item.scenario==='attack'
      && (!useNewB || (item.report.traffic_profile==='bounded_udp_load' && (!latestB || workload(item)===workload(latestB)))));
    return job?.report.matched_predictions ? job.report.predicted_attack/job.report.matched_predictions : null;
  },'PROBE → DỰ ĐOÁN ATTACK') : '';
  $('result-head').innerHTML='<tr><th>NODE / KỊCH BẢN</th><th>MODEL</th><th>FLOW / PRED.</th><th>BENIGN</th><th>ATTACK</th><th>TRỄ TB</th><th>KẾT QUẢ</th></tr>';
  $('result-body').innerHTML=jobs.slice().reverse().map(job=>{
    const report=job.report, stale=job.mode==='global' && job.weights_sha256!==latest.fl.global_model.hash;
    return `<tr><td><b>${job.node.toUpperCase()} · ${job.scenario==='benign'?'Benign':job.node==='b' && report.traffic_profile!=='bounded_udp_load'?'UDP burst (cũ)':descriptions[job.node][1]}</b><small>${clock(job.created_at)}</small></td><td><span class="model-label ${job.mode}">${job.mode.toUpperCase()}</span><small title="${escapeHTML(job.weights_sha256)}">${hash(job.weights_sha256)}${stale?' · model cũ':''}</small></td><td>${report.matched_flows} / ${report.matched_predictions}</td><td>${report.predicted_benign}</td><td>${report.predicted_attack}</td><td>${report.mean_delay_seconds===null?'—':report.mean_delay_seconds.toFixed(2)+'s'}</td><td><span class="pill ${job.status==='complete'?'good':'warn'}">${job.status==='complete'?'Đã ghép':'Chưa đầy đủ'}</span></td></tr>`;
  }).join('') || '<tr><td colspan="7" class="report-empty">Gửi benign hoặc probe để bắt đầu so sánh.<br>Kết quả sẽ xuất hiện sau khi Suricata xuất flow.</td></tr>';
}

function renderCrossAttack(summary) {
  const {source_node:source,node:target,rows,models}=summary;
  $('report-note').textContent=`${source} → ${target} · ${number(rows)} flow attack có nhãn từ tập test của ${source} · CSV ${hash(summary.test_csv_sha256)}. Chấm offline bằng Local ${target} và Global trên cùng các flow. Tập chỉ gồm attack nên báo cáo recall và số mẫu bỏ sót.`;
  $('comparison-chart').classList.add('dataset-single');
  $('comparison-chart').innerHTML=bars([source+' → '+target],(_,mode)=>models[mode].recall_attack,'RECALL ATTACK');
  $('result-head').innerHTML='<tr><th>DỮ LIỆU → NODE</th><th>MODEL</th><th>MẪU ATTACK</th><th>PHÁT HIỆN (TP)</th><th>BỎ SÓT (FN)</th><th>RECALL ATTACK</th></tr>';
  $('result-body').innerHTML=Object.entries(models).map(([mode,model])=>{
    const current = mode==='global' ? latest.fl.global_model : latest.nodes[target.toLowerCase()].local_model;
    const stale = model.weights_sha256!==current.hash;
    return `<tr><td><b>${source} → ${target}</b></td><td><span class="model-label ${mode}">${mode.toUpperCase()}</span><small title="${escapeHTML(model.id)}">${hash(model.weights_sha256)}${stale?' · model cũ':''}</small></td><td>${number(rows)}</td><td>${number(model.tp)}</td><td>${number(model.fn)}</td><td><b>${pct(model.recall_attack)}</b></td></tr>`;
  }).join('');
}

function render() {
  const good=latest.docker.ok;
  $('connection').textContent=good?'Docker đã kết nối':'Docker chưa sẵn sàng';
  $('connection').className='pill '+(good?'good':'warn');
  $('error-banner').classList.toggle('hidden',good);
  $('error-banner').textContent=good?'':`Không đọc được Docker. Mở Docker Desktop rồi chờ cập nhật. ${latest.docker.error || ''}`;
  $('session-id').textContent=latest.session;
  $('ready-count').textContent=Object.values(latest.nodes).filter(node=>node.ready).length+' / 3';
  $('global-round').textContent=latest.fl.global_model.exists?'Checkpoint R'+(latest.fl.global_model.round || '—'):'Chưa có model';
  $('flow-count').textContent=number(latest.jobs.reduce((total,job)=>total+(job.report?.matched_predictions || 0),0));
  $('job-count').textContent=activeJobs().length;
  $('new-session').disabled=activeJobs().length>0;
  renderNodes(); renderFL(); renderActivity(); renderReports();
  $('clear-files').disabled=!latest.docker.ok || activeJobs($('log-node').value).length>0 || Object.values(latest.nodes[$('log-node').value].services).some(service=>service.running);
}

let refreshPending=false;
async function refresh() {
  if(refreshPending) return;
  refreshPending=true;
  try { latest=await api('/api/state'); render(); }
  catch(error) { $('connection').textContent='Mất kết nối dashboard'; $('connection').className='pill bad'; }
  finally { refreshPending=false; }
}

function renderLog(text) {
  const container=$('event-log'), atBottom=container.scrollTop+container.clientHeight>=container.scrollHeight-50;
  const lines=text.split('\n').filter(line=>line.trim() && !hiddenLogLines.has(line));
  $('log-count').textContent=lines.length+' dòng';
  container.innerHTML=lines.length ? lines.map(line=>{
    let record;
    try { record=JSON.parse(line); } catch { return `<pre class="plain-log">${escapeHTML(line)}</pre>`; }
    if(!record || typeof record!=='object') return `<pre class="plain-log">${escapeHTML(line)}</pre>`;
    const prediction=record.prediction && typeof record.prediction==='object' ? record.prediction : record;
    const isPrediction=typeof prediction.probability_attack==='number';
    const type=isPrediction ? prediction.prediction : record.event_type || record.status || 'event';
    const css=['attack','benign','flow'].includes(type)?type:'other';
    let summary=isPrediction ? `flow ${prediction.flow_id} · P(attack) ${prediction.probability_attack.toFixed(6)} · ${prediction.model_id}` : record.event_type==='flow' ? `${record.proto} ${record.src_ip}:${record.src_port ?? ''} → ${record.dest_ip}:${record.dest_port ?? ''} · gói ${record.flow?.pkts_toserver}/${record.flow?.pkts_toclient}` : record.event_type || record.status || 'JSON';
    return `<div class="event-row"><span class="event-time">${clock(prediction.scored_at_utc || record.timestamp || record.flow?.end)}</span><details class="event-content"><summary><span class="log-tag ${css}">${escapeHTML(type)}</span>${escapeHTML(summary)}</summary><pre>${escapeHTML(JSON.stringify(record,null,2))}</pre></details></div>`;
  }).join('') : '<div class="empty-state"><span>⌁</span>Chưa có dòng log phù hợp.<br>Gửi traffic rồi chờ Suricata xuất flow.</div>';
  if(atBottom) container.scrollTop=container.scrollHeight;
}

let logPending=false;
async function refreshLog() {
  if(logPaused || logPending) return;
  logPending=true;
  const request=++logRequest, node=$('log-node').value, kind=logKind;
  try {
    const data=await api(`/api/logs?node=${node}&kind=${kind}&event=${$('only-flow').checked?'flow':'all'}`);
    if(request!==logRequest || node!==$('log-node').value || kind!==logKind) return;
    if(data.text!==currentLog) { currentLog=data.text; renderLog(currentLog); }
    else if(!$('event-log').children.length) renderLog(currentLog);
  } catch(error) { if(request===logRequest) $('event-log').textContent=error.message; }
  finally { logPending=false; }
}

function resetLogSelection() { logRequest++; currentLog=null; hiddenLogLines.clear(); renderLog(''); refreshLog(); }

$('nodes').addEventListener('click',event=>{
  const button=event.target.closest('button'), card=event.target.closest('[data-node]');
  if(!button || !card || button.disabled) return;
  const node=card.dataset.node;
  if(button.dataset.mode) { choices[node]=button.dataset.mode; renderNodes(); return; }
  const operation=button.dataset.do;
  if(operation==='start' || operation==='mode') action({action:'node.'+operation,node,mode:choices[node]});
  else if(operation==='stop') action({action:'node.stop',node});
  else if(operation==='benign' || operation==='attack') action({action:'traffic',node,scenario:operation});
  else if(operation==='dataset') action({action:'dataset.test',node});
  else if(operation==='cross') action({action:'dataset.cross_attack',node,source_node:button.dataset.source});
});
$('tensorboard-open').onclick=async()=>{
  const button=$('tensorboard-open');
  const viewer=window.open('about:blank','lab-tensorboard');
  if(viewer) { viewer.opener=null; viewer.document.title='TensorBoard'; viewer.document.body.textContent='Đang mở TensorBoard, không chạy train…'; }
  button.disabled=true;
  try {
    const created=await api('/api/action',{method:'POST',headers:{'Content-Type':'application/json','X-Dashboard-Token':token},body:JSON.stringify({action:'tensorboard.start'})});
    let result;
    for(let attempt=0;attempt<160;attempt++) {
      const state=await api('/api/state');
      result=state.jobs.find(job=>job.id===created.job);
      if(result && ['complete','failed'].includes(result.status)) break;
      await new Promise(resolve=>setTimeout(resolve,500));
    }
    if(!result || result.status!=='complete') throw new Error(result?.error || 'TensorBoard chưa sẵn sàng; kiểm tra mục Hoạt động.');
    if(viewer) viewer.location.href='http://127.0.0.1:6006/#scalars';
    else toast('TensorBoard đã sẵn sàng tại http://127.0.0.1:6006');
    await refresh();
  } catch(error) { if(viewer) viewer.close(); toast(error.message,true); }
  finally { button.disabled=false; }
};
$('fl-start').onclick=()=>action({action:'fl.start'});
$('fl-stop').onclick=()=>action({action:'fl.stop'});
$('fl-run').onclick=()=>{
  const rounds=Number($('rounds').value);
  if(!Number.isInteger(rounds) || rounds<1 || rounds>50) { toast('Chọn số vòng nguyên từ 1 đến 50.',true); return; }
  if(confirm(`Chạy FL ${rounds} vòng từ seed chung? Run thành công sẽ thay global/current. Model local được giữ nguyên; inference chưa tự nạp model mới.`)) action({action:'fl.run',rounds});
};
$('new-session').onclick=()=>{ if(confirm('Mở phiên demo mới? Màn hình hoạt động/kết quả được làm mới; file bằng chứng và log trên đĩa vẫn giữ nguyên.')) action({action:'session.new'}); };
$('export').onclick=()=>{ location.href='/api/export'; };
$('log-tabs').onclick=event=>{ const button=event.target.closest('[data-kind]'); if(!button) return; logKind=button.dataset.kind; document.querySelectorAll('#log-tabs button').forEach(item=>item.classList.toggle('active',item===button)); $('flow-filter').classList.toggle('hidden',logKind!=='eve'); resetLogSelection(); };
$('log-node').onchange=()=>{ resetLogSelection(); if(latest) render(); };
$('only-flow').onchange=resetLogSelection;
$('pause-log').onclick=()=>{ logPaused=!logPaused; $('pause-log').textContent=logPaused?'Tiếp tục':'Tạm dừng'; $('log-live').textContent=logPaused?'Đã tạm dừng':'● Tự cập nhật'; if(!logPaused) refreshLog(); };
$('clear-view').onclick=()=>{ hiddenLogLines=new Set((currentLog || '').split('\n')); renderLog(currentLog || ''); };
$('clear-files').onclick=()=>{ const node=$('log-node').value; if(confirm(`Xóa nội dung EVE/Suricata và prediction local/global trên đĩa của node ${node.toUpperCase()}? Node phải được dừng. Không xóa model, dataset hoặc report.`)) action({action:'logs.clear',node}); };
$('report-tabs').onclick=event=>{ const button=event.target.closest('[data-report]'); if(!button) return; reportKind=button.dataset.report; document.querySelectorAll('#report-tabs button').forEach(item=>item.classList.toggle('active',item===button)); if(latest) renderReports(); };
$('dataset-run').onchange=()=>{datasetSelection=$('dataset-run').value;datasetPage=1;datasetLoadedKey='';datasetRequest++;if(latest)renderReports();};
for(const id of ['dataset-model','dataset-filter']) $(id).onchange=()=>{datasetPage=1;datasetLoadedKey='';refreshDatasetRows();};
$('dataset-prev').onclick=()=>{if(datasetPage>1){datasetPage--;datasetLoadedKey='';refreshDatasetRows();}};
$('dataset-next').onclick=()=>{datasetPage++;datasetLoadedKey='';refreshDatasetRows();};
$('dataset-csv').onclick=()=>{location.href='/api/dataset/export?job='+encodeURIComponent(datasetSelection)+'&format=csv';};
$('dataset-json').onclick=()=>{location.href='/api/dataset/export?job='+encodeURIComponent(datasetSelection)+'&format=json';};
$('activity-list').onclick=event=>{ const item=event.target.closest('[data-job]'); if(!item) return; const job=latest.jobs.find(job=>job.id===item.dataset.job); $('job-detail').textContent=JSON.stringify(job,null,2); $('job-dialog').showModal(); };
$('close-dialog').onclick=()=>$('job-dialog').close();
$('theme').onclick=()=>{ document.body.classList.toggle('dark'); try { localStorage.setItem('fl-theme',document.body.classList.contains('dark')?'dark':'light'); } catch {} };
try { document.body.classList.toggle('dark',localStorage.getItem('fl-theme')==='dark'); } catch {}

(async()=>{
  try { const data=await api('/api/bootstrap'); token=data.token; await refresh(); await refreshLog(); }
  catch(error) { toast('Không kết nối được dashboard: '+error.message,true); }
  setInterval(refresh,2500); setInterval(refreshLog,2500);
})();
