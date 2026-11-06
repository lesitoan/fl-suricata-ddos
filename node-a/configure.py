""" Thiết lập Suricata xuất EVE JSON, thông tin flow và giới hạn bộ nhớ """
from pathlib import Path
import yaml

path = Path('/etc/suricata/suricata.yaml')
cfg = yaml.safe_load(path.read_text())
cfg['vars']['address-groups']['HOME_NET'] = '[10.0.0.0/8,172.16.0.0/12,192.168.0.0/16]'
cfg['vars']['address-groups']['EXTERNAL_NET'] = 'any'
cfg['default-rule-path'] = '/etc/suricata/rules'
cfg['rule-files'] = ['node-a.rules']
cfg['outputs'] = [{'eve-log': {
    'enabled': True, 'filetype': 'regular', 'filename': 'eve.json',
    'types': [{'alert': {'metadata': True}}, {'http': {'extended': True}},
              'flow', {'stats': {'totals': True, 'threads': False}}]
}}]
cfg['stats'] = {'enabled': True, 'interval': 5}
cfg['af-packet'] = [{'interface': 'eth0', 'threads': 1, 'cluster-id': 81,
                     'cluster-type': 'cluster_flow', 'defrag': True,
                     'use-mmap': True, 'tpacket-v3': True}]
cfg['flow'] = {'memcap': '32mb', 'hash-size': 8192, 'prealloc': 1000}
cfg['stream']['memcap'] = '32mb'
cfg['stream']['reassembly']['memcap'] = '64mb'
cfg['flow-timeouts']['tcp'].update({'new': 15, 'established': 60, 'closed': 5,
                                   'emergency-new': 5, 'emergency-established': 15,
                                   'emergency-closed': 2})
cfg['flow-timeouts']['udp'].update({'new': 10, 'established': 30,
                                   'emergency-new': 5, 'emergency-established': 10})
cfg.setdefault('threading', {})['set-cpu-affinity'] = False
cfg['threading']['detect-thread-ratio'] = 1.0
path.write_text('%YAML 1.1\n---\n' + yaml.safe_dump(cfg, sort_keys=False))
rules = Path('/etc/suricata/rules')
rules.mkdir(parents=True, exist_ok=True)
(rules / 'node-a.rules').write_text(
    'alert http any any -> any any (msg:"NODE_A LAB smoke marker"; '
    'flow:established,to_server; http.uri; content:"/lab-check"; '
    'sid:1000001; rev:1;)\n'
)
