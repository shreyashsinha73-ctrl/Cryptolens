"""Build src/data/demo_dataset.json from a REAL scoring run over captures/*.pcap."""
import json, datetime, pathlib
from backend.services.analyzer_provider import AnalyzerProvider
from backend.scoring.scoring_engine import ScoringEngine

root = pathlib.Path(__file__).resolve().parents[1]
rows = []
for pcap in sorted((root / 'captures').glob('config_*.pcap')):
    analysis = AnalyzerProvider(mode='real').get_analysis(str(pcap))
    r = ScoringEngine().evaluate(analysis)
    rows.append({
        'capture': pcap.name,
        'score': r.get('score'),
        'risk_level': r.get('risk_level'),
        'coverage': r.get('coverage'),
        'score_headline': r.get('score_headline'),
        'score_if_unobserved_fail': r.get('score_if_unobserved_fail'),
        'score_if_unobserved_pass': r.get('score_if_unobserved_pass'),
        'findings': [{'severity': f.get('severity'), 'title': f.get('title')} for f in r.get('findings', [])],
    })
out = {'generated_at': datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC'), 'captures': rows}
(root / 'src' / 'data' / 'demo_dataset.json').write_text(json.dumps(out, indent=2))
print(len(rows), 'captures written')
