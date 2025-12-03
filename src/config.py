
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

DATA = ROOT / 'data'
RAW_PCAPS = DATA / 'raw_pcaps'
CICIDS_CSV = DATA / 'cicids_csv'
PROCESSED = DATA / 'processed'
MODELS = ROOT / 'models'
REPORTS = ROOT / 'reports'


for p in (PROCESSED, MODELS, REPORTS):
    p.mkdir(parents=True, exist_ok=True)


FLOWS_LABELED = PROCESSED / 'flows_labeled.csv'
ALERTS_LOG = PROCESSED / 'alerts.jsonl'
BEST_MODEL = MODELS / 'best_model.joblib'
SCALER_PATH = MODELS / 'scaler.joblib'
LABEL_ENCODER = MODELS / 'label_encoder.joblib'
METRICS_JSON = REPORTS / 'metrics.json'
CONF_MATRIX_PNG = REPORTS / 'conf_matrix.png'


TARGET_CLASSES = ['BENIGN', 'PORTSCAN', 'DDOS', 'SSH-BF', 'OUTROS']

FEATURES = ['duration_s', 'tot_pkts', 'pkts_per_sec']