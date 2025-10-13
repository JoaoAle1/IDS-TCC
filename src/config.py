# =============================================================
# src/config.py
# =============================================================
from pathlib import Path

# Define o caminho raiz do projeto (a pasta 'IDS-TCC')
ROOT = Path(__file__).resolve().parents[1]

# Define os caminhos para as subpastas principais
DATA = ROOT / 'data'
RAW_PCAPS = DATA / 'raw_pcaps'
CICIDS_CSV = DATA / 'cicids_csv'
PROCESSED = DATA / 'processed'
MODELS = ROOT / 'models'
REPORTS = ROOT / 'reports'

# Cria as pastas de saída se elas não existirem
for p in (PROCESSED, MODELS, REPORTS):
    p.mkdir(parents=True, exist_ok=True)

# Define os nomes dos arquivos que serão gerados ou lidos
FLOWS_LABELED = PROCESSED / 'flows_labeled.csv'
ALERTS_LOG = PROCESSED / 'alerts.jsonl'
BEST_MODEL = MODELS / 'best_model.joblib'
SCALER_PATH = MODELS / 'scaler.joblib'
LABEL_ENCODER = MODELS / 'label_encoder.joblib'
METRICS_JSON = REPORTS / 'metrics.json'
CONF_MATRIX_PNG = REPORTS / 'conf_matrix.png'

# Define as classes de ataque que o projeto focará
TARGET_CLASSES = ['BENIGN', 'PORTSCAN', 'DDOS', 'SSH-BF', 'OUTROS']

# Define as features (características) que o modelo usará para aprender e prever
FEATURES = ['duration_s', 'tot_pkts', 'pkts_per_sec']