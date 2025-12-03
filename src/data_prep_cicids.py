
import pandas as pd
import numpy as np
from pathlib import Path
import warnings
from config import CICIDS_CSV, FLOWS_LABELED, PROCESSED, FEATURES

warnings.filterwarnings('ignore')


CANDIDATES = {
    'flow_duration': ['Flow Duration', 'Flow_Duration', 'FlowDuration'],
    'fwd_pkts': ['Tot Fwd Pkts', 'Total Fwd Packets'],
    'bwd_pkts': ['Tot Bwd Pkts', 'Total Backward Packets'],
    'label': ['Label']
}

LABEL_MAP = {
    'BENIGN': 'BENIGN',
    'DoS Hulk': 'DDOS',
    'PortScan': 'PORTSCAN',
    'DDoS': 'DDOS',
    'DoS GoldenEye': 'DDOS',
    'FTP-Patator': 'OUTROS',
    'SSH-Patator': 'SSH-BF',
    'DoS slowloris': 'DDOS',
    'DoS Slowhttptest': 'DDOS',
    'Bot': 'OUTROS',
    'Web Attack  Brute Force': 'OUTROS',
    'Web Attack  XSS': 'OUTROS',
    'Infiltration': 'OUTROS',
    'Web Attack  Sql Injection': 'OUTROS',
    'Heartbleed': 'OUTROS'
}


def pick_col(df, names):
    for n in names:
        if n in df.columns:
            return n
    return None


def load_all_csv(folder: Path) -> pd.DataFrame:
    files = list(folder.glob('*.csv'))
    if not files:
        raise FileNotFoundError(f"Nenhum arquivo CSV encontrado em {folder}")

    parts = []
    for f in files:
        print(f"Lendo arquivo: {f.name}")
        try:
            df = pd.read_csv(f, encoding='utf-8', on_bad_lines='skip')
        except Exception:
            df = pd.read_csv(f, encoding='latin1', on_bad_lines='skip')

        df.columns = [col.strip() for col in df.columns]
        parts.append(df)

    return pd.concat(parts, ignore_index=True)


def main():
    print("Iniciando pré-processamento do dataset CIC-IDS2017...")
    df = load_all_csv(CICIDS_CSV)
    print(f"Total de {len(df)} linhas lidas.")

    cols_to_keep = {}
    for key, names in CANDIDATES.items():
        col_name = pick_col(df, names)
        if col_name:
            cols_to_keep[key] = col_name
        else:
            if key != 'label':
                print(f"AVISO: Nenhuma coluna encontrada para '{key}'.")

    if 'label' not in cols_to_keep:
        raise ValueError("Coluna 'Label' é essencial e não foi encontrada.")

    rename_map = {v: k for k, v in cols_to_keep.items()}
    tmp = df[list(cols_to_keep.values())].copy()
    tmp.rename(columns=rename_map, inplace=True)

    tmp.replace([np.inf, -np.inf], np.nan, inplace=True)
    tmp.dropna(inplace=True)

    numeric_cols = ['flow_duration', 'fwd_pkts', 'bwd_pkts']
    for col in numeric_cols:
        if col in tmp.columns:
            tmp[col] = pd.to_numeric(tmp[col], errors='coerce')

    tmp.fillna(0, inplace=True)


    tmp['duration_s'] = tmp['flow_duration'] / 1e6
    tmp['tot_pkts'] = tmp['fwd_pkts'] + tmp['bwd_pkts']


    duration_safe = tmp['duration_s'].replace(0, 1e-6)
    tmp['pkts_per_sec'] = tmp['tot_pkts'] / duration_safe

    tmp['label'] = tmp['label'].map(LABEL_MAP).fillna('OUTROS')


    out = tmp[FEATURES + ['label']].copy()

    out.replace([np.inf, -np.inf], np.nan, inplace=True)
    out.fillna(0, inplace=True)

    PROCESSED.mkdir(parents=True, exist_ok=True)
    out.to_csv(FLOWS_LABELED, index=False)

    print("\n" + "=" * 50)
    print(f"SUCESSO: {FLOWS_LABELED} salvo com {len(out)} linhas.")
    print("Contagem de Rótulos:")
    print(out['label'].value_counts())
    print("=" * 50)


if __name__ == '__main__':
    main()