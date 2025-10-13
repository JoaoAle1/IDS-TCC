# =============================================================
# src/data_prep_cicids.py
# =============================================================
import pandas as pd
import numpy as np
from pathlib import Path
import warnings
from config import CICIDS_CSV, FLOWS_LABELED, PROCESSED

# Ignora avisos que podem aparecer durante a leitura dos CSVs
warnings.filterwarnings('ignore')

# Mapeamento para normalizar os nomes das colunas, já que os CSVs têm nomes diferentes
CANDIDATES = {
    'flow_duration': ['Flow Duration', 'Flow_Duration', 'FlowDuration'],
    'fwd_pkts': ['Tot Fwd Pkts', 'Total Fwd Packets', 'Fwd Packets/s'],  # Adicionado 'Fwd Packets/s'
    'bwd_pkts': ['Tot Bwd Pkts', 'Total Backward Packets', 'Bwd Packets/s'],  # Adicionado 'Bwd Packets/s'
    'fwd_bytes': ['TotLen Fwd Pkts', 'Total Length of Fwd Packets'],  # Corrigido nomes
    'bwd_bytes': ['TotLen Bwd Pkts', 'Total Length of Bwd Packets'],  # Corrigido nomes
    'label': ['Label']
}

# Mapeamento para normalizar os rótulos de ataque
LABEL_MAP = {
    'BENIGN': 'BENIGN',
    'DoS Hulk': 'DDOS',
    'PortScan': 'PORTSCAN',
    'DDoS': 'DDOS',
    'DoS GoldenEye': 'DDOS',
    'FTP-Patator': 'OUTROS',  # Exemplo de outro ataque
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
    """Função auxiliar para encontrar o nome correto da coluna em um DataFrame."""
    for n in names:
        if n in df.columns:
            return n
    return None


def load_all_csv(folder: Path) -> pd.DataFrame:
    """Carrega e une todos os arquivos CSV de uma pasta."""
    files = list(folder.glob('*.csv'))
    if not files:
        raise FileNotFoundError(f"Nenhum arquivo CSV encontrado em {folder}")

    parts = []
    for f in files:
        print(f"Lendo arquivo: {f.name}")
        try:
            df = pd.read_csv(f, encoding='utf-8', on_bad_lines='skip')
            # Remove espaços extras dos nomes das colunas
            df.columns = [col.strip() for col in df.columns]
            parts.append(df)
        except Exception:
            df = pd.read_csv(f, encoding='latin1', on_bad_lines='skip')
            df.columns = [col.strip() for col in df.columns]
            parts.append(df)

    return pd.concat(parts, ignore_index=True)


def main():
    print("Iniciando pré-processamento do dataset CIC-IDS2017...")
    df = load_all_csv(CICIDS_CSV)
    print(f"Total de {len(df)} linhas lidas de {len(list(CICIDS_CSV.glob('*.csv')))} arquivos.")

    # Seleciona as colunas de interesse, lidando com os nomes variados
    cols_to_keep = {}
    for key, names in CANDIDATES.items():
        col_name = pick_col(df, names)
        if col_name:
            cols_to_keep[key] = col_name
        else:
            print(f"AVISO: Nenhuma coluna encontrada para '{key}'. Pulando.")

    if len(cols_to_keep) < len(CANDIDATES):
        raise ValueError("Não foi possível encontrar todas as colunas necessárias. Verifique o dataset.")

    # Renomeia as colunas para um padrão
    tmp = df[list(cols_to_keep.values())].copy()
    tmp.rename(columns={v: k for k, v in cols_to_keep.items()}, inplace=True)

    # Limpeza e engenharia de features
    tmp.replace([np.inf, -np.inf], np.nan, inplace=True)
    tmp.dropna(inplace=True)

    # Converte colunas para numérico, forçando erros para NaN e depois preenchendo com 0
    for col in ['flow_duration', 'fwd_pkts', 'bwd_pkts', 'fwd_bytes', 'bwd_bytes']:
        tmp[col] = pd.to_numeric(tmp[col], errors='coerce')
    tmp.fillna(0, inplace=True)

    # Normaliza a duração para segundos (o original está em microssegundos)
    tmp['duration_s'] = tmp['flow_duration'] / 1e6

    tmp['tot_pkts'] = tmp['fwd_pkts'] + tmp['bwd_pkts']
    tmp['tot_bytes'] = tmp['fwd_bytes'] + tmp['bwd_bytes']

    # Evita divisão por zero
    tmp['pkts_per_sec'] = tmp['tot_pkts'] / tmp['duration_s'].replace(0, 1)
    tmp['bytes_per_sec'] = tmp['tot_bytes'] / tmp['duration_s'].replace(0, 1)

    # Normaliza os rótulos
    tmp['label'] = tmp['label'].map(LABEL_MAP).fillna('OUTROS')

    # Seleciona as colunas finais
    features = ['duration_s', 'tot_pkts', 'tot_bytes', 'pkts_per_sec', 'bytes_per_sec']
    out = tmp[features + ['label']].copy()

    # Garante que não haja valores infinitos no resultado final
    out.replace([np.inf, -np.inf], 0, inplace=True)

    # Salva o arquivo processado
    PROCESSED.mkdir(parents=True, exist_ok=True)
    out.to_csv(FLOWS_LABELED, index=False)

    print("\n" + "=" * 50)
    print(f"SUCESSO: {FLOWS_LABELED} salvo com {len(out)} linhas.")
    print("Contagem de Rótulos no arquivo final:")
    print(out['label'].value_counts())
    print("=" * 50)


if __name__ == '__main__':
    main()