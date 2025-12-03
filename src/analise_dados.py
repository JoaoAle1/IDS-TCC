import pandas as pd
import numpy as np
from config import FLOWS_LABELED, FEATURES

print("--- INICIANDO ANÁLISE COMPARATIVA DE DADOS ---")


try:
    df_treino = pd.read_csv(FLOWS_LABELED)
except FileNotFoundError:
    print(f"ERRO: Arquivo {FLOWS_LABELED} não encontrado. Execute o 'data_prep_cicids.py' primeiro.")
    exit()


dados_captura_ao_vivo = {
    'duration_s': [0.000004, 0.000010, 0.000025],
    'tot_pkts': [2, 2, 2],
    'tot_bytes': [128, 128, 128],
    'pkts_per_sec': [493447.0, 199728.0, 80659.0],
    'bytes_per_sec': [31580640.0, 12782640.0, 5162220.0]
}
df_captura = pd.DataFrame(dados_captura_ao_vivo)


df_treino_portscan = df_treino[df_treino['label'] == 'PORTSCAN'].copy()


for col in ['pkts_per_sec', 'bytes_per_sec']:
    df_treino_portscan.loc[:, col] = np.log1p(df_treino_portscan[col].values)
    df_captura.loc[:, col] = np.log1p(df_captura[col].values)


df_treino_portscan = df_treino_portscan[FEATURES]


print("\n" + "="*80)
print("MUNDO 1: Resumo Estatístico dos ataques PORTSCAN no Dataset de Treino (CIC-IDS2017)")
print("="*80)
print(df_treino_portscan.describe())

print("\n" + "="*80)
print("MUNDO 2: Resumo Estatístico do seu ataque de Port Scan (Captura Ao Vivo)")
print("="*80)
print(df_captura.describe())