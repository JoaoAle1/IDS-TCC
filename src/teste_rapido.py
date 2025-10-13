import joblib
import numpy as np
import pandas as pd
from config import BEST_MODEL, SCALER_PATH, LABEL_ENCODER, FEATURES

print("--- INICIANDO TESTE RÁPIDO DO MODELO ---")

# Carrega os artefatos de IA que acabaram de ser treinados
try:
    model = joblib.load(BEST_MODEL)
    scaler = joblib.load(SCALER_PATH)
    le = joblib.load(LABEL_ENCODER)
    print("Modelo, Scaler e Encoder carregados com sucesso.")
except FileNotFoundError:
    print("\nERRO: Arquivos de modelo não encontrados! Você rodou o 'train_compare.py' primeiro?")
    exit()

# Cria uma amostra de ataque de Port Scan, baseada nos seus dados de debug
# (duração minúscula, 2 pacotes, pkts_per_sec altíssimo)
ataque_de_teste = {
    'duration_s': [0.00001],
    'tot_pkts': [2],
    'tot_bytes': [128],
    'pkts_per_sec': [150000.0],
    'bytes_per_sec': [9000000.0]
}
df_ataque = pd.DataFrame(ataque_de_teste)

print("\nDados do ataque de teste (antes da transformação):")
print(df_ataque)

# Aplica a MESMA transformação logarítmica
for col in ['pkts_per_sec', 'bytes_per_sec']:
    df_ataque.loc[:, col] = np.log1p(df_ataque[col].values)

print("\nDados do ataque de teste (DEPOIS da transformação logarítmica):")
print(df_ataque)

# Prepara os dados com o scaler
X_scaled = scaler.transform(df_ataque[FEATURES])

# Faz a predição
prediction_codificada = model.predict(X_scaled)
prediction_final = le.inverse_transform(prediction_codificada)

print("\n" + "="*50)
print(f"RESULTADO DA PREDIÇÃO: {prediction_final}")
print("="*50)

if prediction_final[0] == 'PORTSCAN':
    print("\nSUCESSO! O modelo treinado está funcionando corretamente.")
else:
    print("\nFALHA. O modelo treinado ainda não está reconhecendo o padrão de ataque.")