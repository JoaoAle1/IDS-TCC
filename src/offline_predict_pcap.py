# =============================================================
# src/offline_predict_pcap.py (VERSÃO FINAL)
# =============================================================
import argparse
import json
import joblib
import pyshark
import numpy as np
import pandas as pd
from config import BEST_MODEL, SCALER_PATH, LABEL_ENCODER, ALERTS_LOG, FEATURES
from feature_extractor import FlowAggregator


def predict_pcap(pcap_path: str):
    print(f"Carregando modelo: {BEST_MODEL}")
    model = joblib.load(BEST_MODEL)
    scaler = joblib.load(SCALER_PATH)
    le = joblib.load(LABEL_ENCODER)

    print(f"Lendo PCAP: {pcap_path}...")
    agg = FlowAggregator()

    try:
        cap = pyshark.FileCapture(pcap_path)
        for pkt in cap:
            agg.add_packet(pkt)
        cap.close()
    except Exception as e:
        print(f"Erro: {e}")
        return

    df_flows = agg.finalize_dataframe()

    if df_flows.empty:
        print("Nenhum fluxo extraído.")
        return

    # Preenche colunas
    for f in FEATURES:
        if f not in df_flows.columns:
            df_flows[f] = 0

    X_flows = df_flows[FEATURES].copy()
    X_flows.loc[:, 'pkts_per_sec'] = np.log1p(X_flows['pkts_per_sec'].values)
    X_flows.replace([np.inf, -np.inf], np.nan, inplace=True)
    X_flows.fillna(0, inplace=True)

    X_scaled = scaler.transform(X_flows)
    predictions = model.predict(X_scaled)
    labels = le.inverse_transform(predictions)
    df_flows['predicted_label'] = labels

    alerts = df_flows[df_flows['predicted_label'] != 'BENIGN']

    print(f"Análise completa. {len(alerts)} alertas.")

    if not alerts.empty:
        with open(ALERTS_LOG, 'a', encoding='utf-8') as f:
            for _, alert in alerts.iterrows():
                log_entry = alert.to_dict()
                f.write(json.dumps(log_entry) + "\n")
        print(f"Salvo em: {ALERTS_LOG}")


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--pcap', required=True)
    args = parser.parse_args()
    predict_pcap(args.pcap)