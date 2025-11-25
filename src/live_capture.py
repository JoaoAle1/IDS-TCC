# =============================================================
# src/live_capture.py (VERSÃO FINAL - COM FILTRO DE DURAÇÃO)
# =============================================================
import argparse
import json
import joblib
import time
import pyshark
import numpy as np
import pandas as pd
from datetime import datetime
from pyshark.tshark.tshark import get_tshark_interfaces
from config import BEST_MODEL, SCALER_PATH, LABEL_ENCODER, ALERTS_LOG, FEATURES
from feature_extractor import FlowAggregator


def list_interfaces():
    print("Interfaces disponíveis (TShark):")
    try:
        interfaces = get_tshark_interfaces()
        for iface in interfaces:
            print(f"- {iface}")
    except Exception as e:
        print(f"Erro ao listar: {e}")


def live_capture(interface: str, seconds: int):
    print(f"Carregando modelo de: {BEST_MODEL}")
    model = joblib.load(BEST_MODEL)
    scaler = joblib.load(SCALER_PATH)
    le = joblib.load(LABEL_ENCODER)

    agg = FlowAggregator()

    print(f"Capturando em '{interface}' por {seconds}s...")

    try:
        cap = pyshark.LiveCapture(interface=interface)
        start_time = time.time()
        for pkt in cap.sniff_continuously():
            agg.add_packet(pkt)
            if time.time() - start_time >= seconds:
                break
        cap.close()
    except Exception as e:
        print(f"Erro na captura: {e}")
        return

    print("\nProcessando fluxos...")
    df_flows = agg.finalize_dataframe()

    if df_flows.empty:
        print("Nenhum fluxo capturado.")
        return

    # --- FILTRO DE RUÍDO (Broadcast/Multicast) ---
    filtro_broadcast = df_flows['flow_key'].str.contains(r'\.255:|224\.|239\.|ff02', regex=True)
    df_flows = df_flows[~filtro_broadcast]

    # --- OPÇÃO 1: FILTRO DE DURAÇÃO (O segredo para limpar os falsos positivos) ---
    # Ignora fluxos "lentos" (> 1.0s) que geralmente são tráfego normal (downloads, vídeos).
    # Ataques como PortScan e DDoS (do tipo que o modelo aprendeu) são explosivos (< 1s).
    df_flows = df_flows[df_flows['duration_s'] < 1.0]

    if df_flows.empty:
        print("Apenas tráfego de fundo (normal/lento) foi capturado. Ignorando.")
        return
    # ------------------------------------------------------------------------------

    print("\n--- DADOS SUSPEITOS PARA ANÁLISE ---")
    print(df_flows.head(5))

    # Preenche colunas se faltar alguma
    for f in FEATURES:
        if f not in df_flows.columns:
            df_flows[f] = 0

    X_flows = df_flows[FEATURES].copy()

    # Logaritmo apenas em pkts_per_sec
    X_flows.loc[:, 'pkts_per_sec'] = np.log1p(X_flows['pkts_per_sec'].values)

    X_flows.replace([np.inf, -np.inf], np.nan, inplace=True)
    X_flows.fillna(0, inplace=True)

    X_scaled = scaler.transform(X_flows)
    predictions = model.predict(X_scaled)
    labels = le.inverse_transform(predictions)
    df_flows['predicted_label'] = labels

    alerts = df_flows[df_flows['predicted_label'] != 'BENIGN']

    print(f"Análise completa. {len(alerts)} alertas detectados.")

    if not alerts.empty:
        with open(ALERTS_LOG, 'a', encoding='utf-8') as f:
            for _, alert in alerts.iterrows():
                log_entry = alert.to_dict()
                # Timestamps reais
                log_entry['timestamp'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                f.write(json.dumps(log_entry) + "\n")
        print(f"Alertas salvos em: {ALERTS_LOG}")


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--interface')
    parser.add_argument('--seconds', type=int, default=60)
    args = parser.parse_args()

    try:
        if not args.interface:
            list_interfaces()
        else:
            live_capture(args.interface, args.seconds)
    except KeyboardInterrupt:
        print("\nInterrompido.")
    except Exception as e:
        print(f"\nErro: {e}")