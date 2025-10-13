import argparse
import json
import joblib
import pyshark
import numpy as np  # Adicionado import
from config import BEST_MODEL, SCALER_PATH, LABEL_ENCODER, ALERTS_LOG, FEATURES
from feature_extractor import FlowAggregator


def predict_pcap(pcap_path: str):
    """Lê um arquivo PCAP, extrai features, faz predições e loga alertas."""
    print(f"Carregando modelo de: {BEST_MODEL}")
    model = joblib.load(BEST_MODEL)
    scaler = joblib.load(SCALER_PATH)
    le = joblib.load(LABEL_ENCODER)

    print(f"Processando arquivo PCAP: {pcap_path}...")
    agg = FlowAggregator()

    try:
        cap = pyshark.FileCapture(pcap_path)
        for pkt in cap:
            agg.add_packet(pkt)
        cap.close()
    except Exception as e:
        print(f"Erro ao ler o arquivo PCAP com PyShark/TShark: {e}")
        return

    df_flows = agg.finalize_dataframe()

    if df_flows.empty:
        print("Nenhum fluxo de rede (IP) foi extraído do arquivo PCAP.")
        return

    print(f"{len(df_flows)} fluxos extraídos para análise.")

    X_flows = df_flows[FEATURES]

    # --- INÍCIO DA MUDANÇA ---
    # Aplica a mesma transformação logarítmica usada no treino
    # PARA:
    # Aplica a transformação logarítmica apenas na coluna necessária
    X_flows.loc[:, 'pkts_per_sec'] = np.log1p(X_flows['pkts_per_sec'].values)
    # --- FIM DA MUDANÇA ---

    X_scaled = scaler.transform(X_flows)
    predictions = model.predict(X_scaled)
    labels = le.inverse_transform(predictions)
    df_flows['predicted_label'] = labels

    alerts = df_flows[df_flows['predicted_label'] != 'BENIGN']

    print(f"Análise completa. {len(alerts)} alertas detectados.")

    if not alerts.empty:
        print("Top 10 Alertas:")
        print(alerts[['flow_key', 'predicted_label', 'duration_s', 'tot_pkts', 'tot_bytes']].head(10))

        with open(ALERTS_LOG, 'a', encoding='utf-8') as f:
            for _, alert in alerts.iterrows():
                log_entry = alert.to_dict()
                f.write(json.dumps(log_entry) + "\n")
        print(f"Alertas salvos em: {ALERTS_LOG}")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Analisa um arquivo PCAP para detectar ataques de rede.")
    parser.add_argument('--pcap', required=True, help='Caminho para o arquivo .pcap a ser analisado.')
    args = parser.parse_args()
    predict_pcap(args.pcap)