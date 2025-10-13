import argparse
import json
import joblib
import time
import pyshark
import numpy as np  # Adicionado import
from pyshark.tshark.tshark import get_tshark_interfaces
from config import BEST_MODEL, SCALER_PATH, LABEL_ENCODER, ALERTS_LOG, FEATURES
from feature_extractor import FlowAggregator


def list_interfaces():
    """Lista as interfaces de rede disponíveis usando o TShark."""
    print("Interfaces de rede disponíveis (detectadas pelo TShark):")
    try:
        interfaces = get_tshark_interfaces()
        for iface in interfaces:
            print(f"- {iface}")
    except Exception as e:
        print(f"Erro ao listar interfaces: {e}")


def live_capture(interface: str, seconds: int):
    """Captura tráfego em tempo real, faz predições e loga alertas."""
    print(f"Carregando modelo de: {BEST_MODEL}")
    model = joblib.load(BEST_MODEL)
    scaler = joblib.load(SCALER_PATH)
    le = joblib.load(LABEL_ENCODER)

    agg = FlowAggregator()

    print(f"Iniciando captura na interface '{interface}' por {seconds} segundos...")
    print("Pressione CTRL+C para parar a captura antes do tempo.")

    try:
        cap = pyshark.LiveCapture(interface=interface)

        start_time = time.time()
        for pkt in cap.sniff_continuously():
            agg.add_packet(pkt)
            if time.time() - start_time >= seconds:
                break
        cap.close()
    except Exception as e:
        print(f"Ocorreu um erro durante a captura: {e}")
        return

    print("\nCaptura finalizada. Processando fluxos...")

    df_flows = agg.finalize_dataframe()

    # Adicionando o debug print que nos ajudou a encontrar o problema
    print("\n--- DADOS DOS FLUXOS CAPTURADOS (DEBUG) ---")
    print(df_flows.head(20))

    if df_flows.empty:
        print("Nenhum fluxo de rede (IP) foi capturado.")
        return

    print(f"\n{len(df_flows)} fluxos capturados para análise.")

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
        print("Alertas:")
        print(alerts[['flow_key', 'predicted_label']])

        with open(ALERTS_LOG, 'a', encoding='utf-8') as f:
            for _, alert in alerts.iterrows():
                log_entry = alert.to_dict()
                f.write(json.dumps(log_entry) + "\n")
        print(f"Alertas salvos em: {ALERTS_LOG}")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Captura tráfego de rede em tempo real para detectar ataques.")
    parser.add_argument('--interface', help='Nome da interface de rede para captura. Rode sem argumentos para listar.')
    parser.add_argument('--seconds', type=int, default=60, help='Duração da captura em segundos.')
    args = parser.parse_args()

    if not args.interface:
        list_interfaces()
    else:
        live_capture(args.interface, args.seconds)