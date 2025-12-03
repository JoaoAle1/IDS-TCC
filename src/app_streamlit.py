
import streamlit as st
import pandas as pd
import json
from pathlib import Path
from datetime import datetime
from config import ALERTS_LOG, METRICS_JSON, CONF_MATRIX_PNG
import subprocess
import sys


st.set_page_config(page_title="IDS Dashboard", layout="wide", initial_sidebar_state="auto")
st.title("🛡️ Dashboard de Detecção de Intrusão (IDS)")
st.markdown("Use este painel para monitorar o desempenho do modelo e analisar os alertas de segurança de rede.")


ATTACK_DESCRIPTIONS = {
    "PORTSCAN": "O ataque Port Scan consiste em varrer as portas de um computador para identificar serviços ativos e vulneráveis.",
    "DDOS": "O ataque de Negação de Serviço Distribuída (DDoS) visa sobrecarregar um servidor ou rede com tráfego massivo, tornando-o indisponível.",
    "SSH-BF": "SSH Brute Force é uma tentativa de adivinhar credenciais (usuário e senha) do serviço SSH por meio de tentativa e erro.",
    "OUTROS": "Categoria para outros tipos de tráfego malicioso que não se enquadram nas classes principais."
}




@st.cache_data(ttl=60)
def load_metrics_data():
    """Carrega as métricas de treino do arquivo JSON."""
    if Path(METRICS_JSON).exists():
        return json.loads(Path(METRICS_JSON).read_text(encoding='utf-8'))
    return None


def load_alerts_data():
    """Carrega os alertas do arquivo JSONL sem cache."""
    log_path = Path(ALERTS_LOG)
    if log_path.exists():
        lines = [json.loads(x) for x in log_path.read_text(encoding='utf-8').splitlines() if x.strip()]
        if lines:
            df = pd.DataFrame(lines)

            if 'timestamp' not in df.columns:
                df['timestamp'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            df = df.sort_values(by='timestamp', ascending=False).reset_index(drop=True)
            return df
    return pd.DataFrame()


metrics_data = load_metrics_data()
alerts_df = load_alerts_data()




st.sidebar.header("Filtros de Alertas")
if not alerts_df.empty:
    unique_attack_types = alerts_df['predicted_label'].unique()
    selected_types = st.sidebar.multiselect(
        "Filtrar por tipo de ataque:",
        options=unique_attack_types,
        default=list(unique_attack_types)
    )
    ip_filter = st.sidebar.text_input("Filtrar por IP/Chave de fluxo:")
else:
    st.sidebar.info("Nenhum alerta para filtrar.")
    selected_types = []
    ip_filter = ""


st.sidebar.header("Controles de Captura")
INTERFACE_DE_CAPTURA = "Ethernet"

if st.sidebar.button(f"Iniciar Captura de 60s na Interface '{INTERFACE_DE_CAPTURA}'"):

    python_executable = sys.executable

    command = [
        python_executable,
        "src/live_capture.py",
        "--interface",
        INTERFACE_DE_CAPTURA,
        "--seconds",
        "60"
    ]

    st.sidebar.write("Iniciando captura de 60 segundos...")

    with st.spinner(f"Capturando tráfego em '{INTERFACE_DE_CAPTURA}'... O dashboard ficará ocupado por 60 segundos."):
        try:

            result = subprocess.run(command, capture_output=True, text=True, check=True, encoding='utf-8',
                                    errors='ignore')

            if result.stderr:

                st.sidebar.error("Aviso/Erro durante captura:")
                st.sidebar.code(result.stderr)

            st.sidebar.success("Captura concluída! Os alertas foram salvos.")
            st.sidebar.info("Por favor, ATUALIZE (F5) a página para ver os novos alertas.")

        except subprocess.CalledProcessError as e:
            st.sidebar.error("A captura falhou!")
            st.sidebar.code(e.stderr)
        except FileNotFoundError:
            st.sidebar.error(f"Erro: Script não encontrado.")
        except Exception as e:
            st.sidebar.error(f"Erro inesperado: {e}")




tab_overview, tab_alerts, tab_performance = st.tabs([
    "Visão Geral 📈",
    "Análise de Alertas 🚨",
    "Desempenho do Modelo 🧠"
])

COLUNAS_PARA_MOSTRAR = ['flow_key', 'duration_s', 'tot_pkts', 'pkts_per_sec', 'predicted_label', 'timestamp']


with tab_overview:
    st.header("Resumo da Atividade de Rede")

    if not alerts_df.empty:
        total_alerts = len(alerts_df)
        most_common_attack = alerts_df['predicted_label'].mode()[0] if not alerts_df['predicted_label'].empty else "N/A"

        col1, col2 = st.columns(2)
        with col1:
            st.metric(label="Total de Alertas Detectados", value=total_alerts)
        with col2:
            st.metric(label="Ataque Mais Comum", value=most_common_attack)

        st.subheader("Distribuição de Alertas por Tipo")
        attack_counts = alerts_df['predicted_label'].value_counts()
        st.bar_chart(attack_counts)

        st.subheader("Últimos Alertas Recebidos")
        cols_display_aba1 = [col for col in COLUNAS_PARA_MOSTRAR if col in alerts_df.columns]
        st.dataframe(alerts_df.head(10)[cols_display_aba1], use_container_width=True)

    else:
        st.info("Nenhum alerta detectado ainda.")


with tab_alerts:
    st.header("Explorador de Alertas Detalhados")

    if not alerts_df.empty:

        filtered_df = alerts_df[alerts_df['predicted_label'].isin(selected_types)]

        if ip_filter:
            filtered_df = filtered_df[filtered_df['flow_key'].str.contains(ip_filter, na=False, case=False)]

        st.subheader(f"Exibindo {len(filtered_df)} de {len(alerts_df)} alertas")

        cols_display_aba2 = [col for col in COLUNAS_PARA_MOSTRAR if col in filtered_df.columns]
        st.dataframe(filtered_df[cols_display_aba2], use_container_width=True)

        st.subheader("O que estes ataques significam?")
        for attack_type in selected_types:
            if attack_type in ATTACK_DESCRIPTIONS:
                with st.expander(f"Definição de **{attack_type}**"):
                    st.write(ATTACK_DESCRIPTIONS[attack_type])
    else:
        st.info("Nenhum alerta para analisar.")


with tab_performance:
    st.header("Métricas e Performance do Modelo de Machine Learning")

    if metrics_data:
        best_model_name = metrics_data.get('best_model', 'Não definido')
        st.subheader(f"Melhor Modelo Selecionado: **{best_model_name}**")

        st.write("A seleção foi baseada na métrica **'F1-Score (Weighted Avg)'** durante a fase de testes.")

        if Path(CONF_MATRIX_PNG).exists():
            st.image(str(CONF_MATRIX_PNG), caption=f"Matriz de Confusão para o modelo {best_model_name}")

        st.subheader("Relatório Comparativo dos Modelos (Weighted Avg)")
        if 'reports' in metrics_data:
            rows = []
            for name, rep in metrics_data['reports'].items():
                metrics = rep.get('weighted avg', rep.get('macro avg', {}))
                rows.append({
                    'Modelo': name,
                    'Precisão': metrics.get('precision'),
                    'Recall': metrics.get('recall'),
                    'F1-Score': metrics.get('f1-score')
                })
            dfm = pd.DataFrame(rows)
            st.dataframe(dfm, use_container_width=True)
    else:
        st.warning("Arquivo de métricas não encontrado.")