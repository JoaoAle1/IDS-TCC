# =============================================================
# src/app_streamlit.py
# =============================================================
import streamlit as st
import pandas as pd
import json
from pathlib import Path
from datetime import datetime
from config import ALERTS_LOG, METRICS_JSON, CONF_MATRIX_PNG

# --- Configurações da Página e Título ---
st.set_page_config(page_title="IDS Dashboard", layout="wide", initial_sidebar_state="auto")
st.title("🛡️ Dashboard de Detecção de Intrusão (IDS)")
st.markdown("Use este painel para monitorar o desempenho do modelo e analisar os alertas de segurança de rede.")

# Dicionário com descrições dos ataques para consulta
ATTACK_DESCRIPTIONS = {
    "PORTSCAN": "O ataque Port Scan consiste em varrer as portas de um computador para identificar serviços ativos e vulneráveis.",
    "DDOS": "O ataque de Negação de Serviço Distribuída (DDoS) visa sobrecarregar um servidor ou rede com tráfego massivo, tornando-o indisponível.",
    "SSH-BF": "SSH Brute Force é uma tentativa de adivinhar credenciais (usuário e senha) do serviço SSH por meio de tentativa e erro.",
    "OUTROS": "Categoria para outros tipos de tráfego malicioso que não se enquadram nas classes principais."
}


# --- Funções de Carregamento de Dados (com cache para performance) ---

@st.cache_data(ttl=60)  # Atualiza os dados a cada 60 segundos
def load_metrics_data():
    """Carrega as métricas de treino do arquivo JSON."""
    if Path(METRICS_JSON).exists():
        return json.loads(Path(METRICS_JSON).read_text(encoding='utf-8'))
    return None


@st.cache_data(ttl=10)  # Atualiza os alertas a cada 10 segundos
def load_alerts_data():
    """Carrega os alertas do arquivo JSONL e os transforma em um DataFrame."""
    log_path = Path(ALERTS_LOG)
    if log_path.exists():
        lines = [json.loads(x) for x in log_path.read_text(encoding='utf-8').splitlines() if x.strip()]
        if lines:
            df = pd.DataFrame(lines).sort_index(ascending=False).reset_index(drop=True)
            df['timestamp'] = pd.to_datetime(datetime.now())  # Adiciona timestamp da última atualização
            return df
    return pd.DataFrame()


# --- Carregamento dos Dados ---
metrics_data = load_metrics_data()
alerts_df = load_alerts_data()

# --- Definição das Abas ---
tab_overview, tab_alerts, tab_performance = st.tabs([
    "Visão Geral 📈",
    "Análise de Alertas 🚨",
    "Desempenho do Modelo 🧠"
])

# --- Aba 1: Visão Geral ---
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
        st.dataframe(alerts_df.head(10), use_container_width=True)

    else:
        st.info("Nenhum alerta detectado ainda. Rode os scripts de captura (offline ou live) para gerar dados.")

# --- Aba 2: Análise de Alertas ---
with tab_alerts:
    st.header("Explorador de Alertas Detalhados")

    if not alerts_df.empty:
        # --- Filtros na Sidebar ---
        st.sidebar.header("Filtros de Alertas")
        unique_attack_types = alerts_df['predicted_label'].unique()

        selected_types = st.sidebar.multiselect(
            "Filtrar por tipo de ataque:",
            options=unique_attack_types,
            default=list(unique_attack_types)
        )

        ip_filter = st.sidebar.text_input("Filtrar por IP/Chave de fluxo:")

        # --- Aplicação dos Filtros ---
        filtered_df = alerts_df[alerts_df['predicted_label'].isin(selected_types)]

        if ip_filter:
            filtered_df = filtered_df[filtered_df['flow_key'].str.contains(ip_filter, na=False, case=False)]

        st.subheader(f"Exibindo {len(filtered_df)} de {len(alerts_df)} alertas")
        st.dataframe(filtered_df, use_container_width=True)

        # --- Descrições dos Ataques Filtrados ---
        st.subheader("O que estes ataques significam?")
        for attack_type in selected_types:
            if attack_type in ATTACK_DESCRIPTIONS:
                with st.expander(f"Definição de **{attack_type}**"):
                    st.write(ATTACK_DESCRIPTIONS[attack_type])
    else:
        st.info("Nenhum alerta para analisar.")

# --- Aba 3: Desempenho do Modelo ---
with tab_performance:
    st.header("Métricas e Performance do Modelo de Machine Learning")

    if metrics_data:
        best_model_name = metrics_data.get('best_model', 'Não definido')
        st.subheader(f"Melhor Modelo Selecionado: **{best_model_name}**")

        st.write("A seleção foi baseada na métrica 'F1-Score' durante a fase de testes.")

        # Exibir Matriz de Confusão
        if Path(CONF_MATRIX_PNG).exists():
            st.image(str(CONF_MATRIX_PNG), caption=f"Matriz de Confusão para o modelo {best_model_name}")

        # Tabela comparativa
        st.subheader("Relatório Comparativo dos Modelos (Macro Avg)")
        if 'reports' in metrics_data:
            rows = []
            for name, rep in metrics_data['reports'].items():
                macro = rep.get('macro avg', {})
                rows.append({
                    'Modelo': name,
                    'Precisão': macro.get('precision'),
                    'Recall': macro.get('recall'),
                    'F1-Score': macro.get('f1-score')
                })
            dfm = pd.DataFrame(rows)
            st.dataframe(dfm, use_container_width=True)
    else:
        st.warning("Arquivo de métricas não encontrado. Execute `src/train_compare.py` para gerar os dados.")