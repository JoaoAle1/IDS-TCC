# =============================================================
# src/app_streamlit.py (VERSÃO ATUALIZADA COM BOTÃO E 3 FEATURES)
# =============================================================
import streamlit as st
import pandas as pd
import json
from pathlib import Path
from datetime import datetime
from config import ALERTS_LOG, METRICS_JSON, CONF_MATRIX_PNG
import subprocess
import sys

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
            # Tenta adicionar um timestamp real da última modificação do arquivo de log
            try:
                mtime = log_path.stat().st_mtime
                df['timestamp'] = pd.to_datetime(mtime, unit='s')
            except Exception:
                df['timestamp'] = pd.to_datetime(datetime.now())  # Fallback
            return df
    return pd.DataFrame()


# --- Carregamento dos Dados ---
metrics_data = load_metrics_data()
alerts_df = load_alerts_data()

# =============================================================
# --- BARRA LATERAL (SIDEBAR) ---
# (Movido da Aba 2 para ser global e adicionado o botão)
# =============================================================
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
    selected_types = []  # Define valores padrão se alerts_df estiver vazio
    ip_filter = ""  # Define valores padrão se alerts_df estiver vazio

# --- Bloco do Botão de Captura (NOVO) ---
st.sidebar.header("Controles de Captura")
# !!! IMPORTANTE: Verifique se "Ethernet" é o nome correto da sua interface !!!
INTERFACE_DE_CAPTURA = "Ethernet"

if st.sidebar.button(f"Iniciar Captura de 60s na Interface '{INTERFACE_DE_CAPTURA}'"):

    # Pega o caminho exato do executável Python que está rodando o Streamlit
    python_executable = sys.executable

    # Monta o comando
    command = [
        python_executable,
        "src/live_capture.py",
        "--interface",
        INTERFACE_DE_CAPTURA,
        "--seconds",
        "60"
    ]

    st.sidebar.write("Iniciando captura de 60 segundos...")

    # Mostra um "spinner" (ícone de carregamento) enquanto o comando roda
    with st.spinner(f"Capturando tráfego em '{INTERFACE_DE_CAPTURA}'... O dashboard ficará ocupado por 60 segundos."):
        try:
            # Executa o comando e captura a saída
            result = subprocess.run(command, capture_output=True, text=True, check=True, encoding='utf-8')

            # Mostra a saída do script (incluindo a tabela de DEBUG e os alertas)
            st.sidebar.subheader("Resultado da Captura:")
            st.sidebar.code(result.stdout)

            if result.stderr:
                st.sidebar.error("Erros da captura:")
                st.sidebar.code(result.stderr)

            st.sidebar.success("Captura concluída! Os alertas foram salvos.")
            st.sidebar.info("Por favor, ATUALIZE (F5) a página para ver os novos alertas no dashboard.")

        except subprocess.CalledProcessError as e:
            # Se o script falhar (ex: permissão negada)
            st.sidebar.error("A captura falhou!")
            st.sidebar.subheader("Saída do Erro:")
            st.sidebar.code(e.stdout)
            st.sidebar.code(e.stderr)
            st.sidebar.warning(
                "Lembre-se: O Streamlit deve ser executado como Administrador para que a captura funcione.")
        except FileNotFoundError:
            st.sidebar.error(f"Erro: Não foi possível encontrar o script 'src/live_capture.py'.")
        except Exception as e:
            st.sidebar.error("Um erro inesperado ocorreu:")
            st.sidebar.code(str(e))
# --- Fim do Bloco do Botão ---


# =============================================================
# --- Definição das Abas ---
# =============================================================
tab_overview, tab_alerts, tab_performance = st.tabs([
    "Visão Geral 📈",
    "Análise de Alertas 🚨",
    "Desempenho do Modelo 🧠"
])

# --- MUDANÇA AQUI: Define as colunas que queremos exibir ---
# (Apenas as 3 features do modelo, mais os identificadores)
COLUNAS_PARA_MOSTRAR = ['flow_key', 'duration_s', 'tot_pkts', 'pkts_per_sec', 'predicted_label', 'timestamp']


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
        # --- MUDANÇA AQUI ---
        # Filtra o dataframe para mostrar apenas as colunas selecionadas
        # Verifica se as colunas existem no DataFrame antes de tentar exibi-las
        cols_display_aba1 = [col for col in COLUNAS_PARA_MOSTRAR if col in alerts_df.columns]
        st.dataframe(alerts_df.head(10)[cols_display_aba1], use_container_width=True)

    else:
        st.info("Nenhum alerta detectado ainda. Rode os scripts de captura (offline ou live) para gerar dados.")

# --- Aba 2: Análise de Alertas ---
with tab_alerts:
    st.header("Explorador de Alertas Detalhados")

    if not alerts_df.empty:
        # --- Aplicação dos Filtros ---
        # (As variáveis 'selected_types' e 'ip_filter' agora vêm da sidebar global)
        filtered_df = alerts_df[alerts_df['predicted_label'].isin(selected_types)]

        if ip_filter:
            filtered_df = filtered_df[filtered_df['flow_key'].str.contains(ip_filter, na=False, case=False)]

        st.subheader(f"Exibindo {len(filtered_df)} de {len(alerts_df)} alertas")
        # --- MUDANÇA AQUI ---
        # Filtra o dataframe para mostrar apenas as colunas selecionadas
        # Verifica se as colunas existem no DataFrame antes de tentar exibi-las
        cols_display_aba2 = [col for col in COLUNAS_PARA_MOSTRAR if col in filtered_df.columns]
        st.dataframe(filtered_df[cols_display_aba2], use_container_width=True)

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