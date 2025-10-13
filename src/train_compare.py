import json
import joblib
import pandas as pd
import numpy as np  # Adicionado import
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import classification_report, ConfusionMatrixDisplay
from sklearn.ensemble import RandomForestClassifier
from sklearn.neural_network import MLPClassifier
from xgboost import XGBClassifier
from config import FLOWS_LABELED, BEST_MODEL, SCALER_PATH, LABEL_ENCODER, METRICS_JSON, CONF_MATRIX_PNG, FEATURES

print("Iniciando o treinamento e comparação de modelos...")

# Carrega o dataset processado
df = pd.read_csv(FLOWS_LABELED)
X = df[FEATURES]
y = df['label']

# --- CONFIRME QUE ESTE TRECHO EXISTE ---
# Aplica a transformação logarítmica para suavizar valores extremos
# PARA:
# Aplica a transformação logarítmica apenas na coluna necessária
X.loc[:, 'pkts_per_sec'] = np.log1p(X['pkts_per_sec'].values)

# ADICIONE ESTAS DUAS LINHAS PARA LIMPEZA FINAL
X.replace([np.inf, -np.inf], np.nan, inplace=True)
X.fillna(0, inplace=True)

print("Transformação logarítmica e limpeza final aplicadas às features de treino.")
# --- FIM DO TRECHO A SER CONFIRMADO ---

print(f"Dataset carregado com {len(df)} amostras.")

# Codifica os rótulos
le = LabelEncoder()
y_enc = le.fit_transform(y)

# Divide os dados em treino e teste
X_train, X_test, y_train, y_test = train_test_split(
    X, y_enc, test_size=0.3, stratify=y_enc, random_state=42
)
print(f"Dados divididos em {len(X_train)} para treino e {len(X_test)} para teste.")

# Escalonamento dos dados
scaler = StandardScaler()
X_train_s = scaler.fit_transform(X_train)
X_test_s = scaler.transform(X_test)
print("Escalonamento de features aplicado.")

# Dicionário com os modelos
candidates = {
    'RandomForest': RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1),
    'XGBoost': XGBClassifier(n_estimators=100, random_state=42, use_label_encoder=False, eval_metric='mlogloss'),
    'MLP': MLPClassifier(hidden_layer_sizes=(64,), max_iter=200, random_state=42, early_stopping=True)
}

metrics_all = {}
best_name = None
best_f1_macro = -1
best_clf = None

# Loop para treinar e avaliar cada modelo
for name, clf in candidates.items():
    print(f"\n--- Treinando modelo: {name} ---")
    clf.fit(X_train_s, y_train)
    y_pred = clf.predict(X_test_s)

    report_dict = classification_report(y_test, y_pred, target_names=le.classes_, output_dict=True)
    report_text = classification_report(y_test, y_pred, target_names=le.classes_)

    f1_macro = report_dict['macro avg']['f1-score']
    metrics_all[name] = report_dict

    print(f"Relatório de Classificação para {name}:\n{report_text}")

    if f1_macro > best_f1_macro:
        best_f1_macro = f1_macro
        best_name = name
        best_clf = clf

print(f"\n--- Melhor modelo encontrado: {best_name} com F1-Macro de {best_f1_macro:.4f} ---")

# Salvar os artefatos
print("Salvando artefatos (modelo, scaler, encoder)...")
joblib.dump(best_clf, BEST_MODEL)
joblib.dump(scaler, SCALER_PATH)
joblib.dump(le, LABEL_ENCODER)

with open(METRICS_JSON, 'w', encoding='utf-8') as f:
    json.dump({'best_model': best_name, 'reports': metrics_all}, f, indent=2, ensure_ascii=False)

print("Gerando e salvando a Matriz de Confusão...")
fig, ax = plt.subplots(figsize=(10, 10))
ConfusionMatrixDisplay.from_estimator(best_clf, X_test_s, y_test, display_labels=le.classes_,
                                      xticks_rotation='vertical', ax=ax)
plt.title(f'Matriz de Confusão - {best_name}')
plt.tight_layout()
fig.savefig(CONF_MATRIX_PNG)

print("\n" + "=" * 50)
print("SUCESSO: Treinamento concluído!")
print(f"Melhor modelo '{best_name}' salvo em: {BEST_MODEL}")
print(f"Métricas salvas em: {METRICS_JSON}")
print(f"Matriz de Confusão salva em: {CONF_MATRIX_PNG}")
print("=" * 50)