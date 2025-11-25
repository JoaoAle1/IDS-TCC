# =============================================================
# src/train_compare.py (VERSÃO WEIGHTED AVG + 3 FEATURES)
# =============================================================
import json
import joblib
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import classification_report, ConfusionMatrixDisplay
from sklearn.ensemble import RandomForestClassifier
from sklearn.neural_network import MLPClassifier
from xgboost import XGBClassifier
from config import FLOWS_LABELED, BEST_MODEL, SCALER_PATH, LABEL_ENCODER, METRICS_JSON, CONF_MATRIX_PNG, FEATURES

print("Iniciando o treinamento (Métrica: F1-Weighted)...")

df = pd.read_csv(FLOWS_LABELED)
X = df[FEATURES]
y = df['label']

# --- TRANSFORMAÇÃO LOGARÍTMICA (Apenas pkts_per_sec) ---
if 'pkts_per_sec' in X.columns:
    X.loc[:, 'pkts_per_sec'] = np.log1p(X['pkts_per_sec'].values)

# Limpeza final
X.replace([np.inf, -np.inf], np.nan, inplace=True)
X.fillna(0, inplace=True)

print("Transformação logarítmica e limpeza aplicadas.")
print(f"Dataset carregado: {len(df)} amostras.")

le = LabelEncoder()
y_enc = le.fit_transform(y)

# Divisão 70/30 Estratificada
X_train, X_test, y_train, y_test = train_test_split(
    X, y_enc, test_size=0.3, stratify=y_enc, random_state=42
)

# Escalonamento
scaler = StandardScaler()
X_train_s = scaler.fit_transform(X_train)
X_test_s = scaler.transform(X_test)
print("Escalonamento aplicado.")

candidates = {
    'RandomForest': RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1),
    'XGBoost': XGBClassifier(n_estimators=100, random_state=42, use_label_encoder=False, eval_metric='mlogloss'),
    'MLP': MLPClassifier(hidden_layer_sizes=(64,), max_iter=200, random_state=42, early_stopping=True)
}

metrics_all = {}
best_name = None
best_f1_weighted = -1
best_clf = None

for name, clf in candidates.items():
    print(f"\n--- Treinando {name} ---")
    clf.fit(X_train_s, y_train)
    y_pred = clf.predict(X_test_s)

    # Relatório com zero_division=0 para evitar warnings
    report_dict = classification_report(y_test, y_pred, target_names=le.classes_, output_dict=True, zero_division=0)
    report_text = classification_report(y_test, y_pred, target_names=le.classes_, zero_division=0)

    # --- USANDO WEIGHTED AVG ---
    f1_weighted = report_dict['weighted avg']['f1-score']
    metrics_all[name] = report_dict

    print(f"Relatório para {name}:\n{report_text}")
    print(f"F1-Score (Weighted): {f1_weighted:.4f}")

    if f1_weighted > best_f1_weighted:
        best_f1_weighted = f1_weighted
        best_name = name
        best_clf = clf

print(f"\n--- VENCEDOR: {best_name} com F1-Weighted de {best_f1_weighted:.4f} ---")

print("Salvando artefatos...")
joblib.dump(best_clf, BEST_MODEL)
joblib.dump(scaler, SCALER_PATH)
joblib.dump(le, LABEL_ENCODER)

with open(METRICS_JSON, 'w', encoding='utf-8') as f:
    json.dump({'best_model': best_name, 'reports': metrics_all}, f, indent=2, ensure_ascii=False)

print("Gerando Matriz de Confusão...")
fig, ax = plt.subplots(figsize=(10, 10))
ConfusionMatrixDisplay.from_estimator(best_clf, X_test_s, y_test, display_labels=le.classes_, xticks_rotation='vertical', ax=ax)
plt.title(f'Matriz de Confusão - {best_name}')
plt.tight_layout()
fig.savefig(CONF_MATRIX_PNG)

print("Concluído!")