import pandas as pd
import numpy as np
import pickle
from sklearn.model_selection import train_test_split
from sklearn.ensemble import (GradientBoostingClassifier,
                               RandomForestClassifier,
                               ExtraTreesClassifier,
                               VotingClassifier)
from sklearn import metrics

print("Loading dataset...")
data = pd.read_csv(r"D:\PROJECT (PHISING)\DataFiles\phishing.csv")
data = data.drop(['Index'], axis=1)

y = data['class']
X = data.drop('class', axis=1)

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)
print(f"Train: {X_train.shape} | Test: {X_test.shape}")

gbc_v = GradientBoostingClassifier(
    n_estimators=200, max_depth=4, learning_rate=0.1,
    subsample=0.8, max_features='sqrt', random_state=42
)
rf_v = RandomForestClassifier(
    n_estimators=200, max_features='sqrt',
    min_samples_leaf=2, random_state=42, n_jobs=-1
)
et_v = ExtraTreesClassifier(
    n_estimators=200, max_features='sqrt',
    min_samples_leaf=2, random_state=42, n_jobs=-1
)

best_model = VotingClassifier(
    estimators=[('gbc', gbc_v), ('rf', rf_v), ('et', et_v)],
    voting='soft'
)

print("Training... (1-2 min lagenge)")
best_model.fit(X_train, y_train)

y_pred = best_model.predict(X_test)
print(f"Accuracy: {metrics.accuracy_score(y_test, y_pred):.4f}")

pickle.dump(best_model, open(r"D:\PROJECT (PHISING)\newmodel.pkl", 'wb'))
print("newmodel.pkl saved!")

loaded = pickle.load(open(r"D:\PROJECT (PHISING)\newmodel.pkl", 'rb'))
print(f"Verified: {metrics.accuracy_score(y_test, loaded.predict(X_test)):.4f}")
print("Done! Ab app.py run kar.")