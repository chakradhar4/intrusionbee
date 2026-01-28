import pandas as pd
import numpy as np
import joblib


from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import confusion_matrix, classification_report

print("Loading data...")

train_df = pd.read_csv("data/UNSW_NB15_training-set.csv")
test_df  = pd.read_csv("data/UNSW_NB15_testing-set.csv")

print("Train/Test loaded:", train_df.shape, test_df.shape)

DROP_COLS = ["id", "attack_cat"]

X_train = train_df.drop(columns=DROP_COLS + ["label"])
y_train = train_df["label"]

X_test  = test_df.drop(columns=DROP_COLS + ["label"])
y_test  = test_df["label"]

X_train = X_train.replace([np.inf, -np.inf], np.nan)
X_test  = X_test.replace([np.inf, -np.inf], np.nan)

cat_cols = X_train.select_dtypes(include="object").columns.tolist()
num_cols = [c for c in X_train.columns if c not in cat_cols]

print("Numeric cols:", len(num_cols), "Categorical cols:", len(cat_cols))
print("Building pipeline...")

num_tf = Pipeline([
    ("imputer", SimpleImputer(strategy="median")),
    ("scaler", StandardScaler())
])

cat_tf = Pipeline([
    ("imputer", SimpleImputer(strategy="most_frequent")),
    ("onehot", OneHotEncoder(handle_unknown="ignore"))
])

preprocess = ColumnTransformer([
    ("num", num_tf, num_cols),
    ("cat", cat_tf, cat_cols)
])

model = LogisticRegression(max_iter=2000, class_weight="balanced")

pipe = Pipeline([
    ("prep", preprocess),
    ("model", model)
])

print("Training...")
pipe.fit(X_train, y_train)
print("Training done.")

print("Evaluating...")
pred = pipe.predict(X_test)

print("\nConfusion Matrix:")
print(confusion_matrix(y_test, pred))

print("\nClassification Report:")
print(classification_report(y_test, pred, digits=4))

joblib.dump(pipe, "ids_pipeline.joblib")
print("Saved ids_pipeline.joblib")
