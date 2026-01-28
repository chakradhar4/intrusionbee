import pandas as pd

train_df = pd.read_csv("data/UNSW_NB15_training-set.csv")
test_df  = pd.read_csv("data/UNSW_NB15_testing-set.csv")

print("Train shape:", train_df.shape)
print("Test shape :", test_df.shape)

print("\nLabel distribution (train):")
print(train_df["label"].value_counts())

print("\nColumns:")
print(train_df.columns.tolist())
