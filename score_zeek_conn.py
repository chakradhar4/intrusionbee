import pandas as pd
import joblib
import numpy as np

# Load trained IDS model pipeline
pipe = joblib.load("ids_pipeline.joblib")  # you will create this if not already saved

# Load Zeek conn data (tab-separated)
zeek_df = pd.read_csv("/Users/cghute/zeek-ids/conn.tsv", sep="\t", header=None, names=[
    "ts","uid","id.orig_h","id.orig_p","id.resp_h","id.resp_p",
    "proto","service","duration","orig_bytes","resp_bytes","conn_state"
])

# Minimal feature mapping (Zeek -> your model feature names)
# UNSW features you trained on include: dur, proto, service, state, spkts, dpkts, sbytes, dbytes, rate, ...
# We can map what we have; missing columns will be filled with 0.
mapped = pd.DataFrame()
mapped["dur"] = zeek_df["duration"].fillna(0)
mapped["proto"] = zeek_df["proto"].fillna("unknown")
mapped["service"] = zeek_df["service"].fillna("unknown")
mapped["state"] = zeek_df["conn_state"].fillna("UNK")

mapped["sbytes"] = zeek_df["orig_bytes"].fillna(0)
mapped["dbytes"] = zeek_df["resp_bytes"].fillna(0)

# Fill remaining required features with 0
# (This is a demo bridge; later we’ll engineer more from Zeek logs.)
required = pipe.feature_names_in_  # works if using sklearn >=1.0 and DataFrame input
for col in required:
    if col not in mapped.columns:
        mapped[col] = 0

mapped = mapped[required].replace([np.inf, -np.inf], np.nan)

# Predict
scores = pipe.predict_proba(mapped)[:, 1]
preds = (scores >= 0.5).astype(int)

out = zeek_df[["ts","id.orig_h","id.resp_h","proto","service","duration"]].copy()
out["attack_score"] = scores
out["pred_attack"] = preds

print(out.head(20))
print("\nTotal flows:", len(out))
print("Predicted attacks:", int(out["pred_attack"].sum()))
