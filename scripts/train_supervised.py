#!/usr/bin/env python3
"""
Off-device trainer for the NeuralGuard Phase-4 *supervised* scorer (ROADMAP 4c).

Trains a LightGBM classifier to recognize known-bad network behaviour, using a
public flow-based IDS dataset (CICIDS2017 or a CIC-FlowMeter CSV of the same
shape), and exports it to ONNX so ngd can score finished flows on-device, in
shadow mode, off the decision path - a second opinion alongside the anomaly
model (train_anomaly.py).

Why a *different, smaller* feature set than the anomaly model: a network IDS
dataset is captured on the wire, so it has no host-side context - it can't know
whether the process was Authenticode-signed, and its wall-clock hour is the
capture's, not yours. So the supervised model uses ONLY the features we share
with such a dataset (see FEATURE_NAMES). The engine builds the matching vector.

Honest limitation (see DESIGN.md 6.2): public IDS data is enterprise/lab
traffic, not your home network. Treat this model's scores with suspicion until
shadow mode has proven it out against *your* traffic; distribution mismatch is
real. This is the "known-bad patterns" complement to the anomaly model's
"unlike your own normal".

Usage:
    python scripts/train_supervised.py --data CICIDS2017.csv --out models/supervised.onnx
    python scripts/train_supervised.py --data path/to/dir/ --out models/supervised.onnx   # all *.csv

Requires: numpy, lightgbm, onnxmltools, onnx   (see scripts/requirements-ml.txt)
"""
import argparse
import csv
import glob
import json
import math
import os
import sys

# Shared feature order - the contract with the ngd-side supervised vector builder.
FEATURE_NAMES = [
    "log_duration",   # log1p(duration_ms)
    "log_bytes_in",   # log1p(bytes received)
    "log_bytes_out",  # log1p(bytes sent)
    "out_ratio",      # bytes_out / (bytes_in + bytes_out + 1)
    "is_https",       # dest port 443
    "is_http",        # dest port 80
]

# CIC-FlowMeter / CICIDS2017 column names (normalized: lowercased, spaces->_,
# stripped) mapped to what we need. The raw files have inconsistent leading
# spaces and casing, so we normalize before matching.
def norm(col):
    return col.strip().lower().replace(" ", "_")


def find_col(header_norm, *candidates):
    for c in candidates:
        if c in header_norm:
            return header_norm.index(c)
    return -1


def featurize(dur_ms, bytes_in, bytes_out, port):
    total = bytes_in + bytes_out
    return [
        math.log1p(max(dur_ms, 0.0)),
        math.log1p(max(bytes_in, 0.0)),
        math.log1p(max(bytes_out, 0.0)),
        bytes_out / (total + 1.0),
        1.0 if port == 443 else 0.0,
        1.0 if port == 80 else 0.0,
    ]


def load_dataset(paths):
    X, y = [], []
    for path in paths:
        with open(path, newline="", encoding="utf-8", errors="replace") as fh:
            reader = csv.reader(fh)
            header = norm_header = None
            iDur = iFwd = iBwd = iPort = iLabel = -1
            for row in reader:
                if header is None:
                    header = row
                    norm_header = [norm(c) for c in row]
                    # Flow Duration is in MICROSECONDS in CICIDS2017.
                    iDur = find_col(norm_header, "flow_duration")
                    # Fwd = source->dest = bytes we sent = bytes_out.
                    iFwd = find_col(norm_header, "total_length_of_fwd_packets",
                                    "totlen_fwd_pkts", "total_length_of_fwd_packet")
                    iBwd = find_col(norm_header, "total_length_of_bwd_packets",
                                    "totlen_bwd_pkts", "total_length_of_bwd_packet")
                    iPort = find_col(norm_header, "destination_port", "dst_port")
                    iLabel = find_col(norm_header, "label")
                    if min(iDur, iFwd, iBwd, iPort, iLabel) < 0:
                        sys.exit(f"{path}: missing expected columns (need Flow Duration, "
                                 f"Total Length of Fwd/Bwd Packets, Destination Port, Label). "
                                 f"Got: {header}")
                    continue
                try:
                    dur_ms = float(row[iDur]) / 1000.0        # us -> ms
                    bytes_out = float(row[iFwd])
                    bytes_in = float(row[iBwd])
                    port = int(float(row[iPort]))
                except (ValueError, IndexError):
                    continue
                label = 0 if row[iLabel].strip().upper() == "BENIGN" else 1
                X.append(featurize(dur_ms, bytes_in, bytes_out, port))
                y.append(label)
    return X, y


def main():
    ap = argparse.ArgumentParser(description="Train the NeuralGuard supervised scorer (LightGBM -> ONNX).")
    ap.add_argument("--data", required=True, help="CICIDS2017 CSV file, or a directory of *.csv")
    ap.add_argument("--out", default="models/supervised.onnx")
    ap.add_argument("--estimators", type=int, default=200)
    args = ap.parse_args()

    import numpy as np
    import lightgbm as lgb
    from onnxmltools.convert import convert_lightgbm
    from onnxmltools.convert.common.data_types import FloatTensorType

    paths = ([p for p in glob.glob(os.path.join(args.data, "*.csv"))]
             if os.path.isdir(args.data) else [args.data])
    if not paths:
        sys.exit(f"no CSVs found at {args.data}")

    X, y = load_dataset(paths)
    if not X:
        sys.exit("no usable rows parsed from the dataset")
    Xn = np.array(X, dtype=np.float32)
    yn = np.array(y, dtype=np.int32)
    n_bad = int(yn.sum())
    print(f"loaded {len(y)} flows from {len(paths)} file(s): {len(y)-n_bad} benign, {n_bad} malicious")
    if n_bad == 0 or n_bad == len(y):
        sys.exit("dataset has only one class - need both benign and malicious rows to train a classifier")

    clf = lgb.LGBMClassifier(n_estimators=args.estimators, is_unbalance=True, verbose=-1)
    clf.fit(Xn, yn)

    # LightGBM -> ONNX. onnxmltools' target_opset is a single int (the main
    # domain); it derives a compatible ai.onnx.ml version. zipmap=False keeps the
    # probability output a plain tensor (not a sequence-of-maps) so the C++ side
    # can read it directly.
    onx = convert_lightgbm(
        clf, initial_types=[("input", FloatTensorType([None, len(FEATURE_NAMES)]))],
        target_opset=15, zipmap=False)

    out = args.out
    os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
    with open(out, "wb") as f:
        f.write(onx.SerializeToString())
    spec = {
        "model": "LightGBMClassifier",
        "features": FEATURE_NAMES,
        "n_features": len(FEATURE_NAMES),
        "n_rows_trained": len(y),
        "n_malicious": n_bad,
        "output": "P(malicious) in [0,1]; higher = more likely bad",
        "note": "feature order is the contract with the ngd-side supervised vector builder",
    }
    with open(os.path.splitext(out)[0] + ".json", "w") as f:
        json.dump(spec, f, indent=2)
    print(f"trained on {len(y)} flows -> {out} ({os.path.getsize(out)} bytes)")


if __name__ == "__main__":
    main()
