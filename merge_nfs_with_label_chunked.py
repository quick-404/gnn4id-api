import os
import csv
import sys
import pandas as pd
import numpy as np

# 放开字段长度限制（payload 很长）
max_int = sys.maxsize
while True:
    try:
        csv.field_size_limit(max_int)
        break
    except OverflowError:
        max_int = int(max_int / 10)

# =======================
# 0) 路径：按你自己的改
# =======================
NFS_CSV = r"E:\wyc\GNN-IDS\dataWednesday-WorkingHours.csv"
LAB_MORNING = r"E:\wyc\GNN-IDS\data\Wednesday-workingHours.pcap_ISCX.csv"

OUT_LABEL_MAP = r"E:\wyc\GNN-IDS\data\Wednesday_id_LabelMap.csv"
OUT_FULL_WITH_LABEL = r"E:\wyc\GNN-IDS\data\Wednesday_NFS_with_Label.csv"

# =======================
# 参数
# =======================
TOLERANCE_MS = 300000  # 5 minutes，先跑通再收紧
CHUNK_SIZE = 100_000

TEST_MODE = False
MAX_TEST_ROWS = 300_000       # 先跑40万行验证

SHIFT_SAMPLE_ROWS = 80_000
SHIFT_SEARCH_HOURS = range(-12, 13)

BUILD_FULL_OUTPUT = False     # 不做全量合并回大CSV，先把 LabelMap 跑通


def normalize_proto(x):
    if pd.isna(x):
        return np.nan
    if isinstance(x, (int, np.integer, float, np.floating)):
        return int(x)
    s = str(x).strip().upper()
    if s == "TCP":
        return 6
    if s == "UDP":
        return 17
    try:
        return int(float(s))
    except:
        return np.nan


def canon_endpoints(df, ip1, port1, ip2, port2):
    # 规范化端点：避免 src/dst 方向不一致
    a = list(zip(df[ip1].astype(str), df[port1].fillna(-1).astype(int)))
    b = list(zip(df[ip2].astype(str), df[port2].fillna(-1).astype(int)))
    swap = np.array([ai > bi for ai, bi in zip(a, b)])

    df["ip_a"] = df[ip1].astype(str)
    df["port_a"] = df[port1].fillna(-1).astype(int)
    df["ip_b"] = df[ip2].astype(str)
    df["port_b"] = df[port2].fillna(-1).astype(int)

    df.loc[swap, ["ip_a", "port_a", "ip_b", "port_b"]] = df.loc[
        swap, ["ip_b", "port_b", "ip_a", "port_a"]
    ].values
    return df


def strip_ip_cols(df, cols):
    for c in cols:
        if c in df.columns:
            df[c] = df[c].astype(str).str.strip()
    return df


def read_label():
    if not os.path.exists(LAB_MORNING):
        raise FileNotFoundError(f"File not found: {LAB_MORNING}")

    lab = pd.read_csv(LAB_MORNING, encoding="latin1", low_memory=False)

    lab.columns = lab.columns.str.strip()

    need = ["Source IP", "Source Port", "Destination IP", "Destination Port", "Protocol", "Timestamp", "Label"]
    for c in need:
        if c not in lab.columns:
            raise ValueError(f"Label CSV missing column: {c}")

    lab = lab[need].copy()
    lab.rename(columns={
        "Source IP": "src_ip",
        "Source Port": "src_port",
        "Destination IP": "dst_ip",
        "Destination Port": "dst_port",
        "Protocol": "protocol",
        "Timestamp": "timestamp_str",
        "Label": "Label_str"
    }, inplace=True)


    lab = strip_ip_cols(lab, ["src_ip", "dst_ip"])

    lab["src_port"] = pd.to_numeric(lab["src_port"], errors="coerce").fillna(-1).astype("int64")
    lab["dst_port"] = pd.to_numeric(lab["dst_port"], errors="coerce").fillna(-1).astype("int64")
    lab["protocol_norm"] = pd.to_numeric(lab["protocol"].apply(normalize_proto), errors="coerce").fillna(-1).astype("int64")

    lab_dt = pd.to_datetime(lab["timestamp_str"], errors="coerce", dayfirst=True)

    # ★ 删除 NaT 行
    mask = lab_dt.notna()
    lab = lab.loc[mask].copy()
    lab_dt = lab_dt.loc[mask]

    print("[Label] NaT rate after drop:", f"{lab_dt.isna().mean():.2%}")
    print("[Label] time span:", lab_dt.min(), "->", lab_dt.max())

    bad_ts = lab_dt.isna().mean()
    print(f"[Label] timestamp parse NaT rate: {bad_ts:.2%}")
    print("[Label] time span:", lab_dt.min(), "->", lab_dt.max())

    lab["t_ms"] = (lab_dt.astype("int64") // 10**6)

    lab = canon_endpoints(lab, "src_ip", "src_port", "dst_ip", "dst_port")
    lab_sorted = lab[["t_ms","ip_a","port_a","ip_b","port_b","protocol_norm","Label_str"]].sort_values("t_ms")

    print("Label rows:", len(lab_sorted))
    print("[Label] proto_norm unique:", sorted(lab_sorted["protocol_norm"].unique())[:20])
    return lab_sorted


def read_nfs_sample(nrows):
    print(f"Reading {nrows} rows from NFS data")

    sample = pd.read_csv(
        NFS_CSV,
        usecols=["id","src_ip","src_port","dst_ip","dst_port","protocol","bidirectional_first_seen_ms"],
        nrows=300000,
        engine="c",
        low_memory=False
    )
    sample = strip_ip_cols(sample, ["src_ip","dst_ip"])
    sample["src_port"] = pd.to_numeric(sample["src_port"], errors="coerce").fillna(-1).astype("int64")
    sample["dst_port"] = pd.to_numeric(sample["dst_port"], errors="coerce").fillna(-1).astype("int64")
    sample["protocol_norm"] = pd.to_numeric(sample["protocol"].apply(normalize_proto), errors="coerce").fillna(-1).astype("int64")
    sample = canon_endpoints(sample, "src_ip","src_port","dst_ip","dst_port")
    print("[NFS sample] proto_norm unique:", sorted(sample["protocol_norm"].unique())[:20])
    return sample


def sanity_check_key_overlap(lab_sorted, nfs_sample):
    # IP 交集
    lab_ips = set(lab_sorted["ip_a"]).union(set(lab_sorted["ip_b"]))
    nfs_ips = set(nfs_sample["ip_a"]).union(set(nfs_sample["ip_b"]))
    ip_inter = lab_ips.intersection(nfs_ips)
    print(f"[Sanity] IP overlap: {len(ip_inter)}  (lab_ips={len(lab_ips)}, nfs_ips={len(nfs_ips)})")

    # 五元组键交集（忽略时间）
    lab_keys = set(zip(lab_sorted["ip_a"], lab_sorted["port_a"], lab_sorted["ip_b"], lab_sorted["port_b"], lab_sorted["protocol_norm"]))
    nfs_keys = set(zip(nfs_sample["ip_a"], nfs_sample["port_a"], nfs_sample["ip_b"], nfs_sample["port_b"], nfs_sample["protocol_norm"]))
    inter = lab_keys.intersection(nfs_keys)
    print(f"[Sanity] 5-tuple key overlap: {len(inter)}  (lab_keys={len(lab_keys)}, nfs_keys={len(nfs_keys)})")

    if len(inter) == 0:
        print("\n>>> 五元组没交集")
        print(nfs_sample[["src_ip","src_port","dst_ip","dst_port","protocol","protocol_norm"]].head(5).to_string(index=False))
        return False
    return True


def find_best_shift_ms(lab_sorted, keys, nfs_sample):
    best_shift = 0
    best_rate = -1.0

    print("\n[Shift Search] coarse scan by hour...")
    for h in SHIFT_SEARCH_HOURS:
        shift_ms = h * 3600 * 1000
        tmp = nfs_sample.copy()
        tmp["t_ms"] = tmp["bidirectional_first_seen_ms"].astype("int64") - shift_ms
        tmp = tmp.sort_values("t_ms")

        m = pd.merge_asof(
            tmp,
            lab_sorted,
            on="t_ms",
            by=keys,
            direction="nearest",
            tolerance=TOLERANCE_MS
        )
        rate = m["Label_str"].notna().mean()
        print(f"  shift {h:+}h  match_rate={rate:.2%}")

        if rate > best_rate:
            best_rate = rate
            best_shift = shift_ms

    print(f"[Shift Search] BEST shift_ms={best_shift}  (≈ {best_shift/3600000:.3f}h), best_rate={best_rate:.2%}\n")
    return best_shift, best_rate


def build_label_map(lab_sorted, keys, shift_ms):
    if os.path.exists(OUT_LABEL_MAP):
        os.remove(OUT_LABEL_MAP)

    #
    usecols_nfs = ["id","src_ip","src_port","dst_ip","dst_port","protocol","bidirectional_first_seen_ms"]

    first_write = True
    total = 0
    matched = 0
    rows_done = 0

    for i, chunk in enumerate(pd.read_csv(NFS_CSV, usecols=usecols_nfs, chunksize=CHUNK_SIZE, engine="c", low_memory=False)):
        rows_done += len(chunk)

        chunk = strip_ip_cols(chunk, ["src_ip","dst_ip"])
        chunk["src_port"] = pd.to_numeric(chunk["src_port"], errors="coerce").fillna(-1).astype("int64")
        chunk["dst_port"] = pd.to_numeric(chunk["dst_port"], errors="coerce").fillna(-1).astype("int64")
        chunk["protocol_norm"] = pd.to_numeric(chunk["protocol"].apply(normalize_proto), errors="coerce").fillna(-1).astype("int64")

        chunk = canon_endpoints(chunk, "src_ip","src_port","dst_ip","dst_port")
        chunk["t_ms"] = chunk["bidirectional_first_seen_ms"].astype("int64") - int(shift_ms)
        chunk_sorted = chunk.sort_values("t_ms")

        merged = pd.merge_asof(
            chunk_sorted,
            lab_sorted,
            on="t_ms",
            by=keys,
            direction="nearest",
            tolerance=TOLERANCE_MS
        )

        total += len(merged)
        matched += merged["Label_str"].notna().sum()

        unk_rate = merged["Label_str"].isna().mean()
        print(f"[Stage1] chunk {i}: unknown_rate={unk_rate:.2%}")

        out_small = merged[["id","Label_str"]].copy()
        out_small["Label_str"] = out_small["Label_str"].fillna("Unknown")
        out_small["Label"] = (out_small["Label_str"].str.upper() != "BENIGN").astype(int)

        out_small.to_csv(OUT_LABEL_MAP, index=False, mode="w" if first_write else "a", header=first_write)
        first_write = False

        print(f"[Stage1] chunk {i}: rows={len(merged)}  cumulative_match_rate={matched/total:.2%}")

        if TEST_MODE and rows_done >= MAX_TEST_ROWS:
            print("[Stage1] TEST_MODE stop at rows:", rows_done)
            break

    print("[Stage1] DONE. Saved:", OUT_LABEL_MAP)
    print("[Stage1] Final match rate:", f"{matched/total:.2%}\n")


def build_full_with_label():
    label_map = pd.read_csv(OUT_LABEL_MAP, engine="c", low_memory=False)
    label_map = label_map.drop_duplicates(subset=["id"]).set_index("id")

    if os.path.exists(OUT_FULL_WITH_LABEL):
        os.remove(OUT_FULL_WITH_LABEL)

    first_write = True
    rows_done = 0

    for i, chunk in enumerate(pd.read_csv(
        NFS_CSV,
        chunksize=CHUNK_SIZE,
        engine="python",
        on_bad_lines="skip"
    )):
        rows_done += len(chunk)

        chunk2 = chunk.set_index("id").join(label_map, how="left").reset_index()
        chunk2["Label_str"] = chunk2["Label_str"].fillna("Unknown")
        chunk2["Label"] = chunk2["Label"].fillna(0).astype(int)

        chunk2.to_csv(OUT_FULL_WITH_LABEL, index=False, mode="w" if first_write else "a", header=first_write)
        first_write = False

        if (i + 1) % 5 == 0:
            print(f"[Stage2] wrote {i+1} chunks...")

        if TEST_MODE and rows_done >= MAX_TEST_ROWS:  # ★ 新增
            print("[Stage2] TEST_MODE stop at rows:", rows_done)
            break


if __name__ == "__main__":
    keys = ["ip_a","port_a","ip_b","port_b","protocol_norm"]

    lab_sorted = read_label()

    nfs_sample = read_nfs_sample(SHIFT_SAMPLE_ROWS)

    ok = sanity_check_key_overlap(lab_sorted, nfs_sample)
    if not ok:

        sys.exit(0)

    shift_ms, best_rate = find_best_shift_ms(lab_sorted, keys, nfs_sample)

    # 调试信息
    print(f"[Main] Using shift_ms={shift_ms}  (≈ {shift_ms / 3600000:.3f}h), coarse_best_rate={best_rate:.2%}")
    print(f"[Main] TOLERANCE_MS={TOLERANCE_MS}, CHUNK_SIZE={CHUNK_SIZE}, TEST_MODE={TEST_MODE}")

    #生成 id->Label 映射
    build_label_map(lab_sorted, keys, shift_ms)

    if BUILD_FULL_OUTPUT:
        build_full_with_label()

    print("All done.")
