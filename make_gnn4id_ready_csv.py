import os, sys, csv
import pandas as pd

# 放开字段长度限制
max_int = sys.maxsize
while True:
    try:
        csv.field_size_limit(max_int)
        break
    except OverflowError:
        max_int = int(max_int / 10)

NFS_CSV = r"E:\wyc\GNN-IDS\dataWednesday-WorkingHours.csv"
LABEL_MAP = r"E:\wyc\GNN-IDS\data\Wednesday_id_LabelMap.csv"
OUT_CSV = r"E:\wyc\GNN-IDS\data\raw\Wednesday_gnn4id_ready_small1.csv"

CHUNK_SIZE = 50_000

# 先用小规模跑链路
TARGET_BENIGN = 10000
TARGET_ATTACK = 10000

# 只要TCP/UDP减少Unknown噪声
KEEP_PROTOCOL = {6, 17}

def to_int(s, default=None):
    try:
        return int(float(s))
    except:
        return default

# 读 id->Label（这个文件不大）
lm = pd.read_csv(LABEL_MAP, engine="c")
# 只保留已匹配的 label（Unknown 全扔掉）
lm = lm[lm["Label_str"].notna()].copy()
lm["Label_str"] = lm["Label_str"].astype(str)
lm["id"] = pd.to_numeric(lm["id"], errors="coerce").astype("Int64")
lm = lm.dropna(subset=["id"])
lm["id"] = lm["id"].astype("int64")
lm = lm.drop_duplicates(subset=["id"]).set_index("id")[["Label_str", "Label"]]

if os.path.exists(OUT_CSV):
    os.remove(OUT_CSV)

benign_cnt = 0
attack_cnt = 0
first_write = True

# 用 python 引擎流式读（能处理超长字段）
for chunk in pd.read_csv(
    NFS_CSV,
    chunksize=CHUNK_SIZE,
    engine="python",
    on_bad_lines="skip"
):
    if "id" not in chunk.columns:
        raise ValueError("NFS CSV missing column 'id'")

    # id 对齐
    chunk["id"] = pd.to_numeric(chunk["id"], errors="coerce")
    chunk = chunk.dropna(subset=["id"])
    chunk["id"] = chunk["id"].astype("int64")

    # 加入 Label
    chunk = chunk.set_index("id").join(lm, how="inner").reset_index()
    # inner：直接丢掉 Unknown/没匹配上的

    # 协议过滤（可选但很推荐）
    if "protocol" in chunk.columns:
        chunk["protocol_int"] = chunk["protocol"].apply(lambda x: to_int(x, default=-1))
        chunk = chunk[chunk["protocol_int"].isin(KEEP_PROTOCOL)].copy()
        chunk.drop(columns=["protocol_int"], inplace=True)

    if chunk.empty:
        continue

    # 分开抽样
    benign = chunk[chunk["Label"] == 0]
    attack = chunk[chunk["Label"] == 1]

    need_b = max(0, TARGET_BENIGN - benign_cnt)
    need_a = max(0, TARGET_ATTACK - attack_cnt)

    out_parts = []
    if need_b > 0 and len(benign) > 0:
        out_parts.append(benign.head(need_b))
        benign_cnt += min(need_b, len(benign))
    if need_a > 0 and len(attack) > 0:
        out_parts.append(attack.head(need_a))
        attack_cnt += min(need_a, len(attack))

    if out_parts:
        out = pd.concat(out_parts, ignore_index=True)
        out.to_csv(OUT_CSV, index=False, mode="w" if first_write else "a", header=first_write)
        first_write = False

    print(f"written benign={benign_cnt}/{TARGET_BENIGN}, attack={attack_cnt}/{TARGET_ATTACK}")

    if benign_cnt >= TARGET_BENIGN and attack_cnt >= TARGET_ATTACK:
        break

print("DONE:", OUT_CSV)
