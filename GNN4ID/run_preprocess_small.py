from Utility.Functions import NIDSDataset

root = r"D:\Adaima\GNN-IDS_data\IDS2017_small"
csv_path = r"D:\Adaima\GNN-IDS_data\IDS2017_small\raw\Thursday_gnn4id_ready_small_shuffled.csv"

ds = NIDSDataset(
    root=root,
    label_dict={},                 # single_file=True 用不到
    filename=[csv_path],           # 用绝对路径最稳
    single_file=True,
    include_packetflag=True,
    include_packetpayload=True,    # 太慢再改 False
    skip_processing=False,
    test=False,
    read_nrows=20000,               # ★先调试跑通
    read_engine="c"
)

print("Dataset size:", len(ds))
print(ds[0])
