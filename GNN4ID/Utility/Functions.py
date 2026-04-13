import os
import re
import glob
import sys
import csv
import random
import pandas as pd
import numpy as np
import torch
from tqdm import tqdm

from torch_geometric.data import HeteroData
from torch_geometric.data import Dataset, Data
import torch_geometric.transforms as T


# -------------------------------------------------------------------
# 重要：如果你用 pandas engine="python" 读取超长 payload 字段，需要放开单字段长度限制
# （engine="c" 不走 python 的 csv.field_size_limit，但 engine="python" 会走）
# -------------------------------------------------------------------
_max_int = sys.maxsize
while True:
    try:
        csv.field_size_limit(_max_int)
        break
    except OverflowError:
        _max_int = int(_max_int / 10)


class NIDSDataset(Dataset):
    """
    A dataset class generates heterogeneous graph data objects from a CSV file/files.
    """

    def __init__(
        self,
        root,
        label_dict,
        filename,
        index_num=0,
        skip_processing=False,
        include_packetflag=False,
        include_packetpayload=True,
        test=False,
        single_file=False,
        transform=None,
        pre_transform=None,
        read_nrows=None,     # 调试用：只读前 N 行；全量训练设为 None
        read_engine="c"      # "c" 更快；若报 field limit / bad lines 可切 "python"
    ):
        self.test = test
        self.filename = filename
        self.include_packetflag = include_packetflag
        self.include_packetpayload = include_packetpayload
        self.index = index_num
        self.label_dict = label_dict
        self.skip_processing = skip_processing
        self.length = 0
        self.single_file = single_file

        self.read_nrows = read_nrows
        self.read_engine = read_engine

        super(NIDSDataset, self).__init__(root, transform, pre_transform)

    @property
    def raw_file_names(self):
        return self.filename

    @property
    def processed_file_names(self):
        if self.skip_processing:
            if self.test:
                files = glob.glob(os.path.join(self.root, "processed/data_test_*.pt"))
            else:
                files = glob.glob(os.path.join(self.root, "processed/data_*.pt"))
            self.length = len(files)
            return [os.path.basename(f) for f in files]
        return []

    def download(self):
        pass

    # -----------------------------
    # Robust list parsers
    # -----------------------------
    @staticmethod
    def _parse_list_str(x):
        """
        Parse a string like "['1','2']" or "[1, 2]" or "[]" into a python list of strings.
        """
        if x is None or (isinstance(x, float) and np.isnan(x)):
            return []
        s = str(x).strip()
        if s == "" or s.lower() in ("nan", "none"):
            return []
        if s == "[]":
            return []
        # remove outer brackets if present
        if len(s) >= 2 and s[0] == "[" and s[-1] == "]":
            s = s[1:-1].strip()
        if s == "":
            return []
        parts = [p.strip().strip("'").strip('"') for p in s.split(",")]
        parts = [p for p in parts if p != ""]
        return parts

    @classmethod
    def _parse_int_list(cls, x, default=0):
        parts = cls._parse_list_str(x)
        out = []
        for p in parts:
            try:
                # 可能是 "1.0"
                out.append(int(float(p)))
            except Exception:
                out.append(default)
        return out

    @classmethod
    def _parse_float_list(cls, x, default=0.0):
        parts = cls._parse_list_str(x)
        out = []
        for p in parts:
            try:
                out.append(float(p))
            except Exception:
                out.append(default)
        return out

    @classmethod
    def _parse_payload_list(cls, x):
        """
        Payload list: list of hex strings. Return [] if empty.
        """
        parts = cls._parse_list_str(x)
        # 清理空项、空白、0x 前缀
        out = []
        for p in parts:
            p2 = p.strip().replace(" ", "")
            if p2.lower().startswith("0x"):
                p2 = p2[2:]
            if p2 == "":
                continue
            out.append(p2)
        return out

    # -----------------------------
    # Main processing
    # -----------------------------
    def process(self):
        for files in self.raw_paths:
            print("Reading File ---> " + os.path.basename(files), file=sys.stderr)

            read_kwargs = dict(low_memory=False)
            if self.read_nrows is not None:
                read_kwargs["nrows"] = int(self.read_nrows)

            if self.read_engine == "python":
                read_kwargs["engine"] = "python"
                # 有些版本 pandas 支持 on_bad_lines
                read_kwargs["on_bad_lines"] = "skip"
            else:
                read_kwargs["engine"] = "c"

            self.data = pd.read_csv(files, **read_kwargs)

            # =========================
            # A) Drop identifiers / string columns that should NOT be flow node numeric features
            # （端口你可以保留：是数值，对检测有用。这里不删 src_port/dst_port）
            # =========================
            drop_cols = [
                "src_ip", "dst_ip", "ip_version",
                "id", "src_mac", "src_oui", "dst_mac", "dst_oui", "vlan_id", "tunnel_id",
                "Label_str"  # 你的合并文件会有，必须删掉，否则 flow 特征会变 object
            ]
            self.data.drop(drop_cols, axis=1, inplace=True, errors="ignore")

            # =========================
            # B) One-hot: expiration_id & protocol （不管 single_file / multi-file 都做）
            # =========================
            dummy_cols = []
            prefixes = []

            if "expiration_id" in self.data.columns:
                exp = pd.to_numeric(self.data["expiration_id"], errors="coerce").fillna(-1).astype(int)
                self.data["expiration_id"] = pd.Categorical(exp, categories=sorted(exp.unique()))
                dummy_cols.append("expiration_id")
                prefixes.append("Exp")

            if "protocol" in self.data.columns:
                proto = pd.to_numeric(self.data["protocol"], errors="coerce").fillna(-1).astype(int)
                cats = sorted(set(proto.unique()).union({1, 2, 6, 17, 58, -1}))
                self.data["protocol"] = pd.Categorical(proto, categories=cats)
                dummy_cols.append("protocol")
                prefixes.append("proto")

            if dummy_cols:
                self.data = pd.get_dummies(self.data, prefix=prefixes, columns=dummy_cols, dtype=int)

            # =========================
            # C) Label for multi-file only
            # =========================
            label = None
            if not self.single_file:
                label = self._get_labels(files)

            # =========================
            # D) udps.* 列：先 fillna，再 parse 成 python list
            # =========================
            # 这些列如果缺失就跳过；但一般 NFStreamer 都会有
            if "udps.payload_data" in self.data.columns:
                self.data["udps.payload_data"] = self.data["udps.payload_data"].fillna("[]")
                self.data["udps.payload_data"] = self.data["udps.payload_data"].apply(self._parse_payload_list)

            for c in ["udps.packet_direction", "udps.ip_size", "udps.transport_size", "udps.payload_size"]:
                if c in self.data.columns:
                    self.data[c] = self.data[c].fillna("[]").apply(self._parse_int_list)

            if "udps.delta_time" in self.data.columns:
                self.data["udps.delta_time"] = self.data["udps.delta_time"].fillna("[]").apply(self._parse_float_list)

            if self.include_packetflag:
                for c in ["udps.syn", "udps.cwr", "udps.ece", "udps.urg", "udps.ack", "udps.psh", "udps.rst", "udps.fin"]:
                    if c in self.data.columns:
                        self.data[c] = self.data[c].fillna("[]").apply(self._parse_int_list)

            # =========================
            # E) Build per-flow heterogeneous graphs
            # =========================
            for _, flow in tqdm(self.data.iterrows(), total=self.data.shape[0]):
                # label
                if self.single_file:
                    # 这里必须保证 Label 是 0/1 或 多类 int
                    try:
                        y = int(flow["Label"])
                    except Exception:
                        y = 0
                    label = torch.tensor([y], dtype=torch.int64)

                # packet count
                payload_list = flow.get("udps.payload_data", [])
                if payload_list is None:
                    payload_list = []
                n_pkts = len(payload_list)

                flow_node_feats = self._get_flow_node_features(flow)
                packet_node_feats = self._get_packet_node_features(flow, n_pkts)

                contain_edge_index = self._get_contain_edge_index(n_pkts)
                link_edge_index = self._get_link_edge_index(n_pkts)

                contain_edge_feats = self._get_contain_edge_features(flow, n_pkts)
                link_edge_feats = self._get_link_edge_features(flow, n_pkts)

                data = HeteroData()
                data["flow"].x = flow_node_feats
                data["packet"].x = packet_node_feats
                data["flow", "contain", "packet"].edge_index = contain_edge_index
                data["packet", "link", "packet"].edge_index = link_edge_index
                data["flow", "contain", "packet"].edge_attr = contain_edge_feats
                data["packet", "link", "packet"].edge_attr = link_edge_feats
                data.y = label

                data = T.ToUndirected()(data)

                if self.test:
                    torch.save(data, os.path.join(self.processed_dir, f"data_test_{self.index}.pt"))
                else:
                    torch.save(data, os.path.join(self.processed_dir, f"data_{self.index}.pt"))
                self.index += 1

            if not self.skip_processing:
                if self.test:
                    list_process = glob.glob(os.path.join(self.root, "processed/data_test*"))
                    self.length = len(list_process)
                else:
                    list_process = glob.glob(os.path.join(self.root, "processed/data*"))
                    self.length = len(list_process) - len(glob.glob(os.path.join(self.root, "processed/data_test*")))

    # -----------------------------
    # Feature builders
    # -----------------------------
    def _get_flow_node_features(self, flow):
        """
        Return flow node feature tensor with shape [1, F].
        Ensures numeric float features (no object columns).
        """
        drop = [
            "Label", "Label_str",
            "udps.payload_data", "udps.delta_time", "udps.packet_direction", "udps.ip_size",
            "udps.transport_size", "udps.payload_size",
            "udps.syn", "udps.cwr", "udps.ece", "udps.urg", "udps.ack", "udps.psh", "udps.rst", "udps.fin"
        ]
        flow_data = flow.drop(drop, errors="ignore")

        # 强制转数值
        flow_data = pd.to_numeric(flow_data, errors="coerce").fillna(0.0)
        x = torch.tensor(flow_data.to_numpy(dtype=np.float32), dtype=torch.float32).view(1, -1)
        return x

    def _get_packet_node_features(self, flow, n_pkts):
        """
        packet node features:
        [flags...(optional) + payload bytes padded/truncated to dims]
        Shape: [n_pkts, D]
        """
        dims = 1500
        feats = []

        payloads = flow.get("udps.payload_data", [])
        if payloads is None:
            payloads = []

        # flags lists
        def safe_list(name):
            v = flow.get(name, [])
            return v if isinstance(v, list) else []

        syn = safe_list("udps.syn")
        cwr = safe_list("udps.cwr")
        ece = safe_list("udps.ece")
        urg = safe_list("udps.urg")
        ack = safe_list("udps.ack")
        psh = safe_list("udps.psh")
        rst = safe_list("udps.rst")
        fin = safe_list("udps.fin")

        for i in range(n_pkts):
            row = []

            if self.include_packetflag:
                row.extend([
                    syn[i] if i < len(syn) else 0,
                    cwr[i] if i < len(cwr) else 0,
                    ece[i] if i < len(ece) else 0,
                    urg[i] if i < len(urg) else 0,
                    ack[i] if i < len(ack) else 0,
                    psh[i] if i < len(psh) else 0,
                    rst[i] if i < len(rst) else 0,
                    fin[i] if i < len(fin) else 0,
                ])

            if self.include_packetpayload:
                hexs = payloads[i] if i < len(payloads) else ""
                # fromhex 要求合法偶数长度
                try:
                    if hexs is None:
                        hexs = ""
                    hexs = str(hexs).strip().replace(" ", "")
                    if len(hexs) % 2 == 1:
                        hexs = "0" + hexs
                    byte_array = bytes.fromhex(hexs) if hexs != "" else b""
                    byte_lst = list(byte_array)
                except Exception:
                    byte_lst = []

                if len(byte_lst) < dims:
                    packet_feat = np.pad(byte_lst, (0, dims - len(byte_lst)), "constant")
                else:
                    packet_feat = np.array(byte_lst[:dims], copy=True)

                packet_feat = np.abs(np.uint8(packet_feat))
                row.extend(packet_feat.tolist())

            feats.append(row)

        if n_pkts == 0:
            # 0 包：返回 [0, D] 的空张量（不要伪造 1 个包）
            d = (8 if self.include_packetflag else 0) + (dims if self.include_packetpayload else 0)
            return torch.zeros((0, d), dtype=torch.float32)

        feats = np.asarray(feats, dtype=np.float32)
        return torch.tensor(feats, dtype=torch.float32)

    def _get_contain_edge_features(self, flow, n_pkts):
        """
        contain edge features: [packet_direction, ip_size, transport_size, payload_size]
        Shape: [n_pkts, 4]
        """
        pdire = flow.get("udps.packet_direction", [])
        ipsz = flow.get("udps.ip_size", [])
        tsz = flow.get("udps.transport_size", [])
        psz = flow.get("udps.payload_size", [])

        def gi(lst, i, default=0):
            try:
                return int(lst[i])
            except Exception:
                return default

        feats = []
        for i in range(n_pkts):
            feats.append([
                gi(pdire, i, 0),
                gi(ipsz, i, 0),
                gi(tsz, i, 0),
                gi(psz, i, 0),
            ])

        if n_pkts == 0:
            return torch.zeros((0, 4), dtype=torch.float32)

        return torch.tensor(np.asarray(feats, dtype=np.float32), dtype=torch.float32)

    def _get_link_edge_features(self, flow, n_pkts):
        """
        link edge features: delta_time between consecutive packets.
        Shape: [n_pkts-1, 1]
        """
        dt = flow.get("udps.delta_time", [])
        if not isinstance(dt, list):
            dt = []

        m = max(n_pkts - 1, 0)
        vals = []
        for i in range(1, n_pkts):
            try:
                vals.append(float(dt[i]) if i < len(dt) else 0.0)
            except Exception:
                vals.append(0.0)

        if m == 0:
            return torch.zeros((0, 1), dtype=torch.float32)

        arr = np.asarray(vals, dtype=np.float32).reshape(-1, 1)
        return torch.tensor(arr, dtype=torch.float32)

    def _get_contain_edge_index(self, length):
        Flow = np.zeros(length, dtype=int)
        Packet = np.arange(0, length, dtype=int)
        contain_edge = np.vstack((Flow, Packet))
        return torch.tensor(contain_edge, dtype=torch.int64)

    def _get_link_edge_index(self, length):
        if length <= 1:
            return torch.tensor(np.zeros((2, 0), dtype=int), dtype=torch.int64)
        packet_ini = np.arange(0, length - 1, dtype=int)
        packet_next = np.arange(1, length, dtype=int)
        link_edge = np.vstack((packet_ini, packet_next))
        return torch.tensor(link_edge, dtype=torch.int64)

    def _get_labels(self, file_name):
        name = os.path.basename(file_name)
        label = self.label_dict[name.split("-")[0]]
        return torch.tensor(np.asarray([label]), dtype=torch.int64)

    def len(self):
        return self.length

    def get(self, idx):
        if self.test:
            return torch.load(os.path.join(self.processed_dir, f"data_test_{idx}.pt"))
        return torch.load(os.path.join(self.processed_dir, f"data_{idx}.pt"))


# -------------------------------------------------------------------
# 以下工具函数：保持原项目一致（我只做了必要的健壮性修正，不影响你原流程）
# -------------------------------------------------------------------
def rename_files(directory, name_mapping):
    if not os.path.exists(directory):
        print(f"The directory '{directory}' does not exist.")
        return

    directory_glob = directory + r"\**\*pcap"
    files = glob.glob(directory_glob, recursive=True)

    for filename in files:
        if not os.path.isfile(filename):
            continue

        old_name_search = filename.split("\\")[-1]
        old_name_search = old_name_search.split(".")[-2]
        old_name_search = re.sub(r"\d+", "", old_name_search)
        old_name_search = old_name_search[:-1] if old_name_search.endswith("_") else old_name_search

        new_base = name_mapping.get(old_name_search, old_name_search)
        new_name = os.path.join(os.path.dirname(filename), new_base)

        try:
            number = extract_number(os.path.basename(filename))
            new_name = new_name + "_" + number + ".pcap"
        except Exception:
            new_name = new_name + "_0.pcap"

        os.rename(filename, new_name)
        print(f"Renamed: {os.path.basename(filename)} -> {os.path.basename(new_name)}")


def extract_number(file_name: str) -> str:
    return re.search(r"\d+", file_name).group(0)


def duplicate_rows(df, target_rows):
    original_df = df.copy()
    itr = int(target_rows / df.shape[0]) - 1
    for _ in range(max(itr, 0)):
        df = pd.concat([df, original_df], ignore_index=True)
    target_over = target_rows - df.shape[0]
    df = random_pick_rows(df, original_df, target_over)
    return df


def random_pick_rows(df, original, over):
    for _ in range(max(over, 0)):
        row_to_duplicate = random.randint(0, original.shape[0] - 1)
        df = pd.concat([df, original.iloc[row_to_duplicate:row_to_duplicate + 1]], ignore_index=True)
    return df


def Combining_classes(
    directory,
    classes_list,
    Number_in_individaul_class=20000,
    Number_of_test_samples=4000,
    label_dict={"Benign": 0, "WebBased": 1, "Spoofing": 2, "Recon": 3, "Mirai": 4, "Dos": 5, "DDos": 6, "BruteForce": 7},
):
    for each_class in tqdm(classes_list):
        df_list = []
        List_of_CSV_File = glob.glob(directory + each_class + "*")
        for file in List_of_CSV_File:
            df = pd.read_csv(file)
            name_file = file.split("\\")[-1]
            name_file = name_file.split(".")[-2]
            name_file = name_file.split("-")[0]
            df_list.append(df)

        final_df = pd.concat(df_list, ignore_index=True)

        if final_df.shape[0] <= Number_in_individaul_class:
            final_df = duplicate_rows(final_df, Number_in_individaul_class)
        else:
            fraction = Number_in_individaul_class / final_df.shape[0]
            final_df = final_df.sample(frac=fraction)

        final_df["Label"] = label_dict[name_file]
        train_file_path = os.path.dirname(file) + "\\train\\" + name_file + "_train.csv"
        if not os.path.exists(os.path.dirname(train_file_path)):
            os.makedirs(os.path.dirname(train_file_path))

        final_df.to_csv(train_file_path, index=False)

        # For Test Data
        List_of_CSV_File = glob.glob(directory + "test\\" + each_class + "*")
        df_list = []
        for file in List_of_CSV_File:
            df = pd.read_csv(file)
            name_file = file.split("\\")[-1]
            name_file = name_file.split(".")[-2]
            name_file = name_file.split("-")[0]
            df_list.append(df)
            os.remove(file)

        final_df = pd.concat(df_list, ignore_index=True)
        final_df["Label"] = label_dict[name_file]
        if final_df.shape[0] > Number_of_test_samples:
            final_df = final_df.sample(n=Number_of_test_samples, random_state=42)
        test_file_path = os.path.dirname(file) + "\\" + name_file + "_test.csv"
        final_df.to_csv(test_file_path, index=False)


def split_csv(file_path, test_sample=4000, Number_in_individaul_class=20000):
    df = pd.read_csv(file_path)
    name_file = file_path.split("\\")[-1]
    name_file = name_file.split(".")[-2]
    name_check = name_file.split("-")[0]

    if name_check == "Benign":
        df = df[
            (df["src_mac"] != "dc:a6:32:dc:27:d5")
            & (df["src_mac"] != "e4:5f:01:55:90:c4")
            & (df["src_mac"] != "dc:a6:32:c9:e4:ab")
            & (df["src_mac"] != "ac:17:02:05:34:27")
            & (df["src_mac"] != "dc:a6:32:c9:e5:a4")
            & (df["src_mac"] != "dc:a6:32:c9:e4:d5")
            & (df["src_mac"] != "dc:a6:32:c9:e5:ef")
            & (df["src_mac"] != "dc:a6:32:c9:e4:90")
            & (df["src_mac"] != "b0:09:da:3e:82:6c")
            & (df["dst_mac"] != "dc:a6:32:dc:27:d5")
            & (df["dst_mac"] != "e4:5f:01:55:90:c4")
            & (df["dst_mac"] != "dc:a6:32:c9:e4:ab")
            & (df["dst_mac"] != "ac:17:02:05:34:27")
            & (df["dst_mac"] != "dc:a6:32:c9:e5:a4")
            & (df["dst_mac"] != "dc:a6:32:c9:e4:d5")
            & (df["dst_mac"] != "dc:a6:32:c9:e5:ef")
            & (df["dst_mac"] != "dc:a6:32:c9:e4:90")
            & (df["dst_mac"] != "b0:09:da:3e:82:6c")
        ]
    else:
        df = df[
            (df["src_mac"].isin(["dc:a6:32:dc:27:d5", "e4:5f:01:55:90:c4", "dc:a6:32:c9:e4:ab", "ac:17:02:05:34:27",
                                 "dc:a6:32:c9:e5:a4", "dc:a6:32:c9:e4:d5", "dc:a6:32:c9:e5:ef", "dc:a6:32:c9:e4:90", "b0:09:da:3e:82:6c"]))
            | (df["dst_mac"].isin(["dc:a6:32:dc:27:d5", "e4:5f:01:55:90:c4", "dc:a6:32:c9:e4:ab", "ac:17:02:05:34:27",
                                   "dc:a6:32:c9:e5:a4", "dc:a6:32:c9:e4:d5", "dc:a6:32:c9:e5:ef", "dc:a6:32:c9:e4:90", "b0:09:da:3e:82:6c"]))
        ]

    if df.shape[0] > 35000:
        df_test = df.sample(n=test_sample, random_state=42)
        df = df.drop(df_test.index)
        df = df.sample(n=Number_in_individaul_class, random_state=42)
    else:
        df_test = df.sample(frac=0.2, random_state=42)
        df = df.drop(df_test.index)

    test_file_path = os.path.dirname(file_path) + "\\test\\" + name_file + "_test.csv"
    if not os.path.exists(os.path.dirname(test_file_path)):
        os.makedirs(os.path.dirname(test_file_path))

    df_test.to_csv(test_file_path, index=False)
    df.to_csv(file_path, index=False)
