import torch
from torch_geometric.loader import DataLoader
from torch.utils.data import random_split

from Utility.Functions import NIDSDataset
from Utility.Model import HeteroGNN  # 你也可以换 HeteroGNN_Edge

root = r"E:\wyc\GNN-IDS\data"

# 只加载 processed 里的 pt
ds = NIDSDataset(
    root=root,
    label_dict={},
    filename=["Wednesday_gnn4id_ready_small1.csv"],
    single_file=True,
    include_packetflag=True,
    include_packetpayload=True,
    skip_processing=True,   # ✅关键：不再 preprocess
    test=False
)

print("Dataset size:", len(ds))
hetero_graph = ds[0]  # 用第一个图拿 metadata

args = {"hidden_size": 64, "eps": 1e-5}
model = HeteroGNN(hetero_graph, args).to("cuda" if torch.cuda.is_available() else "cpu")
device = next(model.parameters()).device

# 8/1/1 切分
n = len(ds)
n_train = int(0.8 * n)
n_val = int(0.1 * n)
n_test = n - n_train - n_val
train_ds, val_ds, test_ds = random_split(ds, [n_train, n_val, n_test], generator=torch.Generator().manual_seed(42))

train_loader = DataLoader(train_ds, batch_size=32, shuffle=True)
val_loader = DataLoader(val_ds, batch_size=64, shuffle=False)
test_loader = DataLoader(test_ds, batch_size=64, shuffle=False)

opt = torch.optim.Adam(model.parameters(), lr=1e-3)

def eval_acc(loader):
    model.eval()
    correct = total = 0
    with torch.no_grad():
        for batch in loader:
            batch = batch.to(device)
            out = model(batch.x_dict, batch.edge_index_dict, batch)  # ✅第三个参数传 batch 本身
            pred = out.argmax(dim=1)
            y = batch.y.view(-1).long()
            correct += (pred == y).sum().item()
            total += y.numel()
    return correct / max(total, 1)

for epoch in range(1, 11):
    model.train()
    for batch in train_loader:
        batch = batch.to(device)
        out = model(batch.x_dict, batch.edge_index_dict, batch)
        loss = model.loss(out, batch.y)
        opt.zero_grad()
        loss.backward()
        opt.step()

    va = eval_acc(val_loader)
    print(f"epoch={epoch} val_acc={va:.4f}")

ta = eval_acc(test_loader)
print("test_acc=", ta)
