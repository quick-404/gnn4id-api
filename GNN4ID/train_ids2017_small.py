import os
import random
import numpy as np
import torch
import torch.nn.functional as F
from torch_geometric.loader import DataLoader

from Utility.Functions import NIDSDataset
from Utility.Model import HeteroGNN_Edge  # 使用 HeteroGNN_Edge 模型

from sklearn.metrics import confusion_matrix, classification_report, roc_auc_score


# -----------------------------
# Reproducibility
# -----------------------------
def set_seed(seed=42):
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    torch.cuda.manual_seed_all(seed)


# -----------------------------
# Feature compression
# -----------------------------
def compress_features_inplace(batch):
    """
    数值压缩：x := log1p(abs(x))
    防止 flow 特征尺度过大导致训练不稳。
    """
    for nt in batch.node_types:
        x = batch[nt].x
        x = torch.nan_to_num(x, nan=0.0, posinf=0.0, neginf=0.0)
        batch[nt].x = torch.log1p(x.abs())
    return batch


# -----------------------------
# Helpers: forward / loss / probs
# -----------------------------
def forward_logits_logsoftmax(model, batch, device):
    batch = batch.to(device)
    batch = compress_features_inplace(batch)
    out = model(batch.x_dict, batch.edge_index_dict, batch.edge_attr_dict, batch)  # 确保传递 edge_attr
    y = batch.y.view(-1).long()
    return out, y


def eval_loss_acc(model, loader, device, class_weight=None):
    model.eval()
    total_loss, correct, total = 0.0, 0, 0
    with torch.no_grad():
        for batch in loader:
            out, y = forward_logits_logsoftmax(model, batch, device)
            loss = F.nll_loss(out, y, weight=class_weight)
            total_loss += float(loss.item()) * y.size(0)
            pred = out.argmax(dim=1)
            correct += int((pred == y).sum().item())
            total += int(y.size(0))
    return total_loss / max(total, 1), correct / max(total, 1)


def collect_probs(model, loader, device):
    """
    收集 y_true 与 P(class=1)，用于 AUC/阈值搜索。
    """
    model.eval()
    ys, prob1s = [], []
    with torch.no_grad():
        for batch in loader:
            out, y = forward_logits_logsoftmax(model, batch, device)  # out: log_softmax
            prob1 = out[:, 1].exp().detach().cpu().numpy()  # P(class=1)
            ys.append(y.detach().cpu().numpy())
            prob1s.append(prob1)
    y_true = np.concatenate(ys, axis=0)
    y_prob1 = np.concatenate(prob1s, axis=0)
    return y_true, y_prob1


# -----------------------------
# Metrics at threshold
# -----------------------------
def metrics_at_threshold(y_true, y_prob1, thr):
    """
    y_true: {0,1}
    y_prob1: P(class=1)
    """
    y_pred = (y_prob1 >= thr).astype(np.int64)

    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()

    fpr = fp / max(fp + tn, 1)
    tpr = tp / max(tp + fn, 1)  # recall(attack=1)
    precision1 = tp / max(tp + fp, 1)
    acc = (tp + tn) / max(tp + tn + fp + fn, 1)

    return {
        "thr": float(thr),
        "cm": cm,
        "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp),
        "fpr": float(fpr),
        "recall1": float(tpr),
        "precision1": float(precision1),
        "acc": float(acc),
        "y_pred": y_pred,
    }


def choose_threshold_by_fpr(y_true, y_prob1, fpr_target=0.10, thr_grid=None):
    """
    核心：在验证集上选择阈值，使 FPR <= fpr_target 的前提下，Recall(attack) 最大。
    若完全达不到 fpr_target，则选择“FPR 最小”的阈值（再以 Recall 最大作 tie-break）。
    """
    if thr_grid is None:
        thr_grid = np.linspace(0.01, 0.99, 99)

    all_ms = [metrics_at_threshold(y_true, y_prob1, thr) for thr in thr_grid]

    feasible = [m for m in all_ms if m["fpr"] <= fpr_target]
    if len(feasible) > 0:
        # maximize recall, then maximize precision, then minimize fpr
        feasible.sort(key=lambda m: (m["recall1"], m["precision1"], -m["fpr"]), reverse=True)
        best = feasible[0]
        best["feasible"] = True
        return best
    else:
        # minimize fpr, then maximize recall, then maximize precision
        all_ms.sort(key=lambda m: (m["fpr"], -m["recall1"], -m["precision1"]))
        best = all_ms[0]
        best["feasible"] = False
        return best


def print_binary_report(title, y_true, y_pred, y_prob1):
    print(f"\n===== {title} =====")
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    print("Confusion Matrix:\n", cm)

    tn, fp, fn, tp = cm.ravel()
    fpr = fp / max(fp + tn, 1)
    recall1 = tp / max(tp + fn, 1)
    precision1 = tp / max(tp + fp, 1)
    acc = (tp + tn) / max(tp + tn + fp + fn, 1)

    print(f"FPR (false alarm rate) = {fpr:.4f}")
    print(f"Recall(attack=1)      = {recall1:.4f}")
    print(f"Precision(attack=1)   = {precision1:.4f}")
    print(f"Accuracy              = {acc:.4f}")

    print("\nClassification Report:\n", classification_report(y_true, y_pred, digits=4))

    try:
        auc = roc_auc_score(y_true, y_prob1)
        print(f"ROC-AUC: {auc:.4f}")
    except Exception as e:
        print("ROC-AUC failed:", e)


# -----------------------------
# Main
# -----------------------------
def main():
    set_seed(42)

    # CPU
    device = torch.device("cpu")

    # 路径与你当前一致
    root = r"E:\wyc\GNN-IDS\data"
    csv_name = "Wednesday_gnn4id_ready_small1.csv"

    # 读 processed/data_*.pt
    ds = NIDSDataset(
        root=root,
        label_dict={},
        filename=[csv_name],
        single_file=True,
        include_packetflag=True,
        include_packetpayload=True,
        skip_processing=True,  #False 会更新.pt文件
        test=False
    )

    n = len(ds)
    print("Total graphs:", n)

    # 随机划分（保持你原逻辑）
    idx = torch.randperm(n)
    n_train = int(0.7 * n)
    n_val = int(0.15 * n)
    train_idx = idx[:n_train]
    val_idx = idx[n_train:n_train + n_val]
    test_idx = idx[n_train + n_val:]

    train_set = torch.utils.data.Subset(ds, train_idx.tolist())
    val_set = torch.utils.data.Subset(ds, val_idx.tolist())
    test_set = torch.utils.data.Subset(ds, test_idx.tolist())

    batch_size = 8  # CPU
    train_loader = DataLoader(train_set, batch_size=batch_size, shuffle=True)
    val_loader = DataLoader(val_set, batch_size=batch_size, shuffle=False)
    test_loader = DataLoader(test_set, batch_size=batch_size, shuffle=False)

    # Model init
    sample = ds[0]
    args = {"hidden_size": 64, "eps": 1e-5}
    model = HeteroGNN_Edge(sample, args).to(device)

    # -----------------------------
    # 关键超参：你的目标是降误报(FPR)
    # -----------------------------
    FPR_TARGET = 0.1       # 先从 10% 开始；你也可以改成 0.05 / 0.01
    MAX_EPOCHS = 50         # 让 early stop 决定停哪里
    PATIENCE = 6            # 连续多少轮 val 不提升就停
    LR = 1e-4

    # loss 权重：提高 class0(benign) 权重 => 更“怕”把正常判成攻击 => 倾向降低 FP
    # 你可以试：W0=1.0/2.0/3.0，看 FPR/Recall 的 trade-off
    W0_BENIGN = 2.0
    W1_ATTACK = 1.0
    class_weight = torch.tensor([W0_BENIGN, W1_ATTACK], dtype=torch.float32, device=device)

    optim = torch.optim.Adam(model.parameters(), lr=LR, weight_decay=1e-4)

    # 保存 checkpoint（包含阈值）
    save_path = os.path.join(root, "Wednesday_best_model_ids2017_small11.pt")

    # -----------------------------
    # Sanity check（只做基本检查）
    # -----------------------------
    first_batch = next(iter(train_loader))
    first_batch = compress_features_inplace(first_batch)
    y0 = first_batch.y.view(-1).long()
    print("\n=== SANITY CHECK (before training) ===")
    for nt in first_batch.node_types:
        x = first_batch[nt].x
        print(f"{nt:>6s} x shape={tuple(x.shape)}  nan={torch.isnan(x).any().item()} inf={torch.isinf(x).any().item()}")
    print("y bincount (raw):", torch.bincount(y0).cpu().numpy())
    print("======================================\n")

    # -----------------------------
    # Training loop: 按“val 上 Recall@FPR<=target”保存 best
    # -----------------------------
    best_score = None
    best_meta = None
    bad_epochs = 0

    for epoch in range(1, MAX_EPOCHS + 1):
        model.train()
        for batch in train_loader:
            out, y = forward_logits_logsoftmax(model, batch, device)
            loss = F.nll_loss(out, y, weight=class_weight)

            optim.zero_grad()
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optim.step()

        # eval
        train_loss, train_acc = eval_loss_acc(model, train_loader, device, class_weight=class_weight)
        val_loss, val_acc = eval_loss_acc(model, val_loader, device, class_weight=class_weight)

        # val probs for AUC & threshold selection
        yv, pv = collect_probs(model, val_loader, device)
        try:
            val_auc = roc_auc_score(yv, pv)
        except Exception:
            val_auc = float("nan")

        best_thr_pack = choose_threshold_by_fpr(yv, pv, fpr_target=FPR_TARGET)
        thr = best_thr_pack["thr"]
        fpr = best_thr_pack["fpr"]
        tpr = best_thr_pack["recall1"]

        # score：优先满足 FPR_TARGET，其次最大化 recall，再看 AUC
        # 用 tuple 做可比较分数
        feasible = 1 if best_thr_pack.get("feasible", False) else 0
        score = (feasible, tpr, -fpr, val_auc)

        print(
            f"Epoch {epoch:02d} | "
            f"train loss {train_loss:.4f} acc {train_acc:.4f} | "
            f"val loss {val_loss:.4f} acc {val_acc:.4f} auc {val_auc:.4f} | "
            f"val@thr={thr:.2f} FPR {fpr:.4f} TPR {tpr:.4f} (target FPR<={FPR_TARGET:.2f})"
        )

        if (best_score is None) or (score > best_score):
            best_score = score
            best_meta = {
                "epoch": epoch,
                "thr": thr,
                "val_fpr": fpr,
                "val_tpr": tpr,
                "val_auc": val_auc,
                "fpr_target": FPR_TARGET,
                "class_weight": [W0_BENIGN, W1_ATTACK],
                "lr": LR,
                "batch_size": batch_size,
            }
            torch.save({"state_dict": model.state_dict(), "meta": best_meta}, save_path)
            print("  -> saved best (by Recall@FPR target) to:", save_path)
            bad_epochs = 0
        else:
            bad_epochs += 1
            if bad_epochs >= PATIENCE:
                print(f"  -> early stop: {PATIENCE} epochs no improvement.")
                break

    # -----------------------------
    # TEST: load best + report at thr=0.50 and thr=best_val_thr
    # -----------------------------
    ckpt = torch.load(save_path, map_location=device)
    model.load_state_dict(ckpt["state_dict"])
    meta = ckpt.get("meta", {})
    best_thr = float(meta.get("thr", 0.50))

    print("\nBest model path:", save_path)
    print("Best meta:", meta)

    # ===== 不重训：同一个 best checkpoint 下，扫多个 FPR_TARGET 选择阈值 =====
    # 重要：阈值永远只在 VAL 上选；TEST 只是用来“看效果”，避免信息泄漏
    FPR_TARGETS = [0.10, 0.05, 0.03, 0.02, 0.01]

    # 收集 VAL / TEST 的概率
    yv, pv = collect_probs(model, val_loader, device)
    yt, pt = collect_probs(model, test_loader, device)

    print("\n==== Threshold sweep (choose thr on VAL, evaluate on TEST) ====")
    for tgt in FPR_TARGETS:
        best_pack = choose_threshold_by_fpr(yv, pv, fpr_target=tgt)
        thr = best_pack["thr"]
        val_fpr = best_pack["fpr"]
        val_tpr = best_pack["recall1"]

        mtgt = metrics_at_threshold(yt, pt, thr)
        print(
            f"\n[TARGET FPR<= {tgt:.2f}] chosen thr={thr:.2f} | "
            f"VAL: FPR={val_fpr:.4f} Recall={val_tpr:.4f} | "
            f"TEST: FPR={mtgt['fpr']:.4f} Recall={mtgt['recall1']:.4f} "
            f"Prec={mtgt['precision1']:.4f} Acc={mtgt['acc']:.4f}"
        )
        print("TEST CM:\n", mtgt["cm"])

    # default 0.50
    m05 = metrics_at_threshold(yt, pt, 0.50)
    print_binary_report("TEST (default thr=0.50)", yt, m05["y_pred"], pt)

    # tuned threshold from VAL
    mt = metrics_at_threshold(yt, pt, best_thr)
    print_binary_report(f"TEST (tuned thr from VAL={best_thr:.2f})", yt, mt["y_pred"], pt)


if __name__ == "__main__":
    main()
