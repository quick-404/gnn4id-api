import torch
import torch.nn as nn
import torch.nn.functional as F
import torch_geometric.nn as pyg_nn
from torch_geometric.nn import HeteroConv, GATConv, TransformerConv


class HeteroGNN(nn.Module):
    """Heterogeneous Graph Classifier with attention mechanism (GATConv)."""

    def __init__(self, hetero_graph, args):
        super(HeteroGNN, self).__init__()
        hidden = int(args.get("hidden_size", 64))
        eps = float(args.get("eps", 1e-5))

        self.hidden = hidden

        # 增加更多的图卷积层
        self.convs1 = HeteroConv(
            {edge_type: GATConv((-1, -1), hidden) for edge_type in hetero_graph.metadata()[1]},
            aggr="sum",
        )
        self.convs2 = HeteroConv(
            {edge_type: GATConv((-1, -1), hidden) for edge_type in hetero_graph.metadata()[1]},
            aggr="sum",
        )
        self.convs3 = HeteroConv(  # 新增图卷积层
            {edge_type: GATConv((-1, -1), hidden) for edge_type in hetero_graph.metadata()[1]},
            aggr="sum",
        )

        self.bns1 = nn.ModuleDict({nt: nn.BatchNorm1d(hidden, eps=eps) for nt in hetero_graph.node_types})
        self.bns2 = nn.ModuleDict({nt: nn.BatchNorm1d(hidden, eps=eps) for nt in hetero_graph.node_types})
        self.bns3 = nn.ModuleDict({nt: nn.BatchNorm1d(hidden, eps=eps) for nt in hetero_graph.node_types})  # 新增 BN
        self.act = nn.LeakyReLU()

        in_dim = len(hetero_graph.node_types) * hidden
        self.mlp = nn.Sequential(
            nn.Linear(in_dim, 64),
            nn.LeakyReLU(),
            nn.Linear(64, 16),
            nn.LeakyReLU(),
            nn.Linear(16, 2),  # 二分类：0/1
        )

    def forward(self, x_dict, edge_index_dict, batch):
        # 第一层卷积
        x = self.convs1(x_dict, edge_index_dict)
        x = {k: self.act(self.bns1[k](v)) for k, v in x.items()}

        # 第二层卷积
        x = self.convs2(x, edge_index_dict)
        x = {k: self.act(self.bns2[k](v)) for k, v in x.items()}

        # 第三层卷积（增加的层）
        x = self.convs3(x, edge_index_dict)
        x = {k: self.act(self.bns3[k](v)) for k, v in x.items()}

        graph_emb = {k: pyg_nn.global_mean_pool(x[k], batch.batch_dict[k]) for k in batch.node_types}
        graph_emb = torch.cat([graph_emb[k] for k in graph_emb.keys()], dim=1)

        out = self.mlp(graph_emb)
        return F.log_softmax(out, dim=1)

    def loss(self, preds, label):
        label = label.view(-1).long()
        return F.nll_loss(preds, label)


class HeteroGNN_Edge(nn.Module):
    """Heterogeneous Graph Classifier with edge_attr (GATConv)."""
    def __init__(self, hetero_graph, args):
        super().__init__()
        hidden = int(args.get("hidden_size", 64))
        eps = float(args.get("eps", 1e-5))

        edge_dim_map = {
            ("flow", "contain", "packet"): 4,
            ("packet", "rev_contain", "flow"): 4,
            ("packet", "link", "packet"): 1,
        }

        def make_gat(edge_type):
            edim = edge_dim_map.get(edge_type, 0)
            if edim > 0:
                return GATConv((-1, -1), hidden, edge_dim=edim, add_self_loops=False)
            else:
                return GATConv((-1, -1), hidden, add_self_loops=False)

        self.convs1 = HeteroConv(
            {edge_type: make_gat(edge_type) for edge_type in hetero_graph.metadata()[1]},
            aggr="sum",
        )
        self.convs2 = HeteroConv(
            {edge_type: make_gat(edge_type) for edge_type in hetero_graph.metadata()[1]},
            aggr="sum",
        )
       # self.convs3 = HeteroConv(  # 新增图卷积层
       #     {edge_type: make_gat(edge_type) for edge_type in hetero_graph.metadata()[1]},
       #     aggr="sum",
       # )

        self.bns1 = nn.ModuleDict({nt: nn.BatchNorm1d(hidden, eps=eps) for nt in hetero_graph.node_types})
        self.bns2 = nn.ModuleDict({nt: nn.BatchNorm1d(hidden, eps=eps) for nt in hetero_graph.node_types})
       # self.bns3 = nn.ModuleDict({nt: nn.BatchNorm1d(hidden, eps=eps) for nt in hetero_graph.node_types})  # 新增 BN
        self.act = nn.LeakyReLU()

        in_dim = len(hetero_graph.node_types) * hidden
        self.mlp = nn.Sequential(
            nn.Linear(in_dim, 64),
            nn.LeakyReLU(),
            nn.Linear(64, 16),
            nn.LeakyReLU(),
            nn.Linear(16, 2),
        )

    def forward(self, x_dict, edge_index_dict, edge_attr_dict, batch):
        x = self.convs1(x_dict, edge_index_dict, edge_attr_dict)
        x = {k: self.act(self.bns1[k](v)) for k, v in x.items()}

        x = self.convs2(x, edge_index_dict, edge_attr_dict)
        x = {k: self.act(self.bns2[k](v)) for k, v in x.items()}

       # x = self.convs3(x, edge_index_dict, edge_attr_dict)  # 使用新增的图卷积层
       # x = {k: self.act(self.bns3[k](v)) for k, v in x.items()}

        graph_emb = {k: pyg_nn.global_mean_pool(x[k], batch.batch_dict[k]) for k in batch.node_types}
        graph_emb = torch.cat([graph_emb[k] for k in graph_emb.keys()], dim=1)

        out = self.mlp(graph_emb)
        return F.log_softmax(out, dim=1)

    def loss(self, preds, label):
        label = label.view(-1).long()
        return F.nll_loss(preds, label)

