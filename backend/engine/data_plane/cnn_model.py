"""
cnn_model.py
------------
Stage: engine/data_plane

1D-CNN over (S_L, S_IAT) sequences, per the project doc:
    "1D-CNN, kernel=3, 64 filters" over "First 30 packet lengths (S_L)"
    for mode, and (S_L, S_IAT) together for inner-traffic type.

Rather than build two separate models, this is one shared convolutional
trunk with two small heads (mode, inner-traffic). This is a deliberate
MVP simplification:
- Both tasks look at the same signal (size + timing rhythm), so a shared
  trunk is a reasonable inductive bias and halves the parameter count /
  training time for the hackathon timeline.
- If the two tasks turn out to fight each other during training (one
  head's loss stalls while the other drops), that's the signal to split
  them into two independent models - noted as a fallback in model_card.md,
  not something to prematurely engineer around now.
"""

import torch
import torch.nn as nn


class DataPlaneCNN(nn.Module):
    def __init__(self, seq_len: int = 30, n_mode_classes: int = 2, n_traffic_classes: int = 3):
        super().__init__()
        self.seq_len = seq_len

        # Shared conv trunk. Input: (batch, 2, seq_len) -> channels = [S_L, S_IAT]
        self.trunk = nn.Sequential(
            nn.Conv1d(in_channels=2, out_channels=64, kernel_size=3, padding=1),
            nn.BatchNorm1d(64),
            nn.ReLU(),
            nn.Conv1d(in_channels=64, out_channels=64, kernel_size=3, padding=1),
            nn.BatchNorm1d(64),
            nn.ReLU(),
            nn.AdaptiveAvgPool1d(1),  # (batch, 64, 1) - length-invariant pooling
        )

        self.mode_head = nn.Sequential(
            nn.Flatten(),
            nn.Linear(64, 32),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(32, n_mode_classes),
        )

        self.traffic_head = nn.Sequential(
            nn.Flatten(),
            nn.Linear(64, 32),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(32, n_traffic_classes),
        )

    def forward(self, x):
        """
        x: (batch, 2, seq_len) float tensor, channel 0 = S_L, channel 1 = S_IAT
        returns: (mode_logits, traffic_logits)
        """
        features = self.trunk(x)
        return self.mode_head(features), self.traffic_head(features)


if __name__ == "__main__":
    # Quick shape sanity check - run `python cnn_model.py`
    model = DataPlaneCNN()
    dummy = torch.randn(8, 2, 30)
    mode_logits, traffic_logits = model(dummy)
    print("mode_logits:", mode_logits.shape)      # expect (8, 2)
    print("traffic_logits:", traffic_logits.shape)  # expect (8, 3)
