import numpy as np
import torch
from torch import nn


def ry(state, angle, qubit):
    indices = torch.arange(8, device=state.device)
    partner = indices ^ (1 << qubit)
    sign = torch.where((indices & (1 << qubit)) == 0, -1., 1.)
    half_angle = angle.reshape(-1, 1) / 2
    return torch.cos(half_angle) * state + torch.sin(half_angle) * state[:, partner] * sign


def cx(state, control, target):
    indices = torch.arange(8, device=state.device)
    return state[:, indices ^ (((indices >> control) & 1) << target)]


def ring(state):
    for control, target in ((0, 1), (1, 2), (2, 0)):
        state = cx(state, control, target)
    return state


class VQNN(nn.Module):
    def __init__(self, nclass=4, extra=5):
        super().__init__()
        self.theta = nn.Parameter(torch.empty(2, 3))
        self.head = nn.Linear(8 + extra, nclass)

    def forward(self, inputs):
        state = torch.zeros((len(inputs), 8), device=inputs.device, dtype=inputs.dtype)
        state[:, 0] = 1
        for block in range(2):
            for qubit in range(3):
                state = ry(state, inputs[:, block * 3 + qubit] * np.pi, qubit)
            state = ring(state)
        for layer in self.theta:
            for qubit in range(3):
                state = ry(state, layer[qubit], qubit)
            state = ring(state)
        return self.head(torch.cat([state.square(), inputs[:, 6:]], dim=1))
