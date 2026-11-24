import numpy as np
from qiskit import QuantumCircuit
from qiskit.quantum_info import Operator


def amplitudes(values):
    padded = np.pad(values, ((0, 0), (0, 2))).astype(float)
    padded[np.linalg.norm(padded, axis=1) == 0, 0] = 1
    return padded / np.linalg.norm(padded, axis=1, keepdims=True)


def encoder(theta, layers):
    circuit = QuantumCircuit(3)
    for layer in np.asarray(theta).reshape(layers, 3, 3):
        for qubit, (a, b, c) in enumerate(layer):
            circuit.rx(a, qubit)
            circuit.ry(b, qubit)
            circuit.rz(c, qubit)
        circuit.cx(0, 1)
        circuit.cx(1, 2)
        circuit.cx(2, 0)
    return circuit


class QAE:
    def __init__(self, theta, layers):
        self.operator = Operator(encoder(theta, layers)).data

    def features(self, values):
        probability = np.abs(amplitudes(values) @ self.operator.T) ** 2
        return np.column_stack([
            probability[:, 4:].sum(1),
            probability[:, :4] + probability[:, 4:],
        ])
