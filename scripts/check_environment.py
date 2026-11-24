import json
import platform
from importlib.metadata import version

import torch
from qiskit import QuantumCircuit
from qiskit.quantum_info import Statevector

from core.config import MODEL_DIR
from core.model_loader import load_model


def main():
    expected = json.loads((MODEL_DIR / "environment.json").read_text(encoding="utf-8"))
    print(f"Python {platform.python_version()} | {platform.platform()}")
    differences = []
    for name, wanted in expected.items():
        actual = version(name)
        print(f"{name} {actual} | Colab {wanted}")
        if actual != wanted:
            differences.append(name)
    circuit = QuantumCircuit(3)
    circuit.h(0)
    assert abs(Statevector.from_instruction(circuit).probabilities()[1] - .5) < 1e-12
    assert torch.tensor([1.], device="cpu").square().item() == 1
    load_model()
    print(f"Streamlit {version('streamlit')} | Plotly {version('plotly')} | CPU smoke test OK")
    if differences:
        raise SystemExit(f"Khác phiên bản Colab: {', '.join(differences)}")


if __name__ == "__main__":
    main()
