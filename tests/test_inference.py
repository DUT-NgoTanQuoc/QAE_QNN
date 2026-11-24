import json
import shutil
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import torch
from qiskit import QuantumCircuit
from qiskit.quantum_info import Statevector

from core.config import ARTIFACTS, CLASSES, FEATURES, MODEL_DIR, RESULTS
from core.model_loader import ModelLoadError, load_model
from core.preprocessing import transform
from scripts.verify_inference import load_test_windows, verify, verify_test_metrics

PCAP = RESULTS / "pcap"
PROBABILITIES = [f"prob_{label}" for label in CLASSES]


def add_cx_ring(circuit):
    circuit.cx(0, 1)
    circuit.cx(1, 2)
    circuit.cx(2, 0)


class InferenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine = load_model()
        cls.windows = load_test_windows(PCAP)

    def test_checkpoint_tensors_on_cpu(self):
        saved = torch.load(MODEL_DIR / "hybrid.pt", map_location="cpu", weights_only=True)
        model = self.engine.model
        self.assertFalse(model.training)
        for name, tensor in model.named_parameters():
            with self.subTest(tensor=name):
                self.assertFalse(tensor.requires_grad)
                torch.testing.assert_close(tensor, saved[name], rtol=0, atol=0)

    def test_tensor_contract_matches_independent_statevector_circuits(self):
        windows = self.windows.groupby("label", sort=False).head(1)
        shuffled = windows.loc[:, list(reversed(FEATURES))].assign(label="metadata")
        scaler = self.engine.scaler
        raw = windows.loc[:, list(FEATURES)].to_numpy()
        normalized = np.clip(np.log1p(raw) * scaler.scale_ + scaler.min_, 0., 1.)
        np.testing.assert_array_equal(transform(shuffled, scaler), normalized)
        theta = np.load(MODEL_DIR / "qae_theta.npy", allow_pickle=False)
        self.assertEqual(theta.dtype, np.dtype("float64"))
        gates = QuantumCircuit(3)
        for qubit, (a, b, c) in enumerate(theta.reshape(3, 3)):
            gates.rx(a, qubit)
            gates.ry(b, qubit)
            gates.rz(c, qubit)
        add_cx_ring(gates)
        qae_features = []
        for row in normalized:
            padded = np.pad(row, (0, 2))
            norm = np.linalg.norm(padded)
            state = Statevector(padded / norm) if norm else Statevector.from_label("000")
            state = state.evolve(gates)
            qae_features.append([state.probabilities([2])[1], *state.probabilities([0, 1])])
        self.assertEqual(normalized.dtype, np.dtype("float64"))
        np.testing.assert_allclose(self.engine.qae.features(normalized), qae_features, rtol=0, atol=1e-12)

        expected_input = torch.tensor(np.column_stack([normalized, qae_features]), dtype=torch.float32)
        torch_inputs = []
        handle = self.engine.model.register_forward_pre_hook(
            lambda _model, args: torch_inputs.append(args[0])
        )
        try:
            actual = self.engine.predict(shuffled, include_probabilities=True)
        finally:
            handle.remove()
        self.assertEqual(torch_inputs[0].shape, (len(windows), 11))
        torch.testing.assert_close(torch_inputs[0], expected_input, rtol=0, atol=1e-7)

        # Independently build the variational circuit using Qiskit gates.
        model = self.engine.model
        head_inputs = []
        for row in expected_input.numpy():
            circuit = QuantumCircuit(3)
            angles = np.concatenate([row[:6].reshape(2, 3) * np.pi, model.theta.detach().numpy()])
            for layer in angles:
                for qubit, angle in enumerate(layer):
                    circuit.ry(float(angle), qubit)
                add_cx_ring(circuit)
            probability = Statevector.from_instruction(circuit).probabilities()
            head_inputs.append(np.concatenate([probability, row[6:]]))
        with torch.inference_mode():
            expected = model.head(torch.tensor(np.array(head_inputs), dtype=torch.float32)).softmax(1).numpy()
        np.testing.assert_allclose(actual[PROBABILITIES], expected, rtol=0, atol=2e-6)

    def test_colab_parity_and_multiple_batches(self):
        windows, actual = verify(self.engine, PCAP)
        verify_test_metrics(windows, actual, PCAP)
        self.assertEqual((len(windows), windows.file.nunique()), (83, 16))
        for batch_size in (1, 16):
            with self.subTest(batch_size=batch_size):
                batch = self.engine.predict(windows, batch_size, include_probabilities=True)
                pd.testing.assert_frame_equal(batch.drop(columns="inference_ms"),
                                              actual.drop(columns="inference_ms"), rtol=0, atol=2e-6)
                self.assertTrue((batch.inference_ms >= 0).all())
        np.testing.assert_allclose(actual[PROBABILITIES].sum(axis=1), 1., rtol=0, atol=1e-6)
        np.testing.assert_array_equal(actual.confidence, actual[PROBABILITIES].max(axis=1))
        np.testing.assert_array_equal(actual.prediction, np.array(CLASSES)[actual[PROBABILITIES].to_numpy().argmax(1)])
        np.testing.assert_array_equal(actual.attack_probability, 1 - actual.prob_Normal)
        np.testing.assert_array_equal(actual.binary_prediction, np.where(actual.attack_probability >= .5, "Attack", "Benign"))

    def test_qae_threshold_is_strict_at_observed_score(self):
        window = self.windows.iloc[:1]
        original = self.engine.predict(window).iloc[0]
        test_thresholds = [original.anomaly_score, np.nextafter(original.anomaly_score, -np.inf)]
        for threshold, flag in zip(test_thresholds, (False, True)):
            config = replace(self.engine.config, threshold=threshold)
            actual = replace(self.engine, config=config).predict(window).iloc[0]
            self.assertEqual(actual.qae_alert, flag)
            self.assertEqual(actual.prediction, original.prediction)
            self.assertEqual(actual.binary_prediction, original.binary_prediction)
            self.assertEqual(actual.confidence, original.confidence)

    def test_malformed_input_fails_before_inference(self):
        windows = self.windows.iloc[:2]
        for batch_size in (0, -1, 1.5, True):
            with self.subTest(batch_size=batch_size), self.assertRaisesRegex(ValueError, "batch_size"):
                self.engine.predict(windows, batch_size)
        for invalid in (windows.drop(columns="f2"), pd.concat([windows, windows[["f2"]]], axis=1)):
            with self.assertRaisesRegex(ValueError, "đúng một cột"):
                self.engine.predict(invalid)
        complex_values = windows.loc[:, list(FEATURES)].to_numpy(dtype=np.complex128)
        with self.assertRaisesRegex(ValueError, "số thực"):
            self.engine.predict(complex_values)

    def test_invalid_config_scaler_and_qae_artifact_fail_loading(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            for name in ARTIFACTS:
                shutil.copyfile(MODEL_DIR / name, folder / name)
            config_path = folder / "config.json"
            original = json.loads(config_path.read_text(encoding="utf-8"))
            for change in ({"threshold": True}, {"features": list(reversed(FEATURES))}):
                config_path.write_text(json.dumps(original | change), encoding="utf-8")
                with self.assertRaisesRegex(ModelLoadError, "Config|threshold"):
                    load_model(folder)
            shutil.copyfile(MODEL_DIR / "config.json", config_path)
            scaler_path = folder / "scaler.joblib"
            scaler = joblib.load(scaler_path)
            scaler.feature_range = (-1, 1)
            joblib.dump(scaler, scaler_path)
            with self.assertRaisesRegex(ModelLoadError, "feature_range"):
                load_model(folder)
            shutil.copyfile(MODEL_DIR / "scaler.joblib", scaler_path)
            np.save(folder / "qae_theta.npy", np.full(9, 1j))
            with self.assertRaisesRegex(ModelLoadError, "Theta QAE"):
                load_model(folder)
