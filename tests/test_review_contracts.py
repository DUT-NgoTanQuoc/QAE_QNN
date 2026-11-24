import hashlib
import unittest

import pandas as pd

from core.config import MODEL_DIR
from core.model_loader import load_model


class ReviewContractTests(unittest.TestCase):
    def test_reviewed_artifact_checksums(self):
        expected = {}
        for line in (MODEL_DIR / "checksums.sha256").read_text(encoding="ascii").splitlines():
            digest, name = line.split(maxsplit=1)
            expected[name] = digest
        self.assertEqual(set(expected), {"config.json", "hybrid.pt", "qae_theta.npy", "scaler.joblib"})
        for name, digest in expected.items():
            with self.subTest(artifact=name):
                actual = hashlib.sha256((MODEL_DIR / name).read_bytes()).hexdigest()
                self.assertEqual(actual, digest)

    def test_labels_and_unrelated_metadata_cannot_change_prediction(self):
        engine = load_model()
        features = pd.DataFrame([[10, 2, 3, 1, 0.5, 4]], columns=engine.config.features)
        first = engine.predict(features).drop(columns="inference_ms")
        decorated = features.assign(label="Attack", target=999, prediction="hardcoded")
        second = engine.predict(decorated).drop(columns="inference_ms")
        pd.testing.assert_frame_equal(first, second, rtol=0, atol=0)


if __name__ == "__main__":
    unittest.main()
