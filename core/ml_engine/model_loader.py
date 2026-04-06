import joblib
import os
from .exploit_likelihood_model import train_model
from .feature_builder import build_features

class ModelLoader:
    def __init__(self, model_path: str = "exploit_model.pkl", dataset_path: str = "sample_cve_dataset.csv"):
        self.model_path = model_path
        self.dataset_path = dataset_path
        self.model = None
        self.load_or_train()

    def load_or_train(self):
        try:
            if os.path.exists(self.model_path):
                self.model = joblib.load(self.model_path)
            else:
                self.model_path = train_model(self.dataset_path, self.model_path)
                self.model = joblib.load(self.model_path)
        except Exception as e:
            print(f"ML model load/train failed: {e}. Using dummy model.")
            self.model = None

    def predict(self, vuln) -> float:
        try:
            features = build_features(vuln)
            if self.model:
                return self.model.predict([features])[0]
            else:
                return 0.0
        except:
            return 0.0
