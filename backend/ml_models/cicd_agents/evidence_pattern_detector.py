import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib
import os

class EvidencePatternDetector:
    def __init__(self):
        self.model = IsolationForest(contamination=0.1, random_state=42)
        self.scaler = StandardScaler()
        self.is_trained = False
        
    def extract_features(self, evidence_data):
        features = []
        for evidence in evidence_data:
            feature_vector = [
                evidence.get('timestamp_hour', 0),
                evidence.get('files_changed', 0),
                evidence.get('lines_added', 0),
                evidence.get('lines_removed', 0),
                evidence.get('commit_size', 0),
                evidence.get('env_vars_count', 0),
                evidence.get('secrets_accessed', 0),
                evidence.get('build_duration', 0),
            ]
            features.append(feature_vector)
        return np.array(features)
    
    def train(self, evidence_data, labels=None):
        features = self.extract_features(evidence_data)
        features_scaled = self.scaler.fit_transform(features)
        self.model.fit(features_scaled)
        self.is_trained = True
        return self
    
    def predict(self, evidence_data):
        if not self.is_trained:
            raise ValueError("Model not trained. Call train() first.")
        
        features = self.extract_features(evidence_data)
        features_scaled = self.scaler.transform(features)
        predictions = self.model.predict(features_scaled)
        scores = self.model.score_samples(features_scaled)
        
        results = []
        for i, evidence in enumerate(evidence_data):
            is_anomaly = predictions[i] == -1
            anomaly_score = float(scores[i])
            results.append({
                'evidence_id': evidence.get('id', f'evidence_{i}'),
                'is_anomaly': is_anomaly,
                'anomaly_score': anomaly_score,
                'confidence': abs(anomaly_score) * 100
            })
        
        return results
    
    def save_model(self, filepath='backend/ml_models/cicd_agents/evidence_pattern_model.pkl'):
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        joblib.dump({
            'model': self.model,
            'scaler': self.scaler,
            'is_trained': self.is_trained
        }, filepath)
    
    def load_model(self, filepath='backend/ml_models/cicd_agents/evidence_pattern_model.pkl'):
        data = joblib.load(filepath)
        self.model = data['model']
        self.scaler = data['scaler']
        self.is_trained = data['is_trained']
        return self


