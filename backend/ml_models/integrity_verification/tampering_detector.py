import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
import joblib
import os
import hashlib

class TamperingDetector:
    def __init__(self):
        self.model = RandomForestClassifier(n_estimators=100, random_state=42)
        self.scaler = StandardScaler()
        self.is_trained = False
        
    def calculate_hash_features(self, artifact_data):
        features = []
        for artifact in artifact_data:
            expected_hash = artifact.get('expected_hash', '')
            actual_hash = artifact.get('actual_hash', '')
            
            hash_match = int(expected_hash == actual_hash)
            
            if expected_hash and actual_hash:
                hash_distance = sum(
                    c1 != c2 for c1, c2 in zip(expected_hash, actual_hash)
                ) / max(len(expected_hash), len(actual_hash))
            else:
                hash_distance = 0.0
            
            size = artifact.get('size', 0)
            size_change = artifact.get('size_change', 0)
            size_change_percent = (size_change / size * 100) if size > 0 else 0
            
            timestamp_diff = artifact.get('timestamp_diff', 0)
            has_signature = int(bool(artifact.get('signature', '')))
            signature_valid = int(artifact.get('signature_valid', False))
            
            feature_vector = [
                hash_match,
                hash_distance,
                size,
                size_change,
                size_change_percent,
                timestamp_diff,
                has_signature,
                signature_valid,
                artifact.get('merkle_tree_valid', 0),
                artifact.get('sbom_hash_match', 0),
            ]
            features.append(feature_vector)
        return np.array(features)
    
    def train(self, artifact_data, labels):
        features = self.calculate_hash_features(artifact_data)
        features_scaled = self.scaler.fit_transform(features)
        self.model.fit(features_scaled, labels)
        self.is_trained = True
        
        train_score = self.model.score(features_scaled, labels)
        
        return {
            'train_accuracy': train_score
        }
    
    def predict(self, artifact_data):
        if not self.is_trained:
            raise ValueError("Model not trained. Call train() first.")
        
        features = self.calculate_hash_features(artifact_data)
        features_scaled = self.scaler.transform(features)
        predictions = self.model.predict(features_scaled)
        probabilities = self.model.predict_proba(features_scaled)
        
        results = []
        for i, artifact in enumerate(artifact_data):
            is_tampered = predictions[i] == 1
            confidence = float(probabilities[i][1] * 100)
            
            tampering_type = 'normal'
            if is_tampered:
                expected_hash = artifact.get('expected_hash', '')
                actual_hash = artifact.get('actual_hash', '')
                if expected_hash != actual_hash:
                    tampering_type = 'hash_mismatch'
                elif artifact.get('size_change', 0) != 0:
                    tampering_type = 'size_change'
                elif not artifact.get('signature_valid', True):
                    tampering_type = 'signature_invalid'
                else:
                    tampering_type = 'suspicious_modification'
            
            results.append({
                'artifact_id': artifact.get('id', f'artifact_{i}'),
                'is_tampered': is_tampered,
                'confidence': confidence,
                'tampering_type': tampering_type,
                'integrity_status': 'compromised' if is_tampered else 'verified'
            })
        
        return results
    
    def verify_hash(self, content, expected_hash):
        actual_hash = hashlib.sha256(content.encode() if isinstance(content, str) else content).hexdigest()
        return actual_hash == expected_hash
    
    def save_model(self, filepath='backend/ml_models/integrity_verification/tampering_detector_model.pkl'):
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        joblib.dump({
            'model': self.model,
            'scaler': self.scaler,
            'is_trained': self.is_trained
        }, filepath)
    
    def load_model(self, filepath='backend/ml_models/integrity_verification/tampering_detector_model.pkl'):
        data = joblib.load(filepath)
        self.model = data['model']
        self.scaler = data['scaler']
        self.is_trained = data['is_trained']
        return self


