import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from difflib import SequenceMatcher
import joblib
import os

class DependencyAnomalyDetector:
    def __init__(self):
        self.model = IsolationForest(contamination=0.15, random_state=42)
        self.scaler = StandardScaler()
        self.is_trained = False
        self.known_packages = set()
        
    def calculate_similarity(self, name1, name2):
        return SequenceMatcher(None, name1.lower(), name2.lower()).ratio()
    
    def extract_features(self, dependency_data):
        features = []
        for dep in dependency_data:
            package_name = dep.get('name', '').lower()
            version = dep.get('version', '0.0.0')
            
            max_similarity = 0
            if self.known_packages:
                max_similarity = max([
                    self.calculate_similarity(package_name, known)
                    for known in self.known_packages
                ])
            
            version_parts = version.split('.')
            major = int(version_parts[0]) if len(version_parts) > 0 and version_parts[0].isdigit() else 0
            minor = int(version_parts[1]) if len(version_parts) > 1 and version_parts[1].isdigit() else 0
            patch = int(version_parts[2]) if len(version_parts) > 2 and version_parts[2].isdigit() else 0
            
            has_suspicious_chars = int(any(c in package_name for c in ['-', '_', '.', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9']))
            name_length = len(package_name)
            
            feature_vector = [
                max_similarity,
                major,
                minor,
                patch,
                has_suspicious_chars,
                name_length,
                dep.get('is_new', 0),
                dep.get('version_change_count', 0),
                dep.get('days_since_release', 0),
            ]
            features.append(feature_vector)
        return np.array(features)
    
    def train(self, dependency_data, labels=None):
        for dep in dependency_data:
            self.known_packages.add(dep.get('name', '').lower())
        
        features = self.extract_features(dependency_data)
        features_scaled = self.scaler.fit_transform(features)
        self.model.fit(features_scaled)
        self.is_trained = True
        return self
    
    def predict(self, dependency_data):
        if not self.is_trained:
            raise ValueError("Model not trained. Call train() first.")
        
        features = self.extract_features(dependency_data)
        features_scaled = self.scaler.transform(features)
        predictions = self.model.predict(features_scaled)
        scores = self.model.score_samples(features_scaled)
        
        results = []
        for i, dep in enumerate(dependency_data):
            is_anomaly = predictions[i] == -1
            anomaly_score = float(scores[i])
            
            package_name = dep.get('name', '').lower()
            max_similarity = 0
            closest_match = None
            if self.known_packages:
                similarities = [
                    (self.calculate_similarity(package_name, known), known)
                    for known in self.known_packages
                ]
                max_similarity, closest_match = max(similarities, key=lambda x: x[0])
            
            anomaly_type = 'normal'
            if is_anomaly:
                if max_similarity > 0.7 and max_similarity < 0.95:
                    anomaly_type = 'typosquatting'
                elif max_similarity < 0.3:
                    anomaly_type = 'unknown_package'
                else:
                    anomaly_type = 'suspicious_dependency'
            
            results.append({
                'dependency_id': dep.get('id', f'dep_{i}'),
                'package_name': dep.get('name', ''),
                'is_anomaly': is_anomaly,
                'anomaly_score': anomaly_score,
                'confidence': abs(anomaly_score) * 100,
                'anomaly_type': anomaly_type,
                'closest_match': closest_match,
                'similarity_score': max_similarity
            })
        
        return results
    
    def save_model(self, filepath='backend/ml_models/anomaly_detection/dependency_anomaly_model.pkl'):
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        joblib.dump({
            'model': self.model,
            'scaler': self.scaler,
            'known_packages': self.known_packages,
            'is_trained': self.is_trained
        }, filepath)
    
    def load_model(self, filepath='backend/ml_models/anomaly_detection/dependency_anomaly_model.pkl'):
        data = joblib.load(filepath)
        self.model = data['model']
        self.scaler = data['scaler']
        self.known_packages = data['known_packages']
        self.is_trained = data['is_trained']
        return self


