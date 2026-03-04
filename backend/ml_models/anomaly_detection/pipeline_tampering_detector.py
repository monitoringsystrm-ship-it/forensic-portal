import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline
import joblib
import os
import re

class PipelineTamperingDetector:
    def __init__(self):
        self.vectorizer = TfidfVectorizer(max_features=1000, ngram_range=(1, 3))
        self.model = RandomForestClassifier(n_estimators=100, random_state=42)
        self.pipeline = None
        self.is_trained = False
        
    def extract_suspicious_patterns(self, script_content):
        suspicious_keywords = [
            'curl', 'wget', 'nc', 'netcat', 'base64', 'eval', 'exec',
            'powershell', 'bash -c', 'sh -c', 'python -c', 'perl -e',
            'rm -rf', 'del /f', 'format', 'dd if=', 'mkfs',
            'chmod 777', 'chown', 'sudo', 'su -', 'passwd'
        ]
        
        script_lower = script_content.lower()
        pattern_count = sum(1 for keyword in suspicious_keywords if keyword in script_lower)
        
        has_external_call = bool(re.search(r'https?://|ftp://|sftp://', script_content))
        has_encoded_content = bool(re.search(r'base64|eval\(|exec\(', script_content, re.IGNORECASE))
        has_suspicious_redirect = bool(re.search(r'>&|2>&1|>/dev/null', script_content))
        
        return {
            'suspicious_keywords': pattern_count,
            'has_external_call': int(has_external_call),
            'has_encoded_content': int(has_encoded_content),
            'has_suspicious_redirect': int(has_suspicious_redirect),
            'script_length': len(script_content),
            'line_count': script_content.count('\n') + 1
        }
    
    def train(self, pipeline_scripts, labels):
        features = []
        script_texts = []
        
        for script in pipeline_scripts:
            script_content = script.get('content', '')
            script_texts.append(script_content)
            
            pattern_features = self.extract_suspicious_patterns(script_content)
            features.append(list(pattern_features.values()))
        
        X_text = self.vectorizer.fit_transform(script_texts).toarray()
        X_patterns = np.array(features)
        X_combined = np.hstack([X_text, X_patterns])
        
        self.model.fit(X_combined, labels)
        self.is_trained = True
        
        train_score = self.model.score(X_combined, labels)
        
        return {
            'train_accuracy': train_score
        }
    
    def predict(self, pipeline_scripts):
        if not self.is_trained:
            raise ValueError("Model not trained. Call train() first.")
        
        features = []
        script_texts = []
        
        for script in pipeline_scripts:
            script_content = script.get('content', '')
            script_texts.append(script_content)
            
            pattern_features = self.extract_suspicious_patterns(script_content)
            features.append(list(pattern_features.values()))
        
        X_text = self.vectorizer.transform(script_texts).toarray()
        X_patterns = np.array(features)
        X_combined = np.hstack([X_text, X_patterns])
        
        predictions = self.model.predict(X_combined)
        probabilities = self.model.predict_proba(X_combined)
        
        results = []
        for i, script in enumerate(pipeline_scripts):
            is_tampered = predictions[i] == 1
            confidence = float(probabilities[i][1] * 100)
            
            pattern_features = self.extract_suspicious_patterns(script.get('content', ''))
            
            results.append({
                'script_id': script.get('id', f'script_{i}'),
                'is_tampered': is_tampered,
                'confidence': confidence,
                'suspicious_patterns': pattern_features,
                'anomaly_type': 'pipeline_tampering' if is_tampered else 'normal'
            })
        
        return results
    
    def save_model(self, filepath='backend/ml_models/anomaly_detection/pipeline_tampering_model.pkl'):
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        joblib.dump({
            'model': self.model,
            'vectorizer': self.vectorizer,
            'is_trained': self.is_trained
        }, filepath)
    
    def load_model(self, filepath='backend/ml_models/anomaly_detection/pipeline_tampering_model.pkl'):
        data = joblib.load(filepath)
        self.model = data['model']
        self.vectorizer = data['vectorizer']
        self.is_trained = data['is_trained']
        return self


