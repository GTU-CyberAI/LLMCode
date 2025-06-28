# TRAINED MODEL LOADER
# Eğitilmiş modeli yüklemek için gerekli class tanımları
# consistent_security_analyzer.pkl dosyası için

import pickle
import re
import numpy as np
from typing import Dict, List, Optional, Any

# ======================== ORIGINAL CLASS DEFINITIONS ========================
# Bu class'lar PKL dosyasını yüklemek için gerekli

class UltimateVulnerabilityScanner:
    """PKL dosyasında referans edilen eksik class"""
    
    def __init__(self, *args, **kwargs):
        pass
    
    def scan(self, code):
        return {"vulnerable": False, "score": 0.0}
    
    def analyze(self, code):
        return self.scan(code)

class SimpleEnhancedScanner:
    """Enhanced scanner base class"""
    
    def __init__(self, base_scanner=None):  
        self.base_scanner = base_scanner
        
        # Expert rules - eğitim sırasında kullanılan
        self.critical_vulnerable = [
            r'gets\s*\(',
            r'system\s*\([^)]*argv',
            r'strcpy\s*\([^,]+,\s*argv',
            r'sprintf\s*\([^,]+,.*%s.*argv'
        ]
        
        self.likely_safe = [
            r'strn\w+\s*\([^,]+,[^,]+,\s*sizeof',
            r'fgets\s*\([^,]+,\s*sizeof',
            r'snprintf\s*\(',
            r'if\s*\([^)]*!=\s*NULL\)[^}]*free',
        ]
        
        self.empty_or_simple = [
            r'^\s*$',
            r'^\s*int\s+\w+\s*;\s*$',
            r'^\s*//.*$',
            r'^\s*/\*.*\*/\s*$' 
        ]
    
    def enhanced_analysis(self, code):
        """Enhanced analysis - PKL'deki method"""
        
        # Base prediction (simulated)
        base_score = 0.5
        
        # Expert rule adjustments
        adjusted_score = base_score
        reasoning = []
        
        code_lower = code.lower().strip()
        
        # Check if empty or very simple
        for pattern in self.empty_or_simple:
            if re.search(pattern, code_lower):
                adjusted_score = 0.1
                reasoning.append("Empty or trivial code")
                break
        
        # Check critical vulnerable patterns
        for pattern in self.critical_vulnerable:
            if re.search(pattern, code_lower):
                adjusted_score = max(adjusted_score, 0.85)
                reasoning.append("Critical vulnerable pattern")
        
        # Check likely safe patterns
        for pattern in self.likely_safe:
            if re.search(pattern, code_lower):
                adjusted_score = min(adjusted_score, 0.3)
                reasoning.append("Safe pattern detected")
        
        # Risk level determination
        if adjusted_score < 0.35:
            risk_level = "✅ GÜVENLİ"
            recommendation = "Güvenlik sorunu tespit edilmedi"
        elif adjusted_score < 0.55:
            risk_level = "🟢 DÜŞÜK RİSK"
            recommendation = "Genel olarak güvenli"
        elif adjusted_score < 0.75:
            risk_level = "🟡 ORTA RİSK"
            recommendation = "Dikkatli inceleme önerilir"
        elif adjusted_score < 0.85:
            risk_level = "🟠 YÜKSEK RİSK"
            recommendation = "Güvenlik kontrolü gerekli"
        else:
            risk_level = "🔴 KRİTİK RİSK"
            recommendation = "Derhal düzeltilmeli!"
        
        return {
            'enhanced_risk_score': adjusted_score,
            'risk_level': risk_level,
            'recommendation': recommendation,
            'is_vulnerable': adjusted_score >= 0.55,
            'confidence': min(0.95, abs(adjusted_score - 0.5) * 2 + 0.3),
            'reasoning': reasoning,
            'base_score': base_score
        }

class ConsistentSecurityAnalyzer:
    """Consistent Security Analyzer - PKL'deki ana class"""
    
    def __init__(self, base_scanner=None):  
        self.base_scanner = base_scanner
        
        # CWE patterns - eğitim sırasında kullanılan
        self.cwe_patterns = {
            'CWE-121': {
                'name': 'Stack-based Buffer Overflow',
                'dangerous_patterns': [
                    r'gets\s*\(',
                    r'strcpy\s*\([^,]+,\s*(?!\"[^\"]*\")[^)]*\)',
                    r'strcat\s*\([^,]+,\s*(?!\"[^\"]*\")[^)]*\)',
                    r'sprintf\s*\([^,]+,.*%s.*[^\"]\)',
                ],
                'safe_patterns': [
                    r'strn\w+\s*\([^,]+,[^,]+,\s*sizeof',
                    r'fgets\s*\([^,]+,\s*sizeof',
                    r'snprintf\s*\(',
                ],
                'severity': 'CRITICAL',
                'description': 'Buffer taşması riski'
            },
            'CWE-78': {
                'name': 'OS Command Injection',
                'dangerous_patterns': [
                    r'system\s*\([^)]*[a-zA-Z_]\w*[^")]*\)',
                    r'exec\w*\s*\([^)]*[a-zA-Z_]\w*[^")]*\)',
                    r'popen\s*\([^)]*[a-zA-Z_]\w*[^")]*\)',
                ],
                'safe_patterns': [
                    r'system\s*\(\s*\"[^\"]*\"\s*\)',
                ],
                'severity': 'HIGH',
                'description': 'İşletim sistemi komut enjeksiyonu'
            },
            'CWE-134': {
                'name': 'Uncontrolled Format String',
                'dangerous_patterns': [
                    r'printf\s*\(\s*[a-zA-Z_]\w*\s*\)',
                    r'fprintf\s*\([^,]+,\s*[a-zA-Z_]\w*\s*\)',
                ],
                'safe_patterns': [
                    r'printf\s*\(\s*\"[^\"]*\"\s*[\),]',
                ],
                'severity': 'HIGH',
                'description': 'Format string saldırısı'
            },
            'CWE-416': {
                'name': 'Use After Free',
                'dangerous_patterns': [
                    r'free\s*\([^)]+\)\s*;[^{}]*strcpy\s*\([^,]*\w+',
                    r'free\s*\([^)]+\)\s*;[^{}]*printf\s*\([^,]*\w+',
                    r'free\s*\([^)]+\)\s*;[^{}]*\w+',
                ],
                'safe_patterns': [],
                'severity': 'HIGH',
                'description': 'Serbest bırakılan belleğin kullanımı'
            },
            'CWE-401': {
                'name': 'Memory Leak',
                'dangerous_patterns': [
                    r'malloc\s*\([^)]+\)[^{}]*return\s*[^;]*;(?!.*free)',
                ],
                'safe_patterns': [
                    r'malloc\s*\([^)]+\).*free\s*\(',
                ],
                'severity': 'MEDIUM',
                'description': 'Bellek sızıntısı'
            }
        }
    
    def is_actually_vulnerable(self, code, cwe_id):
        """CWE vulnerability check"""
        cwe_info = self.cwe_patterns.get(cwe_id, {})
        dangerous_patterns = cwe_info.get('dangerous_patterns', [])
        safe_patterns = cwe_info.get('safe_patterns', [])
        
        # Safe pattern check
        for safe_pattern in safe_patterns:
            if re.search(safe_pattern, code, re.IGNORECASE):
                return False
        
        # Dangerous pattern check
        for dangerous_pattern in dangerous_patterns:
            if re.search(dangerous_pattern, code, re.IGNORECASE):
                return True
        
        return False
    
    def detect_real_vulnerabilities(self, code):
        """Real vulnerability detection"""
        real_vulnerabilities = []
        
        for cwe_id, cwe_info in self.cwe_patterns.items():
            if self.is_actually_vulnerable(code, cwe_id):
                dangerous_matches = 0
                for pattern in cwe_info['dangerous_patterns']:
                    if re.search(pattern, code, re.IGNORECASE):
                        dangerous_matches += 1
                
                confidence = dangerous_matches / len(cwe_info['dangerous_patterns']) if cwe_info['dangerous_patterns'] else 0
                
                real_vulnerabilities.append({
                    'cwe_id': cwe_id,
                    'name': cwe_info['name'],
                    'severity': cwe_info['severity'],
                    'description': cwe_info['description'],
                    'confidence': confidence,
                    'is_real_vulnerability': True
                })
        
        # Sort by severity
        severity_order = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
        real_vulnerabilities.sort(key=lambda x: (severity_order.get(x['severity'], 0), x['confidence']), reverse=True)
        
        return real_vulnerabilities
    
    def calculate_consistent_risk_score(self, base_score, vulnerabilities):
        """Consistent risk score calculation"""
        if not vulnerabilities:
            return min(base_score, 0.4)
        
        max_severity = vulnerabilities[0]['severity']
        
        if max_severity == 'CRITICAL':
            min_score = 0.80
        elif max_severity == 'HIGH':
            min_score = 0.65
        elif max_severity == 'MEDIUM':
            min_score = 0.45
        else:
            min_score = 0.25
        
        adjusted_score = max(base_score, min_score)
        
        if len(vulnerabilities) > 1:
            adjusted_score = min(1.0, adjusted_score + 0.1)
        
        return adjusted_score
    
    def get_consistent_risk_level(self, score, has_vulnerabilities):
        """Risk level determination"""
        if not has_vulnerabilities:
            if score < 0.3:
                return "✅ GÜVENLİ", "Güvenlik sorunu tespit edilmedi"
            else:
                return "🟢 DÜŞÜK RİSK", "Genel olarak güvenli"
        
        if score >= 0.85:
            return "🔴 KRİTİK RİSK", "Derhal düzeltilmeli!"
        elif score >= 0.65:
            return "🟠 YÜKSEK RİSK", "Güvenlik incelemesi gerekli"
        elif score >= 0.45:
            return "🟡 ORTA RİSK", "Dikkatli inceleme gerekli"
        else:
            return "🟢 DÜŞÜK RİSK", "Genel olarak güvenli ama dikkat gerekli"
    
    def consistent_analysis(self, code):
        """Main consistent analysis method - PKL'deki ana method"""
        
        # Base enhanced analysis (simulated)
        base_result = {'enhanced_risk_score': 0.5, 'reasoning': []}
        base_score = base_result['enhanced_risk_score']
        
        # Real vulnerability detection
        real_vulnerabilities = self.detect_real_vulnerabilities(code)
        
        # Consistent risk score
        consistent_score = self.calculate_consistent_risk_score(base_score, real_vulnerabilities)
        
        # Risk level
        has_vulns = len(real_vulnerabilities) > 0
        risk_level, recommendation = self.get_consistent_risk_level(consistent_score, has_vulns)
        
        return {
            'risk_score': consistent_score,
            'risk_level': risk_level,
            'recommendation': recommendation,
            'is_vulnerable': has_vulns,
            'confidence': max([v['confidence'] for v in real_vulnerabilities]) if real_vulnerabilities else 0.0,
            'detected_vulnerabilities': real_vulnerabilities,
            'primary_vulnerability': real_vulnerabilities[0] if real_vulnerabilities else None,
            'vulnerability_count': len(real_vulnerabilities),
            'max_severity': real_vulnerabilities[0]['severity'] if real_vulnerabilities else 'NONE',
            'base_score': base_score,
            'base_reasoning': base_result.get('reasoning', []),
            'logic_consistent': True
        }

# ======================== TRAINED MODEL LOADER ========================

class TrainedModelLoader:
    """Eğitilmiş modeli yükleyen class"""
    
    def __init__(self, model_path: str):  
        self.model_path = model_path
        self.model = None
        self.model_type = None
        self.load_success = False
        
        self.load_model()
    
    def load_model(self):
        """Model'i yükle"""
        try:
            print(f"📦 Model yükleniyor: {self.model_path}")
            
            with open(self.model_path, 'rb') as f:
                self.model = pickle.load(f)
            
            # Model tipini belirle
            if hasattr(self.model, 'consistent_analysis'):
                self.model_type = "ConsistentSecurityAnalyzer"
                print("✅ Consistent Security Analyzer modeli yüklendi")
            elif hasattr(self.model, 'enhanced_analysis'):
                self.model_type = "SimpleEnhancedScanner"
                print("✅ Enhanced Scanner modeli yüklendi")
            else:
                self.model_type = "Unknown"
                print("⚠️ Bilinmeyen model tipi")
            
            self.load_success = True
            print(f"🎯 Model tipi: {self.model_type}")
            
        except Exception as e:
            print(f"❌ Model yükleme hatası: {e}")
            self.load_success = False
            self.model = None
    
    def analyze(self, code: str) -> Dict[str, Any]:
        """Model ile analiz yap"""
        
        if not self.load_success or not self.model:
            return {
                'error': 'Model yüklenemedi',
                'success': False
            }
        
        try:
            if self.model_type == "ConsistentSecurityAnalyzer":
                result = self.model.consistent_analysis(code)
            elif self.model_type == "SimpleEnhancedScanner":
                result = self.model.enhanced_analysis(code)
            else:
                return {
                    'error': 'Desteklenmeyen model tipi',
                    'success': False
                }
            
            # Standard format'a çevir
            return {
                'success': True,
                'model_type': self.model_type,
                'safe': not result.get('is_vulnerable', False),
                'risk_level': result.get('risk_level', 'UNKNOWN'),
                'risk_score': result.get('risk_score', result.get('enhanced_risk_score', 0.5)),
                'vulnerabilities': result.get('detected_vulnerabilities', []),
                'vulnerability_count': result.get('vulnerability_count', 0),
                'confidence': result.get('confidence', 0.0),
                'recommendation': result.get('recommendation', 'Analiz tamamlandı'),
                'max_severity': result.get('max_severity', 'NONE'),
                'raw_result': result  # Debug için
            }
            
        except Exception as e:
            return {
                'error': f'Analiz hatası: {str(e)}',
                'success': False
            }
    
    def get_model_info(self) -> Dict[str, Any]:
        """Model bilgilerini getir"""
        return {
            'model_path': self.model_path,
            'model_type': self.model_type,
            'load_success': self.load_success,
            'available_methods': [method for method in dir(self.model) if not method.startswith('_')] if self.model else []
        }

# ======================== KULLANIM FONKSİYONLARI ========================

def load_trained_model(model_path: str) -> TrainedModelLoader:
    """Eğitilmiş modeli yükle"""
    return TrainedModelLoader(model_path)

def analyze_with_trained_model(model_path: str, code: str) -> Dict[str, Any]:
    """Tek seferlik analiz"""
    loader = TrainedModelLoader(model_path)
    return loader.analyze(code)

def create_analyzer_from_model(model_path: str):
    """Model'den analyzer oluştur"""
    
    class ModelAnalyzer:
        def __init__(self, model_path):  # ✅ DÜZELTME: _init_ → __init__
            self.loader = TrainedModelLoader(model_path)
        
        def analyze(self, code):
            return self.loader.analyze(code)
        
        def quick_check(self, code):
            result = self.loader.analyze(code)
            if not result['success']:
                return result
            
            return {
                'safe': result['safe'],
                'risk': result['risk_level'],
                'score': result['risk_score'],
                'issues': [v.get('cwe_id', v.get('name', 'Unknown')) for v in result['vulnerabilities']],
                'message': result['recommendation']
            }
        
        def batch_analyze(self, code_list):
            results = []
            for i, code in enumerate(code_list):
                result = self.analyze(code)
                result['index'] = i
                results.append(result)
            return results
        
        def get_info(self):
            return self.loader.get_model_info()
    
    return ModelAnalyzer(model_path)

# ======================== TEST FONKSİYONU ========================

def test_trained_model(model_path: str):
    """Trained model'i test et"""
    
    print("🧪 TRAINED MODEL TEST")
    print("="*50)
    
    loader = TrainedModelLoader(model_path)
    
    if not loader.load_success:
        print("❌ Model yüklenemedi, test iptal edildi")
        return
    
    # Test kodları
    test_cases = [
        "gets(buffer);",
        "system(user_input);",
        "printf(user_data);",
        "fgets(buf, sizeof(buf), stdin);",
        "int x = 5;",
        "free(ptr); strcpy(ptr, \"hello\");"
    ]
    
    print(f"\n📊 Model Bilgileri:")
    info = loader.get_model_info()
    for key, value in info.items():
        print(f"   {key}: {value}")
    
    print(f"\n🔍 Test Sonuçları:")
    print("-" * 60)
    
    for i, code in enumerate(test_cases, 1):
        result = loader.analyze(code)
        
        print(f"\n{i}. {code}")
        if result['success']:
            print(f"   Risk: {result['risk_level']} (Score: {result['risk_score']:.3f})")
            print(f"   Safe: {'✅' if result['safe'] else '❌'}")
            print(f"   Vulnerabilities: {result['vulnerability_count']}")
            if result['vulnerabilities']:
                cwes = [v.get('cwe_id', 'Unknown') for v in result['vulnerabilities']]
                print(f"   CWE: {', '.join(cwes)}")
        else:
            print(f"   ❌ Error: {result['error']}")
    
    print(f"\n✅ Test tamamlandı!")

# ======================== MAIN ========================

if __name__ == "__main__":  
    import sys
    
    if len(sys.argv) < 2:
        print("Kullanım: python trained_model_loader.py <model_path>")
        print("Örnek: python trained_model_loader.py consistent_security_analyzer.pkl")
        sys.exit(1)
    
    model_path = sys.argv[1]
    test_trained_model(model_path)