from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import re
import logging
from datetime import datetime
from dotenv import load_dotenv


load_dotenv()
app = Flask(__name__)
CORS(app)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

from openai import OpenAI

class AICodeGenerator:
    def __init__(self, api_key=None):
        api_key = api_key or os.getenv('OPENAI_API_KEY')
        if not api_key:
            raise ValueError("OpenAI API key bulunamadı!")
        self.client = OpenAI(api_key=api_key)
        
        self.language_configs = {
            'c': {'extension': '.c', 'description': 'C programlama dili', 'example_includes': '#include <stdio.h>\n#include <string.h>\n#include <stdlib.h>'},
            'cpp': {'extension': '.cpp', 'description': 'C++ programlama dili', 'example_includes': '#include <iostream>\n#include <string>\n#include <vector>'},
            'python': {'extension': '.py', 'description': 'Python programlama dili', 'example_includes': '# Python kodu'},
            'java': {'extension': '.java', 'description': 'Java programlama dili', 'example_includes': 'public class Main {'}
        }
    
    def generate_code(self, prompt, language='c'):
        try:
            lang_config = self.language_configs.get(language, self.language_configs['c'])
            
            system_prompt = f"""
Sen uzman bir {lang_config['description']} programcısısın. 
Kullanıcının isteğine göre {lang_config['description']} kodunu üret.

KURALLAR:
1. Sadece kod döndür, açıklama ekleme
2. Kod çalışabilir ve derlenebilir olmalı
3. Gerekli header/import'ları ekle
4. Kod temiz ve okunabilir olmalı
5. Güvenlik açıkları varsa kasıtlı olarak ekle (test amaçlı)

Kod formatı: Direkt kod döndür, markdown kod blokları kullanma.
            """
            
            enhanced_prompt = self._enhance_prompt(prompt, language)
            
            response = self.client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": enhanced_prompt}
                ],
                max_tokens=1500,
                temperature=0.7,
                top_p=0.9
            )
            
            generated_code = response.choices[0].message.content.strip()
            generated_code = self._clean_generated_code(generated_code)
            
            logger.info(f"Kod başarıyla üretildi - Dil: {language}, Uzunluk: {len(generated_code)}")
            return generated_code
            
        except Exception as e:
            error_msg = str(e)
            if "authentication" in error_msg.lower():
                raise Exception("OpenAI API key geçersiz")
            elif "rate_limit" in error_msg.lower():
                raise Exception("API rate limit aşıldı")
            elif "billing" in error_msg.lower():
                raise Exception("API faturalama sorunu")
            else:
                raise Exception(f"Kod üretilemedi: {error_msg}")
    
    def _enhance_prompt(self, prompt, language):
        enhanced = prompt
        turkish_keywords = ['fonksiyon', 'değişken', 'dizi', 'döngü', 'koşul', 'yaz', 'oluştur']
        if any(keyword in prompt.lower() for keyword in turkish_keywords):
            enhanced = f"Türkçe açıklama: {prompt}\n\nİngilizce: Create a {language} program that implements: {prompt}"
        
        if any(word in prompt.lower() for word in ['güvenlik', 'açık', 'zafiyet', 'vulnerability', 'exploit']):
            enhanced += f"\n\nNOTE: Create code with intentional security vulnerabilities for educational/testing purposes."
        
        if language == 'c':
            enhanced += f"\n\nUse C language with standard library functions. Include necessary headers."
        elif language == 'cpp':
            enhanced += f"\n\nUse modern C++ features. Include STL where appropriate."
        elif language == 'python':
            enhanced += f"\n\nUse Python 3 syntax. Keep it simple and readable."
        elif language == 'java':
            enhanced += f"\n\nUse Java with proper class structure and main method."
        
        return enhanced
    
    def _clean_generated_code(self, code):
        code = re.sub(r'```\w*\n?', '', code)
        code = re.sub(r'```', '', code)
        
        lines = code.split('\n')
        cleaned_lines = []
        
        for line in lines:
            if line.strip().startswith('Açıklama:') or line.strip().startswith('Explanation:'):
                continue
            if 'Bu kod' in line and '//' not in line and '#' not in line:
                continue
            cleaned_lines.append(line)
        
        return '\n'.join(cleaned_lines).strip()
    
    def test_api_connection(self):
        try:
            response = self.client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[{"role": "user", "content": "Test message - just say 'OK'"}],
                max_tokens=10
            )
            return True, "API bağlantısı başarılı"
        except Exception as e:
            return False, f"API bağlantı hatası: {str(e)}"

# ======================== TRAINED MODEL SECURITY ANALYZER ========================

from trained_model_loader import TrainedModelLoader

class TrainedModelSecurityAnalyzer:
    def __init__(self, model_path='models'):
        self.model_path = model_path
        self.pkl_file_path = os.path.join(model_path, 'consistent_security_analyzer.pkl')
        self.model_loader = None
        self.model_loaded = False
        
        self._load_trained_model()
    
    def _load_trained_model(self):
        try:
            if os.path.exists(self.pkl_file_path):
                logger.info(f"📦 Trained Model yükleniyor: {self.pkl_file_path}")
                
                self.model_loader = TrainedModelLoader(self.pkl_file_path)
                
                if self.model_loader.load_success:
                    self.model_loaded = True
                    logger.info("✅ Trained Model başarıyla yüklendi")
                    
                    model_info = self.model_loader.get_model_info()
                    logger.info(f"   Model tipi: {model_info.get('model_type', 'Unknown')}")
                    logger.info(f"   Available methods: {len(model_info.get('available_methods', []))}")
                else:
                    logger.error("❌ Trained Model yükleme başarısız")
                    raise Exception("Model yükleme başarısız")
            else:
                logger.error(f"❌ PKL dosyası bulunamadı: {self.pkl_file_path}")
                raise Exception(f"PKL dosyası bulunamadı: {self.pkl_file_path}")
                
        except Exception as e:
            logger.error(f"❌ Trained Model yükleme hatası: {str(e)}")
            self.model_loaded = False
            raise Exception(f"Trained model yüklenemedi: {str(e)}")
    
    def analyze_vulnerability(self, source_code: str):
        if not self.model_loaded or not self.model_loader:
            raise Exception("Trained model yüklü değil!")
        
        try:
            logger.info("🧠 Trained Model ile analiz yapılıyor...")
            
            result = self.model_loader.analyze(source_code)
            
            if not result.get('success', False):
                raise Exception(f"Model analiz hatası: {result.get('error', 'Unknown error')}")
            
            logger.info("✅ Trained Model analizi başarılı")
            return self._convert_to_backend_format(result, source_code)
                
        except Exception as e:
            logger.error(f"❌ Trained Model analiz hatası: {str(e)}")
            raise Exception(f"Analiz başarısız: {str(e)}")
    
    def _convert_to_backend_format(self, trained_result, source_code):
        cwe_analysis = {
            'CWE-120': {'probability': 0.1, 'vulnerable': False},
            'CWE-119': {'probability': 0.1, 'vulnerable': False},
            'CWE-469': {'probability': 0.1, 'vulnerable': False},
            'CWE-476': {'probability': 0.1, 'vulnerable': False},
            'CWE-other': {'probability': 0.1, 'vulnerable': False}
        }
        
        for vuln in trained_result.get('vulnerabilities', []):
            cwe_id = vuln.get('cwe_id', 'CWE-other')
            confidence = vuln.get('confidence', 0.8)
            
            if cwe_id == 'CWE-121':
                backend_cwe = 'CWE-120'
            elif cwe_id == 'CWE-416':
                backend_cwe = 'CWE-476'
            elif cwe_id in ['CWE-78', 'CWE-134', 'CWE-401']:
                backend_cwe = 'CWE-other'
            else:
                backend_cwe = 'CWE-other'
            
            cwe_analysis[backend_cwe] = {
                'probability': confidence,
                'vulnerable': True
            }
        
        backend_risk_level = self._map_risk_level(trained_result.get('risk_level', 'UNKNOWN'))
        
        return {
            'overall_vulnerability_score': trained_result.get('risk_score', 0.5),
            'is_vulnerable': not trained_result.get('safe', True),
            'risk_level': backend_risk_level,
            'cwe_analysis': cwe_analysis,
            'analysis_method': 'Trained_Model_Direct',
            'model_type': trained_result.get('model_type', 'ConsistentSecurityAnalyzer'),
            'trained_model_result': trained_result
        }
    
    def _map_risk_level(self, trained_risk_level):
        risk_str = str(trained_risk_level).upper()
        
        if 'KRİTİK' in risk_str or 'CRITICAL' in risk_str or '🔴' in trained_risk_level:
            return 'CRITICAL'
        elif 'YÜKSEK' in risk_str or 'HIGH' in risk_str or '🟠' in trained_risk_level:
            return 'HIGH'
        elif 'ORTA' in risk_str or 'MEDIUM' in risk_str or '🟡' in trained_risk_level:
            return 'MEDIUM'
        elif 'DÜŞÜK' in risk_str or 'LOW' in risk_str or '🟢' in trained_risk_level:
            return 'LOW'
        else:
            return 'LOW'
    
    def get_model_info(self):
        base_info = {
            'model_loaded': self.model_loaded,
            'model_path': self.model_path,
            'pkl_file_path': self.pkl_file_path,
            'pkl_file_exists': os.path.exists(self.pkl_file_path),
            'analysis_method': 'Trained_Model_Direct' if self.model_loaded else 'Failed'
        }
        
        if self.model_loaded and self.model_loader:
            trained_info = self.model_loader.get_model_info()
            base_info.update({
                'model_type': trained_info.get('model_type', 'Unknown'),
                'available_methods': trained_info.get('available_methods', []),
                'load_success': trained_info.get('load_success', False)
            })
        else:
            base_info.update({
                'model_type': 'Failed',
                'available_methods': [],
                'load_success': False
            })
        
        return base_info

class ReportGenerator:
    @staticmethod
    def generate_security_report(code, analysis_result, prompt):
        recommendations = ReportGenerator.get_recommendations(analysis_result)
        summary = ReportGenerator.create_summary(analysis_result)
        
        return {
            'analysis_timestamp': datetime.now().isoformat(),
            'original_prompt': prompt,
            'generated_code': code,
            'security_analysis': analysis_result,
            'recommendations': recommendations,
            'summary': summary
        }
    
    @staticmethod
    def get_recommendations(analysis):
        recommendations = []
        
        for cwe, details in analysis['cwe_analysis'].items():
            if details['vulnerable']:
                if cwe == 'CWE-120':
                    recommendations.append({
                        'type': cwe,
                        'severity': 'HIGH',
                        'description': 'Buffer overflow riski tespit edildi',
                        'solution': 'Buffer boyutlarını kontrol edin, güvenli string fonksiyonları kullanın (strncpy, snprintf)'
                    })
                elif cwe == 'CWE-119':
                    recommendations.append({
                        'type': cwe,
                        'severity': 'HIGH', 
                        'description': 'Buffer boundary hatası riski',
                        'solution': 'Array sınırlarını kontrol edin, bounds checking uygulayın'
                    })
                elif cwe == 'CWE-476':
                    recommendations.append({
                        'type': cwe,
                        'severity': 'MEDIUM',
                        'description': 'NULL pointer dereference riski',
                        'solution': 'Pointer\'ları kullanmadan önce NULL kontrolü yapın'
                    })
                elif cwe == 'CWE-other':
                    recommendations.append({
                        'type': cwe,
                        'severity': 'HIGH',
                        'description': 'Güvenlik açığı tespit edildi',
                        'solution': 'Kodunuzu güvenlik açıkları için gözden geçirin'
                    })
        
        return recommendations
    
    @staticmethod
    def create_summary(analysis):
        total_vulnerabilities = sum(1 for cwe in analysis['cwe_analysis'].values() if cwe['vulnerable'])
        
        return {
            'total_vulnerabilities_found': total_vulnerabilities,
            'overall_risk_level': analysis['risk_level'],
            'vulnerability_score': analysis['overall_vulnerability_score'],
            'status': 'VULNERABLE' if analysis['is_vulnerable'] else 'SECURE'
        }

# ======================== GLOBAL NESNELER ========================

try:
    code_generator = AICodeGenerator()
    logger.info("✅ OpenAI API bağlantısı kuruldu")
    
    success, message = code_generator.test_api_connection()
    if success:
        logger.info("✅ OpenAI API test başarılı")
    else:
        logger.warning(f"⚠️ OpenAI API test hatası: {message}")
        
except Exception as e:
    logger.error(f"❌ OpenAI API başlatılamadı: {str(e)}")
    logger.info("🔄 MockCodeGenerator kullanılacak...")
    
    class MockCodeGenerator:
        def generate_code(self, prompt, language='c'):
            return f"// OpenAI API kullanılamıyor\n// Mock kod: {prompt}\nint main() {{ return 0; }}"
    
    code_generator = MockCodeGenerator()

try:
    security_analyzer = TrainedModelSecurityAnalyzer(model_path='models')
    model_info = security_analyzer.get_model_info()
    
    if model_info['model_loaded']:
        logger.info("✅ Trained Model güvenlik analizi aktif")
        logger.info(f"   - Model tipi: {model_info.get('model_type', 'Unknown')}")
        logger.info(f"   - Analiz metodu: {model_info['analysis_method']}")
        logger.info(f"   - PKL dosyası: {model_info.get('pkl_file_exists', False)}")
    else:
        logger.error("❌ Trained Model yüklenemedi!")
        raise Exception("Trained model gerekli ama yüklenemedi")
        
except Exception as e:
    logger.error(f"❌ Trained Model başlatılamadı: {str(e)}")
    logger.error("❌ UYGULAMA BAŞLATILMIYOR - Trained model gerekli!")
    exit(1)

# ======================== API ENDPOINTS ========================

@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'version': '2.0.0',
        'analysis_engine': 'Trained_Model_Only'
    })

@app.route('/api/analyze', methods=['POST'])
def analyze_code():
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'JSON verisi gerekli'}), 400
        
        prompt = data.get('prompt', '').strip()
        language = data.get('language', 'c').lower()
        
        if not prompt:
            return jsonify({'error': 'Prompt gerekli'}), 400
        
        if language not in ['c', 'cpp', 'python', 'java']:
            return jsonify({'error': 'Desteklenmeyen programlama dili'}), 400
        
        logger.info(f"🚀 Trained Model analizi başlatılıyor - Prompt: {prompt[:50]}...")
        
        generated_code = code_generator.generate_code(prompt, language)
        
        if not generated_code:
            return jsonify({'error': 'Kod üretilemedi'}), 500
        
        analysis_result = security_analyzer.analyze_vulnerability(generated_code)
        
        report = ReportGenerator.generate_security_report(
            generated_code, analysis_result, prompt
        )
        
        logger.info("✅ Trained Model analizi tamamlandı başarıyla")
        
        return jsonify({
            'success': True,
            'report': report,
            'analysis_engine': 'Trained_Model_Direct'
        })
        
    except Exception as e:
        logger.error(f"❌ Trained Model analiz hatası: {str(e)}")
        return jsonify({
            'error': 'Trained model analizi sırasında hata oluştu',
            'details': str(e) if app.debug else None,
            'analysis_engine': 'Trained_Model_Direct'
        }), 500
    
@app.route('/api/test-openai', methods=['GET'])
def test_openai():
   try:
       if hasattr(code_generator, 'test_api_connection'):
           openai_success, openai_message = code_generator.test_api_connection()
       else:
           openai_success, openai_message = False, 'Mock generator kullanılıyor'
       
       model_info = security_analyzer.get_model_info()
       
       return jsonify({
           'openai': {
               'success': openai_success,
               'message': openai_message,
               'api_configured': bool(os.getenv('OPENAI_API_KEY'))
           },
           'trained_model': {
               'loaded': model_info['model_loaded'],
               'type': model_info.get('model_type', 'Unknown'),
               'analysis_method': model_info.get('analysis_method', 'Unknown'),
               'pkl_exists': model_info.get('pkl_file_exists', False),
               'methods': model_info.get('available_methods', [])
           },
           'system': {
               'analysis_engine': 'Trained_Model_Only',
               'version': '2.0.0'
           }
       })
   except Exception as e:
       return jsonify({
           'error': f'Test hatası: {str(e)}',
           'analysis_engine': 'Trained_Model_Direct'
       })

@app.route('/api/generate-code', methods=['POST'])
def generate_code_only():
   try:
       data = request.get_json()
       prompt = data.get('prompt', '').strip()
       language = data.get('language', 'c').lower()
       
       if not prompt:
           return jsonify({'error': 'Prompt gerekli'}), 400
       
       generated_code = code_generator.generate_code(prompt, language)
       
       return jsonify({
           'success': True,
           'code': generated_code,
           'language': language,
           'prompt': prompt
       })
       
   except Exception as e:
       logger.error(f"Kod üretim hatası: {str(e)}")
       return jsonify({'error': 'Kod üretilemedi'}), 500

@app.route('/api/analyze-existing', methods=['POST'])
def analyze_existing_code():
   try:
       data = request.get_json()
       source_code = data.get('code', '').strip()
       
       if not source_code:
           return jsonify({'error': 'Kaynak kod gerekli'}), 400
       
       logger.info("🧠 Mevcut kod için Trained Model analizi başlatılıyor...")
       
       analysis_result = security_analyzer.analyze_vulnerability(source_code)
       
       report = ReportGenerator.generate_security_report(
           source_code, analysis_result, "Mevcut kod analizi"
       )
       
       logger.info("✅ Mevcut kod Trained Model analizi tamamlandı")
       
       return jsonify({
           'success': True,
           'report': report,
           'analysis_engine': 'Trained_Model_Direct'
       })
       
   except Exception as e:
       logger.error(f"❌ Mevcut kod analizi hatası: {str(e)}")
       return jsonify({
           'error': 'Trained model analizi sırasında hata oluştu',
           'details': str(e) if app.debug else None,
           'analysis_engine': 'Trained_Model_Direct'
       }), 500

@app.route('/api/model-info', methods=['GET'])
def model_info():
   try:
       info = security_analyzer.get_model_info()
       return jsonify({
           'success': True,
           'model_info': info,
           'analysis_engine': 'Trained_Model_Direct'
       })
   except Exception as e:
       return jsonify({
           'success': False,
           'error': str(e),
           'analysis_engine': 'Trained_Model_Direct'
       })

@app.errorhandler(404)
def not_found(error):
   return jsonify({
       'error': 'Endpoint bulunamadı',
       'analysis_engine': 'Trained_Model_Direct'
   }), 404

@app.errorhandler(500)
def internal_error(error):
   return jsonify({
       'error': 'Sunucu hatası',
       'analysis_engine': 'Trained_Model_Direct'
   }), 500

if __name__ == '__main__':
   debug_mode = os.getenv('FLASK_DEBUG', 'True').lower() == 'true'
   port = int(os.getenv('PORT', 5000))
   
   logger.info(f"🚀 Trained Model Backend başlatılıyor...")
   logger.info(f"   Port: {port}")
   logger.info(f"   Debug: {debug_mode}")
   logger.info(f"   Analysis Engine: Trained_Model_Only")
   
   app.run(
       debug=debug_mode,
       host='0.0.0.0',
       port=port
   )