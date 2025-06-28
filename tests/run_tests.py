# tests/run_tests.py
"""
Basit test çalıştırıcı
Tüm testleri çalıştırır ve sonuçları gösterir
"""

import subprocess
import sys
import time

def check_requirements():
    """Gerekli paketler yüklü mü kontrol et"""
    try:
        import requests
        print("✅ requests modülü hazır")
        return True
    except ImportError:
        print("❌ requests modülü eksik")
        print("   Yüklemek için: pip install requests")
        return False

def run_system_test():
    """Sistem testini çalıştır"""
    print("🚀 Sistem testi başlatılıyor...\n")
    import os
    try:
        # Python ile test dosyasını çalıştır
        test_file = os.path.join(os.path.dirname(__file__), "test_system_health.py")
        result = subprocess.run([
            sys.executable, test_file
        ], capture_output=True, text=True, timeout=60)
        
        print(result.stdout)
        
        if result.stderr:
            print("⚠️ Uyarılar:")
            print(result.stderr)
        
        if result.returncode == 0:
            print("\n🎉 Tüm testler başarılı!")
            return True
        else:
            print(f"\n❌ Test hatası (exit code: {result.returncode})")
            return False
            
    except subprocess.TimeoutExpired:
        print("❌ Test timeout (60 saniye)")
        return False
    except Exception as e:
        print(f"❌ Test çalıştırma hatası: {e}")
        return False

def main():
    print("🧪 LLMCode Test Suite")
    print("=" * 50)
    
    # 1. Requirements check
    if not check_requirements():
        print("\n💡 Eksik paketleri yükleyip tekrar deneyin")
        return
    
    print("\n" + "=" * 50)
    
    # 2. Run tests
    success = run_system_test()
    
    print("\n" + "=" * 50)
    
    if success:
        print("✅ SONUÇ: Sistem tamamen çalışıyor!")
    else:
        print("❌ SONUÇ: Sistemde sorunlar var")
        print("💡 Backend'in çalıştığından emin olun: python src/backend/app.py")

if __name__ == "__main__":
    main()