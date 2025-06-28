import { useState } from 'react';

const SecurityAnalyzer = () => {
  const [prompt, setPrompt] = useState('');
  const [language, setLanguage] = useState('c');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');

  const languages = [
    { value: 'c', label: 'C', icon: '🔧', color: '#00599C' },
    { value: 'cpp', label: 'C++', icon: '⚡', color: '#659ad2' },
    { value: 'python', label: 'Python', icon: '🐍', color: '#3776ab' },
    { value: 'java', label: 'Java', icon: '☕', color: '#f89820' }
  ];

  const severityConfig = {
    'CRITICAL': { 
      bg: 'linear-gradient(135deg, #ef4444, #dc2626)', 
      text: 'white', 
      icon: '🔴',
      shadow: '0 4px 14px 0 rgba(239, 68, 68, 0.4)'
    },
    'HIGH': { 
      bg: 'linear-gradient(135deg, #f97316, #ea580c)', 
      text: 'white', 
      icon: '🟠',
      shadow: '0 4px 14px 0 rgba(249, 115, 22, 0.4)'
    },
    'MEDIUM': { 
      bg: 'linear-gradient(135deg, #f59e0b, #d97706)', 
      text: 'white', 
      icon: '🟡',
      shadow: '0 4px 14px 0 rgba(245, 158, 11, 0.4)'
    },
    'LOW': { 
      bg: 'linear-gradient(135deg, #10b981, #059669)', 
      text: 'white', 
      icon: '🟢',
      shadow: '0 4px 14px 0 rgba(16, 185, 129, 0.4)'
    }
  };

  const analyzeCode = async () => {
    if (!prompt.trim()) {
      setError('Lütfen bir prompt giriniz');
      return;
    }

    setLoading(true);
    setError('');
    setResult(null);

    try {
      const response = await fetch('http://localhost:5000/api/analyze', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          prompt: prompt.trim(),
          language: language
        })
      });

      const data = await response.json();

      if (response.ok && data.success) {
        setResult(data.report);
      } else {
        setError(data.error || 'Analiz sırasında hata oluştu');
      }
    } catch (err) {
      setError('Sunucuya bağlanılamıyor. Flask uygulamasının çalıştığından emin olun.');
    } finally {
      setLoading(false);
    }
  };

  const formatCode = (code) => {
    return code.split('\n').map((line, index) => (
      <div key={index} style={{ 
        display: 'flex',
        minHeight: '20px',
        lineHeight: '20px'
      }}>
        <span style={{ 
          minWidth: '35px', 
          color: '#64748b', 
          fontSize: '12px',
          paddingRight: '12px',
          textAlign: 'right',
          userSelect: 'none',
          borderRight: '1px solid #334155',
          marginRight: '12px'
        }}>
          {index + 1}
        </span>
        <span style={{ flex: 1 }}>{line}</span>
      </div>
    ));
  };

  const getSeverityLevel = (level) => {
    if (level.includes('KRİTİK') || level === 'CRITICAL') return 'CRITICAL';
    if (level.includes('YÜKSEK') || level === 'HIGH') return 'HIGH';
    if (level.includes('ORTA') || level === 'MEDIUM') return 'MEDIUM';
    return 'LOW';
  };

  const formatTimestamp = (timestamp) => {
    return new Date(timestamp).toLocaleString('tr-TR', {
      year: 'numeric',
      month: 'long',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit'
    });
  };

  // Backend'den gelen doğru veri yapısını kontrol et
  const getAnalysisData = () => {
    if (!result?.security_analysis) return null;
    
    const analysis = result.security_analysis;
    
    return {
      riskLevel: analysis.risk_level || 'LOW',
      overallScore: analysis.overall_vulnerability_score || 0,
      isVulnerable: analysis.is_vulnerable || false,
      analysisMethod: analysis.analysis_method || 'Unknown',
      modelType: analysis.model_type || 'Unknown',
      detectedCweCount: analysis.detected_cwe_count || 0,
      mlModelCount: analysis.ml_model_count || 0,
      ensembleProbability: analysis.ensemble_probability || 0,
      cweAnalysis: analysis.cwe_analysis || {},
      vulnerabilities: analysis.production_ml_result?.vulnerabilities || [],
      primaryVuln: analysis.production_ml_result?.vulnerabilities?.[0] || null
    };
  };

  const analysisData = getAnalysisData();

  return (
    <div style={{ 
      minHeight: '100vh', 
      background: 'linear-gradient(135deg, #1e293b 0%, #334155 50%, #475569 100%)',
      fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif',
      color: '#f8fafc'
    }}>
      {/* Header */}
      <div style={{ 
        background: 'rgba(255, 255, 255, 0.1)',
        backdropFilter: 'blur(10px)',
        borderBottom: '1px solid rgba(255, 255, 255, 0.1)',
        padding: '24px 0'
      }}>
        <div style={{ 
          maxWidth: '1400px',
          margin: '0 auto',
          padding: '0 24px',
          textAlign: 'center'
        }}>
          <h1 style={{ 
            fontSize: '3rem', 
            fontWeight: '800', 
            margin: '0 0 8px 0',
            background: 'linear-gradient(135deg, #60a5fa, #34d399)',
            WebkitBackgroundClip: 'text',
            WebkitTextFillColor: 'transparent',
            textShadow: 'none'
          }}>
            🛡️ AI Security Code Analyzer
          </h1>
          <p style={{ 
            fontSize: '1.2rem', 
            opacity: 0.8,
            margin: 0,
            fontWeight: '400'
          }}>
            AI destekli güvenlik açığı tespit sistemi
          </p>
        </div>
      </div>

      {/* Main Content */}
      <div style={{ 
        maxWidth: '1400px', 
        margin: '0 auto',
        padding: '40px 24px',
        display: 'grid',
        gridTemplateColumns: result ? '400px 1fr' : '1fr',
        gap: '40px',
        minHeight: 'calc(100vh - 200px)'
      }}>
        
        {/* Input Panel */}
        <div style={{ 
          background: 'rgba(255, 255, 255, 0.95)', 
          borderRadius: '24px',
          padding: '32px',
          backdropFilter: 'blur(20px)',
          border: '1px solid rgba(255, 255, 255, 0.2)',
          boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.25)',
          color: '#1e293b',
          height: 'fit-content',
          position: 'sticky',
          top: '40px'
        }}>
          <div style={{ 
            display: 'flex', 
            alignItems: 'center', 
            gap: '12px',
            marginBottom: '24px'
          }}>
            <div style={{
              width: '40px',
              height: '40px',
              background: 'linear-gradient(135deg, #60a5fa, #34d399)',
              borderRadius: '12px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              fontSize: '18px'
            }}>
              💻
            </div>
            <h2 style={{ 
              fontSize: '1.5rem', 
              fontWeight: '700', 
              margin: 0,
              color: '#1e293b'
            }}>
              Kod Üretici
            </h2>
          </div>

          {/* Language Selection */}
          <div style={{ marginBottom: '24px' }}>
            <label style={{ 
              display: 'block', 
              marginBottom: '12px', 
              fontWeight: '600',
              color: '#374151',
              fontSize: '14px'
            }}>
              Programlama Dili
            </label>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px' }}>
              {languages.map((lang) => (
                <button
                  key={lang.value}
                  onClick={() => setLanguage(lang.value)}
                  style={{
                    padding: '12px 16px',
                    borderRadius: '12px',
                    border: '2px solid',
                    borderColor: language === lang.value ? lang.color : '#e2e8f0',
                    background: language === lang.value ? lang.color : 'white',
                    color: language === lang.value ? 'white' : '#475569',
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    gap: '8px',
                    fontWeight: '600',
                    fontSize: '13px',
                    transition: 'all 0.2s ease',
                    boxShadow: language === lang.value ? `0 4px 12px ${lang.color}40` : 'none'
                  }}
                >
                  <span style={{ fontSize: '16px' }}>{lang.icon}</span>
                  {lang.label}
                </button>
              ))}
            </div>
          </div>

          {/* Prompt Input */}
          <div style={{ marginBottom: '24px' }}>
            <label style={{ 
              display: 'block', 
              marginBottom: '12px', 
              fontWeight: '600',
              color: '#374151',
              fontSize: '14px'
            }}>
              Güvenlik Açığı Prompt'u
            </label>
            <textarea
              value={prompt}
              onChange={(e) => setPrompt(e.target.value)}
              placeholder="Örnek: buffer overflow açığı olan bir C kodu yaz&#10;Örnek: SQL injection zafiyeti olan Python kodu&#10;Örnek: command injection riski olan Java kodu"
              style={{
                width: '100%',
                height: '140px',
                padding: '16px',
                border: '2px solid #e2e8f0',
                borderRadius: '12px',
                fontSize: '14px',
                fontFamily: 'inherit',
                resize: 'vertical',
                outline: 'none',
                transition: 'all 0.2s ease',
                lineHeight: '1.5'
              }}
              onFocus={(e) => {
                e.target.style.borderColor = '#60a5fa';
                e.target.style.boxShadow = '0 0 0 3px rgba(96, 165, 250, 0.1)';
              }}
              onBlur={(e) => {
                e.target.style.borderColor = '#e2e8f0';
                e.target.style.boxShadow = 'none';
              }}
            />
          </div>

          {/* Error Display */}
          {error && (
            <div style={{
              background: 'linear-gradient(135deg, #fef2f2, #fee2e2)',
              border: '1px solid #fca5a5',
              color: '#dc2626',
              padding: '16px',
              borderRadius: '12px',
              marginBottom: '24px',
              fontSize: '14px',
              display: 'flex',
              alignItems: 'center',
              gap: '8px'
            }}>
              <span style={{ fontSize: '16px' }}>❌</span>
              {error}
            </div>
          )}

          {/* Analyze Button */}
          <button
            onClick={analyzeCode}
            disabled={loading}
            style={{
              width: '100%',
              background: loading ? '#94a3b8' : 'linear-gradient(135deg, #3b82f6, #1d4ed8)',
              color: 'white',
              border: 'none',
              padding: '16px 24px',
              borderRadius: '12px',
              fontSize: '16px',
              fontWeight: '700',
              cursor: loading ? 'not-allowed' : 'pointer',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: '12px',
              transition: 'all 0.2s ease',
              boxShadow: loading ? 'none' : '0 4px 14px 0 rgba(59, 130, 246, 0.4)',
              transform: loading ? 'none' : 'translateY(0)'
            }}
            onMouseEnter={(e) => {
              if (!loading) {
                e.target.style.transform = 'translateY(-2px)';
                e.target.style.boxShadow = '0 8px 25px 0 rgba(59, 130, 246, 0.4)';
              }
            }}
            onMouseLeave={(e) => {
              if (!loading) {
                e.target.style.transform = 'translateY(0)';
                e.target.style.boxShadow = '0 4px 14px 0 rgba(59, 130, 246, 0.4)';
              }
            }}
          >
            {loading ? (
              <>
                <div style={{
                  width: '20px',
                  height: '20px',
                  border: '2px solid transparent',
                  borderTop: '2px solid white',
                  borderRadius: '50%',
                  animation: 'spin 1s linear infinite'
                }} />
                Analiz Ediliyor...
              </>
            ) : (
              <>
                <span style={{ fontSize: '18px' }}>🔍</span>
                Güvenlik Analizi Başlat
              </>
            )}
          </button>
        </div>

        {/* Results Panel */}
        {result && analysisData && (
          <div style={{ 
            display: 'flex',
            flexDirection: 'column',
            gap: '24px'
          }}>
            {/* Analysis Header */}
            <div style={{
              background: 'rgba(255, 255, 255, 0.95)',
              borderRadius: '20px',
              padding: '24px',
              backdropFilter: 'blur(20px)',
              border: '1px solid rgba(255, 255, 255, 0.2)',
              boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.25)'
            }}>
              <div style={{ 
                display: 'flex', 
                justifyContent: 'space-between', 
                alignItems: 'flex-start',
                marginBottom: '20px'
              }}>
                <div>
                  <h2 style={{ 
                    fontSize: '1.5rem', 
                    fontWeight: '700', 
                    margin: '0 0 8px 0',
                    color: '#1e293b',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '12px'
                  }}>
                    <span style={{ fontSize: '24px' }}>📊</span>
                    Güvenlik Analiz Raporu
                  </h2>
                  <div style={{ 
                    fontSize: '14px', 
                    color: '#64748b',
                    fontStyle: 'italic',
                    marginBottom: '8px'
                  }}>
                    "{result.original_prompt}"
                  </div>
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', alignItems: 'flex-end' }}>
                  <div style={{
                    background: 'linear-gradient(135deg, #f8fafc, #e2e8f0)',
                    padding: '6px 12px',
                    borderRadius: '16px',
                    fontSize: '11px',
                    color: '#475569',
                    border: '1px solid #cbd5e1',
                    fontWeight: '600'
                  }}>
                    🧠 {analysisData.analysisMethod}
                  </div>
                  <div style={{
                    background: 'linear-gradient(135deg, #ddd6fe, #c4b5fd)',
                    padding: '6px 12px',
                    borderRadius: '16px',
                    fontSize: '11px',
                    color: '#5b21b6',
                    border: '1px solid #a78bfa',
                    fontWeight: '600'
                  }}>
                    🤖 {analysisData.modelType}
                  </div>
                  <div style={{
                    background: analysisData.isVulnerable 
                      ? 'linear-gradient(135deg, #fee2e2, #fca5a5)' 
                      : 'linear-gradient(135deg, #dcfce7, #86efac)',
                    padding: '6px 12px',
                    borderRadius: '16px',
                    fontSize: '11px',
                    color: analysisData.isVulnerable ? '#dc2626' : '#16a34a',
                    border: `1px solid ${analysisData.isVulnerable ? '#fca5a5' : '#86efac'}`,
                    fontWeight: '600'
                  }}>
                    {analysisData.isVulnerable ? '🚨 VULNERABLE' : '✅ SECURE'}
                  </div>
                </div>
              </div>
              
              <div style={{ 
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                flexWrap: 'wrap',
                gap: '12px'
              }}>
                <div style={{ 
                  fontSize: '13px', 
                  color: '#64748b',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '8px'
                }}>
                  <span>🕒</span>
                  {formatTimestamp(result.analysis_timestamp)}
                </div>
                <div style={{ 
                  fontSize: '13px', 
                  color: '#64748b',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '8px'
                }}>
                  <span>🎯</span>
                  ML Models: {analysisData.mlModelCount}
                </div>
              </div>
            </div>

            {/* Risk Summary Card */}
            {(() => {
              const severity = getSeverityLevel(analysisData.riskLevel);
              const config = severityConfig[severity];
              return (
                <div style={{
                  background: config.bg,
                  borderRadius: '20px',
                  padding: '32px',
                  color: config.text,
                  boxShadow: config.shadow,
                  border: '1px solid rgba(255, 255, 255, 0.2)'
                }}>
                  <div style={{ 
                    display: 'flex', 
                    alignItems: 'center', 
                    gap: '16px', 
                    marginBottom: '24px' 
                  }}>
                    <span style={{ fontSize: '32px' }}>{config.icon}</span>
                    <div>
                      <h3 style={{ 
                        margin: 0, 
                        fontSize: '1.8rem',
                        fontWeight: '800'
                      }}>
                        {severity} RİSK
                      </h3>
                      <p style={{ margin: '4px 0 0 0', opacity: 0.9 }}>
                        {result.recommendations?.[0]?.description || 'Güvenlik analizi tamamlandı'}
                      </p>
                    </div>
                  </div>
                  
                  <div style={{ 
                    display: 'grid', 
                    gridTemplateColumns: 'repeat(auto-fit, minmax(110px, 1fr))', 
                    gap: '20px' 
                  }}>
                    <div style={{ textAlign: 'center' }}>
                      <div style={{ fontSize: '2.5rem', fontWeight: '800', marginBottom: '4px' }}>
                        {Math.round(analysisData.overallScore * 100)}%
                      </div>
                      <div style={{ fontSize: '13px', opacity: 0.9 }}>Risk Skoru</div>
                    </div>
                    <div style={{ textAlign: 'center' }}>
                      <div style={{ fontSize: '2.5rem', fontWeight: '800', marginBottom: '4px' }}>
                        {result.summary?.total_vulnerabilities_found || analysisData.detectedCweCount}
                      </div>
                      <div style={{ fontSize: '13px', opacity: 0.9 }}>Zafiyet Sayısı</div>
                    </div>
                    <div style={{ textAlign: 'center' }}>
                      <div style={{ fontSize: '2.5rem', fontWeight: '800', marginBottom: '4px' }}>
                        {Math.round(analysisData.ensembleProbability * 100)}%
                      </div>
                      <div style={{ fontSize: '13px', opacity: 0.9 }}>ML Güvenilirlik</div>
                    </div>
                    <div style={{ textAlign: 'center' }}>
                      <div style={{ fontSize: '1.8rem', fontWeight: '800', marginBottom: '4px' }}>
                        {analysisData.primaryVuln?.severity || 'NONE'}
                      </div>
                      <div style={{ fontSize: '13px', opacity: 0.9 }}>En Yüksek Tehdit</div>
                    </div>
                    <div style={{ textAlign: 'center' }}>
                      <div style={{ fontSize: '2.5rem', fontWeight: '800', marginBottom: '4px' }}>
                        {analysisData.mlModelCount}
                      </div>
                      <div style={{ fontSize: '13px', opacity: 0.9 }}>ML Model</div>
                    </div>
                    <div style={{ textAlign: 'center' }}>
                      <div style={{ fontSize: '2rem', fontWeight: '800', marginBottom: '4px' }}>
                        {analysisData.detectedCweCount}
                      </div>
                      <div style={{ fontSize: '13px', opacity: 0.9 }}>CWE Count</div>
                    </div>
                  </div>
                </div>
              );
            })()}

            {/* Generated Code */}
            <div style={{
              background: 'rgba(255, 255, 255, 0.95)',
              borderRadius: '20px',
              padding: '24px',
              backdropFilter: 'blur(20px)',
              border: '1px solid rgba(255, 255, 255, 0.2)',
              boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.25)'
            }}>
              <h3 style={{ 
                fontSize: '1.2rem', 
                fontWeight: '700', 
                marginBottom: '16px',
                color: '#1e293b',
                display: 'flex',
                alignItems: 'center',
                gap: '10px'
              }}>
                <span style={{ fontSize: '20px' }}>📝</span>
                Üretilen Kod
                <span style={{
                  background: languages.find(l => l.value === language)?.color || '#6b7280',
                  color: 'white',
                  padding: '4px 12px',
                  borderRadius: '12px',
                  fontSize: '12px',
                  fontWeight: '600'
                }}>
                  {languages.find(l => l.value === language)?.label || language.toUpperCase()}
                </span>
              </h3>
              <div style={{
                background: 'linear-gradient(135deg, #0f172a, #1e293b)',
                color: '#f1f5f9',
                padding: '24px',
                borderRadius: '16px',
                fontFamily: '"JetBrains Mono", Monaco, Consolas, "Courier New", monospace',
                fontSize: '14px',
                lineHeight: '1.6',
                overflow: 'auto',
                maxHeight: '400px',
                border: '1px solid #334155'
              }}>
                {formatCode(result.generated_code)}
              </div>
            </div>

            {/* Primary Vulnerability Details */}
            {analysisData.primaryVuln && (
              <div style={{
                background: 'rgba(255, 255, 255, 0.95)',
                borderRadius: '20px',
                padding: '24px',
                backdropFilter: 'blur(20px)',
                border: '1px solid rgba(255, 255, 255, 0.2)',
                boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.25)'
              }}>
                <h3 style={{ 
                  fontSize: '1.2rem', 
                  fontWeight: '700', 
                  marginBottom: '20px',
                  color: '#1e293b',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '10px'
                }}>
                  <span style={{ fontSize: '20px' }}>🎯</span>
                  Ana Güvenlik Tehdidi
                </h3>
                
                {(() => {
                  const primaryVuln = analysisData.primaryVuln;
                  const severityConfig = {
                    'CRITICAL': { bg: '#fef2f2', border: '#dc2626', text: '#dc2626' },
                    'HIGH': { bg: '#fff7ed', border: '#ea580c', text: '#ea580c' },
                    'MEDIUM': { bg: '#fffbeb', border: '#d97706', text: '#d97706' },
                    'LOW': { bg: '#f0fdf4', border: '#16a34a', text: '#16a34a' }
                  };
                  const config = severityConfig[primaryVuln.severity] || severityConfig['MEDIUM'];
                  
                  return (
                    <div style={{
                      background: config.bg,
                      border: `3px solid ${config.border}`,
                      borderRadius: '16px',
                      padding: '24px'
                    }}>
                      <div style={{ 
                        display: 'flex', 
                        alignItems: 'center', 
                        gap: '12px', 
                        marginBottom: '16px' 
                      }}>
                        <span style={{
                          background: config.text,
                          color: 'white',
                          padding: '8px 16px',
                          borderRadius: '24px',
                          fontSize: '14px',
                          fontWeight: '800'
                        }}>
                          {primaryVuln.cwe_id}
                        </span>
                        <span style={{
                          background: config.text,
                          color: 'white',
                          padding: '8px 16px',
                          borderRadius: '24px',
                          fontSize: '14px',
                          fontWeight: '800'
                        }}>
                          {primaryVuln.severity} SEVERITY
                        </span>
                        <span style={{
                          background: 'rgba(0,0,0,0.1)',
                          color: config.text,
                          padding: '8px 16px',
                          borderRadius: '24px',
                          fontSize: '14px',
                          fontWeight: '700'
                        }}>
                          🎯 %{Math.round(primaryVuln.confidence * 100)} Güvenilirlik
                        </span>
                      </div>
                      
                      <h4 style={{ 
                        margin: '0 0 12px 0', 
                        color: config.text,
                        fontSize: '18px',
                        fontWeight: '700'
                      }}>
                        {primaryVuln.name}
                      </h4>
                      
                      <p style={{ 
                        margin: '0 0 16px 0', 
                        color: '#374151',
                        lineHeight: '1.6',
                        fontSize: '15px'
                      }}>
                        {primaryVuln.description}
                      </p>
                      
                      <div style={{
                        display: 'grid',
                        gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))',
                        gap: '16px',
                        marginTop: '16px'
                      }}>
                        <div style={{ 
                          background: 'rgba(255,255,255,0.8)',
                          padding: '12px',
                          borderRadius: '12px',
                          textAlign: 'center'
                        }}>
                          <div style={{ fontSize: '12px', color: '#6b7280', marginBottom: '4px' }}>
                            CWE ID
                          </div>
                          <div style={{ fontSize: '16px', fontWeight: '700', color: config.text }}>
                            {primaryVuln.cwe_id}
                          </div>
                        </div>
                        
                        <div style={{ 
                          background: 'rgba(255,255,255,0.8)',
                          padding: '12px',
                          borderRadius: '12px',
                          textAlign: 'center'
                        }}>
                          <div style={{ fontSize: '12px', color: '#6b7280', marginBottom: '4px' }}>
                            Confidence Level
                          </div>
                          <div style={{ fontSize: '16px', fontWeight: '700', color: config.text }}>
                            {Math.round(primaryVuln.confidence * 100)}%
                          </div>
                        </div>
                      </div>
                    </div>
                  );
                })()}
              </div>
            )}

            {/* All Vulnerabilities List */}
            {analysisData.vulnerabilities.length > 0 && (
              <div style={{
                background: 'rgba(255, 255, 255, 0.95)',
                borderRadius: '20px',
                padding: '24px',
                backdropFilter: 'blur(20px)',
                border: '1px solid rgba(255, 255, 255, 0.2)',
                boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.25)'
              }}>
                <h3 style={{ 
                  fontSize: '1.2rem', 
                  fontWeight: '700', 
                  marginBottom: '20px',
                  color: '#1e293b',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '10px'
                }}>
                  <span style={{ fontSize: '20px' }}>⚠️</span>
                  Tespit Edilen Güvenlik Açıkları ({analysisData.vulnerabilities.length})
                </h3>
                
                {analysisData.vulnerabilities.map((vuln, index) => {
                  const severityConfig = {
                    'CRITICAL': { bg: '#fef2f2', border: '#dc2626', text: '#dc2626' },
                    'HIGH': { bg: '#fff7ed', border: '#ea580c', text: '#ea580c' },
                    'MEDIUM': { bg: '#fffbeb', border: '#d97706', text: '#d97706' },
                    'LOW': { bg: '#f0fdf4', border: '#16a34a', text: '#16a34a' }
                  };
                  const config = severityConfig[vuln.severity] || severityConfig['MEDIUM'];
                  
                  return (
                    <div key={index} style={{
                      background: config.bg,
                      border: `2px solid ${config.border}`,
                      borderRadius: '16px',
                      padding: '20px',
                      marginBottom: index < analysisData.vulnerabilities.length - 1 ? '16px' : '0'
                    }}>
                      <div style={{ 
                        display: 'flex', 
                        alignItems: 'center', 
                        gap: '12px', 
                        marginBottom: '12px' 
                      }}>
                        <span style={{
                          background: config.text,
                          color: 'white',
                          padding: '6px 12px',
                          borderRadius: '20px',
                          fontSize: '12px',
                          fontWeight: '700'
                        }}>
                          {vuln.cwe_id}
                        </span>
                        <span style={{
                          background: config.text,
                          color: 'white',
                          padding: '6px 12px',
                          borderRadius: '20px',
                          fontSize: '12px',
                          fontWeight: '700'
                        }}>
                          {vuln.severity}
                        </span>
                        <span style={{
                          background: 'rgba(0,0,0,0.1)',
                          color: config.text,
                          padding: '6px 12px',
                          borderRadius: '20px',
                          fontSize: '12px',
                          fontWeight: '600'
                        }}>
                          %{Math.round(vuln.confidence * 100)} Güvenilirlik
                        </span>
                      </div>
                      
                      <h4 style={{ 
                        margin: '0 0 8px 0', 
                        color: config.text,
                        fontSize: '16px',
                        fontWeight: '700'
                      }}>
                        {vuln.name}
                      </h4>
                      
                      <p style={{ 
                        margin: '0 0 16px 0', 
                        color: '#374151',
                        lineHeight: '1.5'
                      }}>
                        {vuln.description}
                      </p>
                      
                      {/* Solution from recommendations */}
                      {result.recommendations?.find(rec => rec.type.includes(vuln.cwe_id.split('-')[1])) && (
                        <div style={{ 
                          background: 'rgba(255,255,255,0.8)',
                          padding: '16px',
                          borderRadius: '12px',
                          border: '1px solid rgba(0,0,0,0.1)'
                        }}>
                          <div style={{ 
                            display: 'flex', 
                            alignItems: 'center', 
                            gap: '8px', 
                            marginBottom: '8px' 
                          }}>
                            <span style={{ fontSize: '16px' }}>💡</span>
                            <strong style={{ color: '#374151' }}>Önerilen Çözüm:</strong>
                          </div>
                          <p style={{ 
                            margin: 0, 
                            color: '#6b7280',
                            fontSize: '14px',
                            lineHeight: '1.5'
                          }}>
                            {result.recommendations.find(rec => rec.type.includes(vuln.cwe_id.split('-')[1]))?.solution}
                          </p>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            )}

            {/* CWE Analysis */}
            <div style={{
              background: 'rgba(255, 255, 255, 0.95)',
              borderRadius: '20px',
              padding: '24px',
              backdropFilter: 'blur(20px)',
              border: '1px solid rgba(255, 255, 255, 0.2)',
              boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.25)'
            }}>
              <h3 style={{ 
                fontSize: '1.2rem', 
                fontWeight: '700', 
                marginBottom: '20px',
                color: '#1e293b',
                display: 'flex',
                alignItems: 'center',
                gap: '10px'
              }}>
                <span style={{ fontSize: '20px' }}>🎯</span>
                CWE Güvenlik Kategorileri
              </h3>
              
              <div style={{ display: 'grid', gap: '12px' }}>
                {Object.entries(analysisData.cweAnalysis).map(([cwe, data]) => (
                  <div key={cwe} style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    padding: '16px',
                    background: data.vulnerable 
                      ? 'linear-gradient(135deg, #fef2f2, #fee2e2)' 
                      : 'linear-gradient(135deg, #f0fdf4, #dcfce7)',
                    border: `2px solid ${data.vulnerable ? '#fca5a5' : '#86efac'}`,
                    borderRadius: '12px',
                    transition: 'all 0.2s ease'
                  }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                      <span style={{ 
                        fontWeight: '700', 
                        color: '#1e293b',
                        fontSize: '14px'
                      }}>
                        {cwe}
                      </span>
                      <span style={{
                        fontSize: '12px',
                        color: data.vulnerable ? '#dc2626' : '#16a34a',
                        fontWeight: '600',
                        display: 'flex',
                        alignItems: 'center',
                        gap: '4px'
                      }}>
                        {data.vulnerable ? '❌ Vulnerable' : '✅ Safe'}
                      </span>
                    </div>
                    
                    <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                      <div style={{
                        background: data.vulnerable ? '#dc2626' : '#16a34a',
                        color: 'white',
                        padding: '6px 16px',
                        borderRadius: '20px',
                        fontSize: '12px',
                        fontWeight: '700'
                      }}>
                        {Math.round(data.probability * 100)}%
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Technical Details */}
            <div style={{
              background: 'rgba(255, 255, 255, 0.95)',
              borderRadius: '20px',
              padding: '24px',
              backdropFilter: 'blur(20px)',
              border: '1px solid rgba(255, 255, 255, 0.2)',
              boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.25)'
            }}>
              <h3 style={{ 
                fontSize: '1.2rem', 
                fontWeight: '700', 
                marginBottom: '20px',
                color: '#1e293b',
                display: 'flex',
                alignItems: 'center',
                gap: '10px'
              }}>
                <span style={{ fontSize: '20px' }}>🔧</span>
                Teknik Detaylar
              </h3>
              
              <div style={{ 
                display: 'grid', 
                gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', 
                gap: '16px' 
              }}>
                <div style={{
                  background: 'linear-gradient(135deg, #f8fafc, #e2e8f0)',
                  padding: '16px',
                  borderRadius: '12px',
                  border: '1px solid #cbd5e1'
                }}>
                  <div style={{ fontSize: '12px', color: '#64748b', marginBottom: '8px' }}>
                    🧠 Analiz Motoru
                  </div>
                  <div style={{ fontSize: '14px', fontWeight: '700', color: '#1e293b' }}>
                    {analysisData.analysisMethod}
                  </div>
                </div>

                <div style={{
                  background: 'linear-gradient(135deg, #ddd6fe, #c4b5fd)',
                  padding: '16px',
                  borderRadius: '12px',
                  border: '1px solid #a78bfa'
                }}>
                  <div style={{ fontSize: '12px', color: '#5b21b6', marginBottom: '8px' }}>
                    🤖 Model Tipi
                  </div>
                  <div style={{ fontSize: '14px', fontWeight: '700', color: '#5b21b6' }}>
                    {analysisData.modelType}
                  </div>
                </div>

                <div style={{
                  background: 'linear-gradient(135deg, #fef3c7, #fde68a)',
                  padding: '16px',
                  borderRadius: '12px',
                  border: '1px solid #f59e0b'
                }}>
                  <div style={{ fontSize: '12px', color: '#92400e', marginBottom: '8px' }}>
                    📊 ML Modelleri
                  </div>
                  <div style={{ fontSize: '14px', fontWeight: '700', color: '#92400e' }}>
                    {analysisData.mlModelCount} Model
                  </div>
                </div>

                <div style={{
                  background: 'linear-gradient(135deg, #dcfce7, #86efac)',
                  padding: '16px',
                  borderRadius: '12px',
                  border: '1px solid #16a34a'
                }}>
                  <div style={{ fontSize: '12px', color: '#166534', marginBottom: '8px' }}>
                    🎯 Ensemble Skoru
                  </div>
                  <div style={{ fontSize: '14px', fontWeight: '700', color: '#166534' }}>
                    {Math.round(analysisData.ensembleProbability * 100)}%
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* CSS Animations */}
      <style jsx>{`
        @keyframes spin {
          0% { transform: rotate(0deg); }
          100% { transform: rotate(360deg); }
        }
      `}</style>
    </div>
  );
};

export default SecurityAnalyzer;