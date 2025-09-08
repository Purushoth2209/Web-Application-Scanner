import React, { useState } from 'react';
import { useMutation } from '@tanstack/react-query';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import { Separator } from '@/components/ui/separator';
import { Loader2, Shield, Download, FileText, Eye, Sparkles, Brain } from 'lucide-react';

const API_BASE = import.meta.env.VITE_API_BASE || 'http://localhost:8000';

interface ScanOutput {
  web_html?: string;
  web_json?: string;
  web_pdf?: string;
  web_html_exploited?: string;
  html?: string;
  json?: string;
  pdf?: string;
  html_exploited?: string;
}

interface ScanResult {
  status: string;
  reportsBase: string;
  outputs: Record<string, ScanOutput>;
  errors: Record<string, string>;
}

interface AIAnalysisResult {
  status: string;
  analysis: string;
  type: string;
}

const SecurityScanner = () => {
  const [url, setUrl] = useState('');
  const [results, setResults] = useState<ScanResult | null>(null);
  const [aiAnalysis, setAiAnalysis] = useState<AIAnalysisResult | null>(null);

  const scanMutation = useMutation({
    mutationFn: async (targetUrl: string): Promise<ScanResult> => {
      const response = await fetch(`${API_BASE}/scan`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ url: targetUrl }),
      });
      
      if (!response.ok) {
        throw new Error('Scan request failed');
      }
      
      return response.json();
    },
    onSuccess: (data) => {
      setResults(data);
      // Automatically get AI analysis after scan
      getAiAnalysis(data);
    },
  });

  const aiAnalysisMutation = useMutation({
    mutationFn: async (scanResults: ScanResult): Promise<AIAnalysisResult> => {
      const response = await fetch(`${API_BASE}/ai_analysis`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ 
          scan_results: scanResults,
          analysis_type: 'summary'
        }),
      });
      
      if (!response.ok) {
        throw new Error('AI analysis request failed');
      }
      
      return response.json();
    },
    onSuccess: (data) => {
      setAiAnalysis(data);
    },
  });

  const getAiAnalysis = (scanResults: ScanResult) => {
    aiAnalysisMutation.mutate(scanResults);
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (url.trim()) {
      setResults(null);
      setAiAnalysis(null);
      scanMutation.mutate(url.trim());
    }
  };

  const getScannerDisplayName = (scanner: string) => {
    const names: Record<string, string> = {
      broken_access: 'Broken Access Control',
      csrf: 'CSRF Protection',
      sqli: 'SQL Injection',
      xss: 'Cross-Site Scripting (XSS)',
      combined: 'Combined Report'
    };
    return names[scanner] || scanner.toUpperCase();
  };

  const getScannerIcon = (scanner: string) => {
    const icons: Record<string, string> = {
      broken_access: '🔐',
      csrf: '🛡️',
      sqli: '💉',
      xss: '⚠️',
      combined: '📊'
    };
    return icons[scanner] || '🔍';
  };

  const isLoading = scanMutation.isPending || aiAnalysisMutation.isPending;

  return (
    <div className="max-w-6xl mx-auto p-6 space-y-6">
      {/* Header */}
      <div className="text-center space-y-2">
        <h1 className="text-4xl font-bold bg-gradient-to-r from-blue-600 to-purple-600 bg-clip-text text-transparent">
          🛡️ B-Secure Scanner AI
        </h1>
        <p className="text-muted-foreground text-lg">
          Comprehensive vulnerability assessment powered by Gemini AI
        </p>
        <div className="flex justify-center gap-2 text-sm text-muted-foreground">
          <Badge variant="outline" className="text-xs">
            <Brain className="w-3 h-3 mr-1" />
            Gemini 2.0 Flash
          </Badge>
          <Badge variant="outline" className="text-xs">
            <Sparkles className="w-3 h-3 mr-1" />
            AI-Powered Analysis
          </Badge>
          <Badge variant="outline" className="text-xs">
            📄 Enhanced PDF Reports
          </Badge>
        </div>
      </div>

      {/* Scan Form */}
      <Card className="border-2 border-primary/20">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Shield className="w-5 h-5" />
            Security Scan Configuration
          </CardTitle>
          <CardDescription>
            Enter a target URL to perform comprehensive vulnerability scanning with AI analysis
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="url">Target URL</Label>
              <Input
                id="url"
                type="url"
                placeholder="https://example.com"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                disabled={isLoading}
                className="text-lg"
              />
            </div>
            <Button 
              type="submit" 
              disabled={isLoading || !url.trim()}
              className="w-full text-lg py-6"
            >
              {isLoading ? (
                <>
                  <Loader2 className="w-5 h-5 mr-2 animate-spin" />
                  {scanMutation.isPending ? 'Scanning...' : 'Analyzing with AI...'}
                </>
              ) : (
                <>
                  <Sparkles className="w-5 h-5 mr-2" />
                  Start AI-Enhanced Scan
                </>
              )}
            </Button>
          </form>
        </CardContent>
      </Card>

      {/* Error Display */}
      {(scanMutation.error || aiAnalysisMutation.error) && (
        <Alert variant="destructive">
          <AlertDescription>
            Error: {scanMutation.error?.message || aiAnalysisMutation.error?.message}
          </AlertDescription>
        </Alert>
      )}

      {/* AI Analysis Results */}
      {aiAnalysis && (
        <Card className="border-2 border-blue-200 bg-gradient-to-r from-blue-50 to-purple-50">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-blue-700">
              <Brain className="w-5 h-5" />
              🤖 AI-Powered Security Analysis
            </CardTitle>
            <CardDescription>
              Gemini AI analysis of your security scan results
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div 
              className="prose max-w-none text-sm"
              dangerouslySetInnerHTML={{ __html: aiAnalysis.analysis }}
            />
          </CardContent>
        </Card>
      )}

      {/* Scan Results */}
      {results && (
        <div className="space-y-6">
          <div className="flex items-center justify-between">
            <h2 className="text-2xl font-bold">Scan Results</h2>
            <Badge variant="outline" className="text-lg px-4 py-2">
              Status: {results.status}
            </Badge>
          </div>

          {/* Summary Card */}
          <Card className="border-2 border-green-200 bg-gradient-to-r from-green-50 to-blue-50">
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-green-700">
                📊 Scan Summary
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div className="text-center">
                  <div className="text-2xl font-bold text-blue-600">
                    {Object.keys(results.outputs).filter(k => k !== 'combined').length}
                  </div>
                  <div className="text-sm text-muted-foreground">Scanners Run</div>
                </div>
                <div className="text-center">
                  <div className="text-2xl font-bold text-red-600">
                    {Object.keys(results.errors).length}
                  </div>
                  <div className="text-sm text-muted-foreground">Errors</div>
                </div>
                <div className="text-center">
                  <div className="text-2xl font-bold text-green-600">
                    {Object.keys(results.outputs).filter(k => 
                      k !== 'combined' && results.outputs[k]?.web_html
                    ).length}
                  </div>
                  <div className="text-sm text-muted-foreground">Reports Generated</div>
                </div>
                <div className="text-center">
                  <div className="text-2xl font-bold text-purple-600">
                    {Object.keys(results.outputs).filter(k => 
                      results.outputs[k]?.web_pdf
                    ).length}
                  </div>
                  <div className="text-sm text-muted-foreground">PDFs Available</div>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Combined Report */}
          {results.outputs.combined && (
            <Card className="border-2 border-purple-200 bg-gradient-to-r from-purple-50 to-pink-50">
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-purple-700">
                  📋 AI-Enhanced Combined Report
                </CardTitle>
                <CardDescription>
                  Comprehensive report with AI analysis and recommendations
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="flex flex-wrap gap-3">
                  {results.outputs.combined.web_html && (
                    <Button asChild variant="default" size="lg">
                      <a href={`${API_BASE}${results.outputs.combined.web_html}`} target="_blank" rel="noopener noreferrer">
                        <Eye className="w-4 h-4 mr-2" />
                        View Enhanced Report
                      </a>
                    </Button>
                  )}
                  {results.outputs.combined.web_pdf && (
                    <Button asChild variant="outline" size="lg">
                      <a href={`${API_BASE}${results.outputs.combined.web_pdf}`} target="_blank" rel="noopener noreferrer">
                        <Download className="w-4 h-4 mr-2" />
                        Download PDF
                      </a>
                    </Button>
                  )}
                </div>
              </CardContent>
            </Card>
          )}

          <Separator />

          {/* Individual Scanner Results */}
          <div className="grid gap-6 md:grid-cols-2">
            {Object.entries(results.outputs)
              .filter(([name]) => name !== 'combined')
              .map(([scanner, output]) => (
                <Card key={scanner} className="transition-all hover:shadow-lg">
                  <CardHeader>
                    <CardTitle className="flex items-center justify-between">
                      <span className="flex items-center gap-2">
                        <span className="text-2xl">{getScannerIcon(scanner)}</span>
                        {getScannerDisplayName(scanner)}
                      </span>
                      {results.errors[scanner] ? (
                        <Badge variant="destructive">Error</Badge>
                      ) : (
                        <Badge variant="secondary">Complete</Badge>
                      )}
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    {results.errors[scanner] ? (
                      <Alert variant="destructive">
                        <AlertDescription>
                          {results.errors[scanner]}
                        </AlertDescription>
                      </Alert>
                    ) : output ? (
                      <div className="space-y-3">
                        <div className="flex flex-wrap gap-2">
                          {output.web_html && (
                            <Button asChild variant="outline" size="sm">
                              <a href={`${API_BASE}${output.web_html}`} target="_blank" rel="noopener noreferrer">
                                <FileText className="w-4 h-4 mr-1" />
                                HTML Report
                              </a>
                            </Button>
                          )}
                          {output.web_json && (
                            <Button asChild variant="outline" size="sm">
                              <a href={`${API_BASE}${output.web_json}`} target="_blank" rel="noopener noreferrer">
                                <Download className="w-4 h-4 mr-1" />
                                JSON Data
                              </a>
                            </Button>
                          )}
                          {output.web_pdf && (
                            <Button asChild variant="outline" size="sm">
                              <a href={`${API_BASE}${output.web_pdf}`} target="_blank" rel="noopener noreferrer">
                                <Download className="w-4 h-4 mr-1" />
                                PDF Report
                              </a>
                            </Button>
                          )}
                          {output.web_html_exploited && (
                            <Button asChild variant="destructive" size="sm">
                              <a href={`${API_BASE}${output.web_html_exploited}`} target="_blank" rel="noopener noreferrer">
                                <Eye className="w-4 h-4 mr-1" />
                                Exploited View
                              </a>
                            </Button>
                          )}
                        </div>
                      </div>
                    ) : (
                      <p className="text-muted-foreground">No output generated</p>
                    )}
                  </CardContent>
                </Card>
              ))}
          </div>
        </div>
      )}
    </div>
  );
};

export default SecurityScanner;
