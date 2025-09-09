import React, { useMemo, useState } from 'react';
import { Shield, Search, CheckCircle, AlertTriangle, XCircle, Loader2, FileText, FileJson, FileDown } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Progress } from '@/components/ui/progress';

type ScannerKey = 'broken_access' | 'csrf' | 'sqli' | 'xss' | 'combined';

type Status = 'safe' | 'warning' | 'vulnerable' | 'info';

interface ScannerOutput {
  html?: string;
  html_full?: string;
  pdf?: string;
  pdf_full?: string;
  json?: string;
  html_exploited?: string;
  web_html?: string;
  web_html_full?: string;
  web_pdf?: string;
  web_pdf_full?: string;
  web_json?: string;
  web_html_exploited?: string;
}

interface ApiResponse {
  status: 'ok' | 'error';
  reportsBase: string; // web base path for this run
  outputs: Partial<Record<ScannerKey, ScannerOutput>>;
  errors: Partial<Record<'broken_access' | 'csrf' | 'sqli' | 'xss', string>>;
}

interface UiScannerResult {
  key: ScannerKey;
  name: string;
  status: Status;
  details?: string;
  icon: React.ReactNode;
  links?: {
    html?: string;
    pdf?: string;
    json?: string;
    exploited?: string;
  };
  error?: string;
}

const SecurityScanner = () => {
  const [url, setUrl] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [results, setResults] = useState<UiScannerResult[] | null>(null);
  const [combinedLink, setCombinedLink] = useState<string | null>(null);
  const apiBase = useMemo(() => (import.meta.env.VITE_API_BASE as string) || 'http://localhost:8000', []);

  const toScannerName = (key: ScannerKey) => {
    switch (key) {
      case 'broken_access':
        return 'Broken Access Control';
      case 'csrf':
        return 'Cross-Site Request Forgery (CSRF)';
      case 'sqli':
        return 'SQL Injection';
      case 'xss':
        return 'Cross-Site Scripting (XSS)';
      case 'combined':
        return 'Combined Report';
      default:
        return key;
    }
  };

  const toIcon = (key: ScannerKey, status: Status) => {
    if (key === 'combined') return <FileText className="h-5 w-5" />;
    if (status === 'safe') return <CheckCircle className="h-5 w-5" />;
    if (status === 'vulnerable') return <XCircle className="h-5 w-5" />;
    return <AlertTriangle className="h-5 w-5" />;
  };

  const handleScan = async () => {
    if (!url) return;
    
    setIsScanning(true);
    setScanProgress(0);
    setResults(null);
    setCombinedLink(null);

    // Simulate a progress bar while the backend processes
    const progressInterval = setInterval(() => {
      setScanProgress((prev) => {
        if (prev >= 100) {
          clearInterval(progressInterval);
          return 100;
        }
        return prev + 8;
      });
    }, 400);

    try {
      const res = await fetch(`${apiBase}/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url }),
      });
      const data = (await res.json()) as ApiResponse;

      // Build UI results
      const scanners: ScannerKey[] = ['broken_access', 'csrf', 'sqli', 'xss'];
      const ui: UiScannerResult[] = scanners.map((key) => {
        const out = data.outputs?.[key];
        const err = data.errors?.[key as 'broken_access' | 'csrf' | 'sqli' | 'xss'];
        const hasReport = !!out?.web_html || !!out?.web_json || !!out?.web_pdf;
        const status: Status = err ? 'warning' : hasReport ? 'info' : 'warning';
        return {
          key,
          name: toScannerName(key),
          status,
          details: err ? 'Scan failed. See error below.' : 'Scan completed. Open the report to review findings.',
          icon: toIcon(key, status),
          links: {
            html: out?.web_html ? `${apiBase}${out.web_html}` : undefined,
            pdf: out?.web_pdf ? `${apiBase}${out.web_pdf}` : undefined,
            json: out?.web_json ? `${apiBase}${out.web_json}` : undefined,
            exploited: out?.web_html_exploited ? `${apiBase}${out.web_html_exploited}` : undefined,
          },
          error: err,
        };
      });

      const combined = data.outputs?.combined;
      if (combined?.web_html_full || combined?.web_html)
        setCombinedLink(`${apiBase}${(combined.web_html_full||combined.web_html) as string}`);
      const combinedPdf = combined?.web_pdf_full || combined?.web_pdf;
      const combinedPdfUrl = combinedPdf ? `${apiBase}${combinedPdf}` : undefined;

      // Inject a synthetic combined row at the top with links if desired
      if (combinedPdfUrl || (combined?.web_html_full || combined?.web_html)) {
        ui.unshift({
          key: 'combined',
          name: 'Combined Report',
          status: 'info',
          details: 'Complete combined report generated',
          icon: <FileText className="h-5 w-5" />,
          links: {
            html: (combined?.web_html_full || combined?.web_html) ? `${apiBase}${(combined.web_html_full||combined.web_html) as string}` : undefined,
            pdf: combinedPdfUrl,
          },
        });
      }

      setResults(ui);
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : 'Unknown error';
      setResults([
        {
          key: 'combined',
          name: 'Scan Error',
          status: 'warning',
          details: msg || 'Failed to contact backend',
          icon: <AlertTriangle className="h-5 w-5" />,
        },
      ]);
    } finally {
      setIsScanning(false);
      setScanProgress(100);
      clearInterval(progressInterval);
    }
  };

  const getStatusColor = (status: Status) => {
    switch (status) {
      case 'safe':
        return 'text-success';
      case 'info':
        return 'text-primary';
      case 'warning':
        return 'text-warning';
      case 'vulnerable':
        return 'text-destructive';
      default:
        return 'text-muted-foreground';
    }
  };

  const getStatusBg = (status: Status) => {
    switch (status) {
      case 'safe':
        return 'bg-success/10 border-success/20';
      case 'info':
        return 'bg-primary/10 border-primary/20';
      case 'warning':
        return 'bg-warning/10 border-warning/20';
      case 'vulnerable':
        return 'bg-destructive/10 border-destructive/20';
      default:
        return 'bg-muted/10 border-border';
    }
  };

  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <header className="bg-gradient-hero shadow-elegant">
        <div className="container mx-auto px-4 py-8">
          <div className="flex items-center justify-center gap-3 mb-2">
            <Shield className="h-8 w-8 text-white" />
            <h1 className="text-4xl font-bold text-white">
              B-Secure Scanner
            </h1>
            <span className="text-2xl">🔒</span>
          </div>
          <p className="text-center text-white/90 text-lg">
            Comprehensive security analysis for web applications
          </p>
        </div>
      </header>

      <div className="container mx-auto px-4 py-12 max-w-4xl">
        {/* Scan Input Section */}
        <Card className="mb-8 shadow-card border-0 bg-card/50 backdrop-blur-sm animate-fade-in">
          <CardHeader className="text-center">
            <CardTitle className="text-2xl text-foreground flex items-center justify-center gap-2">
              <Search className="h-6 w-6 text-primary" />
              Enter Target URL
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex gap-4">
              <Input
                type="url"
                placeholder="https://example.com"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                className="flex-1 text-lg h-12 border-border/50 focus:border-primary"
                disabled={isScanning}
              />
              <Button 
                onClick={handleScan}
                disabled={!url || isScanning}
                variant="hero"
                size="lg"
                className="px-8"
              >
                {isScanning ? (
                  <>
                    <Loader2 className="mr-2 h-5 w-5 animate-spin" />
                    Scanning...
                  </>
                ) : (
                  <>
                    <Shield className="mr-2 h-5 w-5" />
                    Start Scan
                  </>
                )}
              </Button>
            </div>
            
            {isScanning && (
              <div className="space-y-2 animate-scale-in">
                <div className="flex justify-between text-sm text-muted-foreground">
                  <span>Scanning in progress...</span>
                  <span>{scanProgress}%</span>
                </div>
                <Progress value={scanProgress} className="h-2" />
                <div className="bg-gradient-primary h-1 rounded-full overflow-hidden">
                  <div className="h-full w-8 bg-white/30 animate-scan-progress"></div>
                </div>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Results Section */}
        {results && (
          <div className="space-y-6 animate-fade-in">
            <div className="text-center mb-6">
              <h2 className="text-2xl font-bold text-foreground mb-2">Security Analysis Results</h2>
              <p className="text-muted-foreground">
                Scan completed for: <span className="font-mono text-primary">{url}</span>
              </p>
              {combinedLink && (
                <div className="mt-3">
                  <a
                    href={combinedLink}
                    target="_blank"
                    rel="noreferrer"
                    className="inline-flex items-center gap-2 text-primary hover:underline"
                  >
                    <FileText className="h-4 w-4" /> Open Combined Report
                  </a>
                </div>
              )}
            </div>

            <div className="grid gap-6 md:grid-cols-2">
              {results.map((result) => (
                <Card
                  key={result.key}
                  className={`shadow-card border transition-all duration-300 hover:shadow-elegant hover:scale-105 ${getStatusBg(result.status)}`}
                >
                  <CardHeader className="pb-3">
                    <CardTitle className="flex items-center gap-3 text-lg">
                      <div className={getStatusColor(result.status)}>
                        {result.icon}
                      </div>
                      {result.name}
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <p className="text-muted-foreground leading-relaxed">
                      {result.details}
                    </p>

                    {result.links && (
                      <div className="mt-4 flex flex-wrap items-center gap-3">
                        {result.links.html && (
                          <a
                            href={result.links.html}
                            target="_blank"
                            rel="noreferrer"
                            className="inline-flex items-center gap-2 text-primary hover:underline"
                          >
                            <FileText className="h-4 w-4" /> HTML Report
                          </a>
                        )}
                        {result.links.pdf && (
                          <a
                            href={result.links.pdf}
                            target="_blank"
                            rel="noreferrer"
                            className="inline-flex items-center gap-2 text-primary hover:underline"
                          >
                            <FileDown className="h-4 w-4" /> PDF
                          </a>
                        )}
                        {result.links.json && (
                          <a
                            href={result.links.json}
                            target="_blank"
                            rel="noreferrer"
                            className="inline-flex items-center gap-2 text-primary hover:underline"
                          >
                            <FileJson className="h-4 w-4" /> JSON
                          </a>
                        )}
                        {result.links.exploited && (
                          <a
                            href={result.links.exploited}
                            target="_blank"
                            rel="noreferrer"
                            className="inline-flex items-center gap-2 text-primary hover:underline"
                          >
                            <FileText className="h-4 w-4" /> Exploited HTML
                          </a>
                        )}
                      </div>
                    )}

                    {result.error && (
                      <div className="mt-3 text-sm text-warning">
                        Error: {result.error}
                      </div>
                    )}

                    <div className="mt-4 flex items-center gap-2">
                      <div
                        className={`px-3 py-1 rounded-full text-xs font-medium ${
                          result.status === 'safe'
                            ? 'bg-success text-success-foreground'
                            : result.status === 'vulnerable'
                            ? 'bg-destructive text-destructive-foreground'
                            : result.status === 'info'
                            ? 'bg-primary text-primary-foreground'
                            : 'bg-warning text-warning-foreground'
                        }`}
                      >
                        {result.status === 'safe'
                          ? 'SECURE'
                          : result.status === 'vulnerable'
                          ? 'HIGH RISK'
                          : result.status === 'info'
                          ? 'COMPLETED'
                          : 'ATTENTION'}
                      </div>
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>

            <Card className="bg-accent/30 border-accent shadow-card">
              <CardContent className="pt-6">
                <div className="text-center">
                  <Shield className="h-12 w-12 text-primary mx-auto mb-4" />
                  <h3 className="text-lg font-semibold text-foreground mb-2">
                    Security Scan Complete
                  </h3>
                  <p className="text-muted-foreground">
                    Open each report to review detailed findings. Prioritize high-risk vulnerabilities
                    and consider implementing additional security measures based on recommendations.
                  </p>
                </div>
              </CardContent>
            </Card>
          </div>
        )}
      </div>
    </div>
  );
};

export default SecurityScanner;