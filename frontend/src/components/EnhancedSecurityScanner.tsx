import React, { useMemo, useState, useEffect, useRef } from 'react';
import { Shield, Search, CheckCircle, AlertTriangle, XCircle, Loader2, FileText, FileJson, FileDown, Eye, Activity, Clock, Globe, Bug, Lock } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Progress } from '@/components/ui/progress';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { ScrollArea } from '@/components/ui/scroll-area';

type ScannerKey = 'broken_access' | 'csrf' | 'sqli' | 'xss' | 'cors' | 'ssl_tls' | 'combined';

type Status = 'safe' | 'warning' | 'vulnerable' | 'info' | 'scanning' | 'pending';

interface ScannerOutput {
  html?: string;
  pdf?: string;
  json?: string;
  html_exploited?: string;
  web_html?: string;
  web_pdf?: string;
  web_json?: string;
  web_html_exploited?: string;
  vulnerabilities_found?: number;
  links_crawled?: number;
  forms_found?: number;
  scan_duration?: number;
  cvss_max?: number;
  cvss_avg?: number;
  cvss_count?: number;
  cvss_findings?: { issue?: string; risk?: string; cvss?: number }[];
  // SSL/TLS specific
  protocol_support?: Record<string, boolean>;
  certificate?: CertificateInfo;
  summary_text?: string;
}

interface ApiResponse {
  status: 'ok' | 'error';
  reportsBase: string;
  outputs: Partial<Record<ScannerKey, ScannerOutput>>;
  errors: Partial<Record<'broken_access' | 'csrf' | 'sqli' | 'xss' | 'cors' | 'ssl_tls', string>>;
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
  stats?: {
    vulnerabilities?: number;
    links?: number;
    forms?: number;
    duration?: number;
  cvss_max?: number;
  cvss_avg?: number;
  cvss_count?: number;
  cvss_findings?: { issue?: string; risk?: string; cvss?: number }[];
  };
  // SSL/TLS specific
  summary_text?: string;
  protocol_support?: Record<string, boolean>;
  certificate?: CertificateInfo;
}

interface LogEntry {
  timestamp: string;
  level: 'info' | 'warning' | 'error' | 'success';
  message: string;
  scanner?: string;
}

interface SSLTLSFinding { issue: string; status: string; risk: string; evidence: string; mitigation: string }

interface ScanResultSummary {
  broken_access?: { findings: number; high_risk: number; };
  csrf?: { findings: number; high_risk: number; };
  sqli?: { findings: number; high_risk: number; };
  xss?: { findings: number; high_risk: number; };
  cors?: { findings: number; high_risk: number; };
  ssl_tls?: { findings: number; high_risk: number; protocols: Record<string, boolean> }
}

interface CertificateInfo { subject?: string; issuer?: string; not_before?: string; not_after?: string; days_until_expiry?: number; wildcard?: boolean; self_signed?: boolean; sans?: string[]; host_match?: boolean }

interface ScanResult {
  key: ScannerKey;
  status: Status;
  error?: string;
  html?: string;
  pdf?: string;
  json?: string;
  html_exploited?: string;
  web_html?: string;
  web_pdf?: string;
  web_json?: string;
  web_html_exploited?: string;
  vulnerabilities_found?: number;
  links_crawled?: number;
  forms_found?: number;
  scan_duration?: number;
  cvss_max?: number;
  cvss_avg?: number;
  cvss_count?: number;
  cvss_findings?: { issue?: string; risk?: string; cvss?: number }[];
  ssl_tls?: { findings: SSLTLSFinding[]; protocol_support: Record<string, boolean>; certificate: CertificateInfo | null; summary_text: string }
}

const EnhancedSecurityScanner = () => {
  const [url, setUrl] = useState('');
  const [scanDepth, setScanDepth] = useState(2);
  const [isScanning, setIsScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [currentScanner, setCurrentScanner] = useState<string>('');
  const [results, setResults] = useState<UiScannerResult[] | null>(null);
  const [combinedLink, setCombinedLink] = useState<string | null>(null);
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [activeTab, setActiveTab] = useState('scan');
  const logsEndRef = useRef<HTMLDivElement>(null);
  const apiBase = useMemo(() => (import.meta.env.VITE_API_URL as string) || 'http://localhost:8000', []);

  const scrollToBottom = () => {
    logsEndRef.current?.scrollIntoView({ behavior: "smooth" });
  };

  useEffect(() => {
    scrollToBottom();
  }, [logs]);

  const addLog = (level: LogEntry['level'], message: string, scanner?: string) => {
    const newLog: LogEntry = {
      timestamp: new Date().toLocaleTimeString(),
      level,
      message,
      scanner
    };
    setLogs(prev => [...prev, newLog]);
  };

  const toScannerName = (key: ScannerKey) => {
    switch (key) {
      case 'broken_access':
        return 'Access Control';
      case 'csrf':
        return 'CSRF Protection';
      case 'sqli':
        return 'SQL Injection';
      case 'xss':
        return 'XSS Prevention';
      case 'cors':
        return 'CORS Configuration';
      case 'ssl_tls':
        return 'SSL/TLS';
      case 'combined':
        return 'Overall Report';
      default:
        return key;
    }
  };

  const getScannerDescription = (key: ScannerKey) => {
    switch (key) {
      case 'broken_access':
        return 'Checks for unauthorized access to restricted resources';
      case 'csrf':
        return 'Validates protection against cross-site request forgery';
      case 'sqli':
        return 'Tests database security against injection attacks';
      case 'xss':
        return 'Examines protection against script injection vulnerabilities';
      case 'cors':
        return 'Analyzes Cross-Origin Resource Sharing configuration';
      case 'ssl_tls':
        return 'Analyzes certificate health & protocol support';
      case 'combined':
        return 'Comprehensive security assessment summary';
      default:
        return 'Security vulnerability assessment';
    }
  };

  const toIcon = (key: ScannerKey, status: Status) => {
    if (status === 'scanning') return <Loader2 className="h-5 w-5 animate-spin" />;
    if (key === 'combined') return <FileText className="h-5 w-5" />;
    if (status === 'safe') return <CheckCircle className="h-5 w-5" />;
    if (status === 'vulnerable') return <XCircle className="h-5 w-5" />;
    if (status === 'pending') return <Clock className="h-5 w-5" />;
    return <AlertTriangle className="h-5 w-5" />;
  };

  const handleScan = async () => {
    if (!url) return;
    
    setIsScanning(true);
    setScanProgress(0);
    setResults(null);
    setCombinedLink(null);
    setLogs([]);
    setActiveTab('scan');

    addLog('info', `Security scan initiated for ${url}`);
    addLog('info', 'Preparing security assessment modules...');

    // Real-time progress tracking
    const scanStartTime = Date.now();
    let progressValue = 10;
    setScanProgress(10);
    
    // Update progress more realistically
    const progressInterval = setInterval(() => {
      if (progressValue < 90) {
        progressValue += Math.random() * 10; // Vary progress increments
        setScanProgress(Math.min(progressValue, 90));
        
        // Add context-aware log messages
        const elapsed = (Date.now() - scanStartTime) / 1000;
        if (elapsed > 3 && elapsed < 8) {
          setCurrentScanner('Crawling website...');
          addLog('info', 'Discovering website structure and endpoints...');
        } else if (elapsed > 10 && elapsed < 15) {
          setCurrentScanner('Analyzing forms...');
          addLog('info', 'Analyzing forms and input validation...');
        } else if (elapsed > 18 && elapsed < 25) {
          setCurrentScanner('Testing vulnerabilities...');
          addLog('info', 'Running security vulnerability tests...');
        } else if (elapsed > 28 && elapsed < 35) {
          setCurrentScanner('Generating reports...');
          addLog('info', 'Compiling security assessment reports...');
        }
      }
    }, 3000); // Update every 3 seconds for more realistic timing

    try {
      addLog('info', 'Connecting to security scanner backend...');
      setCurrentScanner('Initializing scan...');
      
      const res = await fetch(`${apiBase}/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url, depth: scanDepth }),
      });
      
      if (!res.ok) {
        throw new Error(`HTTP ${res.status}: ${res.statusText}`);
      }
      
      const data = (await res.json()) as ApiResponse;

      clearInterval(progressInterval);
      setScanProgress(100);
      setCurrentScanner('');
      
      addLog('success', 'Backend processing completed successfully');
      addLog('info', 'Processing scan results...');

      // Build UI results with enhanced stats
  const scanners: ScannerKey[] = ['broken_access', 'csrf', 'sqli', 'xss', 'cors', 'ssl_tls', 'combined'];
      const ui: UiScannerResult[] = scanners.map((key) => {
  const out = data.outputs?.[key];
  const err = data.errors?.[key as 'broken_access' | 'csrf' | 'sqli' | 'xss' | 'cors' | 'ssl_tls'];
        const hasReport = !!out?.web_html || !!out?.web_json || !!out?.web_pdf;
        
        let status: Status = 'safe';
        let details = '';
        
        if (err) {
          status = 'warning';
          details = 'Scan encountered issues. Check logs for details.';
          addLog('error', `${toScannerName(key)} scan failed: ${err}`, key);
        } else if (hasReport) {
          const vulnCount = out?.vulnerabilities_found || 0;
          if (vulnCount > 0) {
            status = vulnCount > 3 ? 'vulnerable' : 'warning';
            details = `Found ${vulnCount} potential ${vulnCount === 1 ? 'vulnerability' : 'vulnerabilities'}. Review required.`;
          } else {
            status = 'safe';
            details = 'No significant vulnerabilities detected. Good security posture.';
          }
          addLog('success', `${toScannerName(key)}: ${details}`, key);
        } else {
          status = 'warning';
          details = 'Scan completed but no report generated.';
        }

  return {
          key,
          name: toScannerName(key),
          status,
          details,
          icon: toIcon(key, status),
          links: {
            html: out?.web_html ? `${apiBase}${out.web_html}` : undefined,
            pdf: out?.web_pdf ? `${apiBase}${out.web_pdf}` : undefined,
            json: out?.web_json ? `${apiBase}${out.web_json}` : undefined,
            exploited: out?.web_html_exploited ? `${apiBase}${out.web_html_exploited}` : undefined,
          },
          error: err,
          stats: {
            vulnerabilities: out?.vulnerabilities_found,
            links: out?.links_crawled,
            forms: out?.forms_found,
            duration: out?.scan_duration,
      cvss_max: out?.cvss_max,
      cvss_avg: out?.cvss_avg,
      cvss_count: out?.cvss_count,
  cvss_findings: out?.cvss_findings,
          },
      summary_text: out?.summary_text,
      protocol_support: out?.protocol_support,
      certificate: out?.certificate,
        };
      });

      const combined = data.outputs?.combined;
      if (combined?.web_html) {
        setCombinedLink(`${apiBase}${combined.web_html}`);
        addLog('success', 'Combined security report generated');
      }

      setResults(ui);
      addLog('success', 'All security assessments completed successfully');
      setActiveTab('results');
      
    } catch (e: unknown) {
      clearInterval(progressInterval);
      setScanProgress(0);
      const msg = e instanceof Error ? e.message : 'Unknown error';
      addLog('error', `Scan failed: ${msg}`);
      setResults([
        {
          key: 'combined',
          name: 'Scan Error',
          status: 'warning',
          details: msg || 'Failed to contact security scanner backend',
          icon: <AlertTriangle className="h-5 w-5" />,
        },
      ]);
      setActiveTab('results');
    } finally {
      clearInterval(progressInterval);
      setIsScanning(false);
      setCurrentScanner('');
      setScanProgress(100);
    }
  };

  const getStatusColor = (status: Status) => {
    switch (status) {
      case 'safe':
        return 'text-green-600';
      case 'info':
        return 'text-blue-600';
      case 'warning':
        return 'text-yellow-600';
      case 'vulnerable':
        return 'text-red-600';
      case 'scanning':
        return 'text-blue-500';
      case 'pending':
        return 'text-gray-500';
      default:
        return 'text-gray-600';
    }
  };

  const getStatusBg = (status: Status) => {
    switch (status) {
      case 'safe':
        return 'bg-green-50 border-green-200 hover:bg-green-100';
      case 'info':
        return 'bg-blue-50 border-blue-200 hover:bg-blue-100';
      case 'warning':
        return 'bg-yellow-50 border-yellow-200 hover:bg-yellow-100';
      case 'vulnerable':
        return 'bg-red-50 border-red-200 hover:bg-red-100';
      case 'scanning':
        return 'bg-blue-50 border-blue-200';
      case 'pending':
        return 'bg-gray-50 border-gray-200';
      default:
        return 'bg-gray-50 border-gray-200';
    }
  };

  const getLogIcon = (level: LogEntry['level']) => {
    switch (level) {
      case 'success':
        return <CheckCircle className="h-4 w-4 text-green-500" />;
      case 'error':
        return <XCircle className="h-4 w-4 text-red-500" />;
      case 'warning':
        return <AlertTriangle className="h-4 w-4 text-yellow-500" />;
      default:
        return <Activity className="h-4 w-4 text-blue-500" />;
    }
  };

  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <header className="bg-gradient-to-r from-blue-600 to-purple-700 shadow-lg">
        <div className="container mx-auto px-4 py-8">
          <div className="flex items-center justify-center gap-3 mb-2">
            <Shield className="h-8 w-8 text-white" />
            <h1 className="text-4xl font-bold text-white">
              B-Secure Scanner
            </h1>
            <Lock className="h-8 w-8 text-white" />
          </div>
          <p className="text-center text-white/90 text-lg">
            Professional web application security assessment platform
          </p>
        </div>
      </header>

      <div className="container mx-auto px-4 py-8 max-w-6xl">
        {/* Scan Input Section */}
        <Card className="mb-6 shadow-lg border-0 bg-gradient-to-r from-white to-gray-50">
          <CardHeader className="text-center">
            <CardTitle className="text-2xl text-gray-800 flex items-center justify-center gap-2">
              <Globe className="h-6 w-6 text-blue-600" />
              Target Configuration
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex gap-4">
              <Input
                type="url"
                placeholder="https://example.com"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                className="flex-1 text-lg h-12 border-gray-300 focus:border-blue-500"
                disabled={isScanning}
              />
              <select
                value={scanDepth}
                onChange={(e) => setScanDepth(Number(e.target.value))}
                className="px-3 h-12 border border-gray-300 rounded-md bg-white text-sm"
                disabled={isScanning}
              >
                <option value={1}>Depth: 1 (Fast)</option>
                <option value={2}>Depth: 2 (Balanced)</option>
                <option value={3}>Depth: 3 (Thorough)</option>
              </select>
              <Button 
                onClick={handleScan}
                disabled={!url || isScanning}
                className="px-8 h-12 bg-blue-600 hover:bg-blue-700"
                size="lg"
              >
                {isScanning ? (
                  <>
                    <Loader2 className="mr-2 h-5 w-5 animate-spin" />
                    Scanning...
                  </>
                ) : (
                  <>
                    <Shield className="mr-2 h-5 w-5" />
                    Start Assessment
                  </>
                )}
              </Button>
            </div>
            
            {isScanning && (
              <div className="space-y-3">
                <div className="flex justify-between text-sm text-gray-600">
                  <span>Security Assessment Progress</span>
                  <span>{scanProgress.toFixed(1)}%</span>
                </div>
                <Progress value={scanProgress} className="h-3" />
                {currentScanner && (
                  <div className="flex items-center gap-2 text-sm text-blue-600">
                    <Loader2 className="h-4 w-4 animate-spin" />
                    <span>Currently scanning: {currentScanner}</span>
                  </div>
                )}
              </div>
            )}
          </CardContent>
        </Card>

        {/* Main Content Tabs */}
        <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-6">
          <TabsList className="grid w-full grid-cols-2">
            <TabsTrigger value="scan" className="text-sm">
              <Eye className="h-4 w-4 mr-2" />
              Live Monitor
            </TabsTrigger>
            <TabsTrigger value="results" className="text-sm">
              <Bug className="h-4 w-4 mr-2" />
              Security Results
            </TabsTrigger>
          </TabsList>

          <TabsContent value="scan" className="space-y-4">
            <Card className="shadow-lg">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Activity className="h-5 w-5 text-blue-600" />
                  Scanning Activity Log
                </CardTitle>
              </CardHeader>
              <CardContent>
                <ScrollArea className="h-96 w-full">
                  <div className="space-y-2">
                    {logs.length === 0 && (
                      <div className="text-center text-gray-500 py-8">
                        <Activity className="h-8 w-8 mx-auto mb-2 opacity-50" />
                        <p>Scan logs will appear here when you start an assessment</p>
                      </div>
                    )}
                    {logs.map((log, index) => (
                      <div key={index} className="flex items-start gap-3 p-3 rounded-lg bg-gray-50 hover:bg-gray-100 transition-colors">
                        {getLogIcon(log.level)}
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 mb-1">
                            <span className="text-xs text-gray-500 font-mono">
                              {log.timestamp}
                            </span>
                            {log.scanner && (
                              <Badge variant="outline" className="text-xs">
                                {log.scanner}
                              </Badge>
                            )}
                          </div>
                          <p className="text-sm text-gray-700">{log.message}</p>
                        </div>
                      </div>
                    ))}
                    <div ref={logsEndRef} />
                  </div>
                </ScrollArea>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="results" className="space-y-6">
            {results && (
              <>
                <div className="text-center mb-6">
                  <h2 className="text-3xl font-bold text-gray-800 mb-3">Security Assessment Report</h2>
                  <p className="text-gray-600 mb-4">
                    Target: <span className="font-mono text-blue-600 bg-blue-50 px-3 py-1 rounded">{url}</span>
                  </p>
                  {combinedLink && (
                    <div className="flex justify-center gap-2 mb-4">
                      <Button asChild variant="outline">
                        <a href={combinedLink} target="_blank" rel="noreferrer">
                          <FileText className="h-4 w-4 mr-2" />
                          View Combined Report
                        </a>
                      </Button>
                      {results?.find(r=>r.key==='combined' && r.links?.pdf) && (
                        <Button asChild variant="outline">
                          <a href={results.find(r=>r.key==='combined')!.links!.pdf} target="_blank" rel="noreferrer">
                            <FileDown className="h-4 w-4 mr-2" />
                            Download PDF
                          </a>
                        </Button>
                      )}
                    </div>
                  )}
                </div>

                <div className="grid gap-6 md:grid-cols-2">
                  {results.filter(r=>r.key!=='combined').map((result) => (
                    <Card
                      key={result.key}
                      className={`shadow-lg border-2 transition-all duration-300 hover:shadow-xl hover:scale-[1.02] ${getStatusBg(result.status)}`}
                    >
                      <CardHeader className="pb-3">
                        <CardTitle className="flex items-center gap-3 text-lg">
                          <div className={getStatusColor(result.status)}>
                            {result.icon}
                          </div>
                          <div className="flex-1">
                            <div className="font-semibold">{result.name}</div>
                            <div className="text-sm text-gray-600 font-normal">
                              {getScannerDescription(result.key)}
                            </div>
                          </div>
                        </CardTitle>
                      </CardHeader>
                      <CardContent className="space-y-4">
                        <p className="text-gray-700 leading-relaxed">
                          {result.details}
                        </p>

                        {/* Stats */}
                        {result.stats && (
                          <div className="grid grid-cols-2 gap-2 text-xs">
                            {result.stats.vulnerabilities !== undefined && (
                              <div className="bg-white/50 p-2 rounded">
                                <div className="font-semibold text-gray-600">Vulnerabilities</div>
                                <div className="text-lg font-bold text-red-600">
                                  {result.stats.vulnerabilities}
                                </div>
                              </div>
                            )}
                            {result.stats.links !== undefined && (
                              <div className="bg-white/50 p-2 rounded">
                                <div className="font-semibold text-gray-600">Links Crawled</div>
                                <div className="text-lg font-bold text-blue-600">
                                  {result.stats.links}
                                </div>
                              </div>
                            )}
                            {result.stats.cvss_max !== undefined && (
                              <div className="bg-white/50 p-2 rounded col-span-2">
                                <div className="flex justify-between items-center">
                                  <div className="font-semibold text-gray-600">CVSS</div>
                                  <div className="flex gap-3 text-sm">
                                    <span className="text-gray-700">Max: <span className="font-bold text-red-600">{result.stats.cvss_max?.toFixed(1)}</span></span>
                                    <span className="text-gray-700">Avg: <span className="font-bold text-orange-600">{result.stats.cvss_avg?.toFixed(1)}</span></span>
                                    <span className="text-gray-700">Findings: <span className="font-bold text-blue-600">{result.stats.cvss_count}</span></span>
                                  </div>
                                </div>
                                <div className="w-full h-2 bg-gray-200 rounded mt-2 overflow-hidden">
                                  <div className="h-full bg-gradient-to-r from-green-500 via-yellow-400 to-red-600" style={{width: `${(Math.min(result.stats.cvss_max||0,10)/10)*100}%`}} />
                                </div>
                              </div>
                            )}
                          </div>
                        )}

                        {/* CVSS Findings List */}
                        {result.stats?.cvss_findings && result.stats.cvss_findings.length > 0 && (
                          <div className="mt-2">
                            <div className="text-xs font-semibold text-gray-600 mb-1">Top Findings (CVSS)</div>
                            <div className="space-y-1 max-h-32 overflow-y-auto pr-1">
                              {result.stats.cvss_findings.slice(0,5).map((f,i)=>(
                                <div key={i} className="flex items-center justify-between bg-white/60 rounded px-2 py-1 text-[11px]">
                                  <span className="truncate max-w-[70%]" title={f.issue}>{f.issue || 'Finding'}</span>
                                  <span className="font-mono text-gray-700">{f.cvss?.toFixed(1)}</span>
                                </div>
                              ))}
                            </div>
                          </div>
                        )}

                        {/* Action Links */}
                        {result.links && (
                          <div className="flex flex-wrap gap-2">
                            {result.links.html && (
                              <Button asChild variant="outline" size="sm">
                                <a href={result.links.html} target="_blank" rel="noreferrer">
                                  <FileText className="h-3 w-3 mr-1" />
                                  View Report
                                </a>
                              </Button>
                            )}
                            {result.links.pdf && (
                              <Button asChild variant="outline" size="sm">
                                <a href={result.links.pdf} target="_blank" rel="noreferrer">
                                  <FileDown className="h-3 w-3 mr-1" />
                                  PDF
                                </a>
                              </Button>
                            )}
                            {result.links.json && (
                              <Button asChild variant="outline" size="sm">
                                <a href={result.links.json} target="_blank" rel="noreferrer">
                                  <FileJson className="h-3 w-3 mr-1" />
                                  Raw Data
                                </a>
                              </Button>
                            )}
                          </div>
                        )}

                        {/* Status Badge */}
                        <div className="flex justify-between items-center">
                          <Badge 
                            variant={result.status === 'safe' ? 'default' : result.status === 'vulnerable' ? 'destructive' : 'secondary'}
                            className="font-medium"
                          >
                            {result.status === 'safe' ? 'SECURE' 
                             : result.status === 'vulnerable' ? 'HIGH RISK'
                             : result.status === 'warning' ? 'NEEDS ATTENTION'
                             : 'COMPLETED'}
                          </Badge>
                        </div>

                        {result.error && (
                          <div className="mt-3 p-3 bg-red-50 border border-red-200 rounded text-sm text-red-700">
                            <strong>Error:</strong> {result.error}
                          </div>
                        )}

                        {/* SSL/TLS extra details inside its card */}
                        {result.key === 'ssl_tls' && result.stats && (
                          <div className="space-y-3">
                            {result.summary_text && <p className="text-sm text-gray-700">{result.summary_text}</p>}
                            {result.protocol_support && (
                              <div>
                                <div className="font-semibold text-xs mb-1">Protocol Support</div>
                                <div className="grid grid-cols-2 gap-1 text-xs">
                                  {Object.entries(result.protocol_support).map(([p,v]) => (
                                    <div key={p} className="flex justify-between bg-white/50 px-2 py-1 rounded"><span>{p}</span><span>{v? '✅':'❌'}</span></div>
                                  ))}
                                </div>
                              </div>
                            )}
                            {result.certificate && (
                              <details className="text-xs">
                                <summary className="cursor-pointer font-medium">Certificate Details</summary>
                                <pre className="mt-1 p-2 bg-gray-100 rounded max-h-48 overflow-y-auto whitespace-pre-wrap">{JSON.stringify(result.certificate,null,2)}</pre>
                              </details>
                            )}
                          </div>
                        )}
                      </CardContent>
                    </Card>
                  ))}
                </div>

                {/* SSL/TLS extra details inside its card */}
              </>
            )}

            {!results && !isScanning && (
              <Card className="shadow-lg">
                <CardContent className="pt-6">
                  <div className="text-center text-gray-500 py-12">
                    <Shield className="h-16 w-16 mx-auto mb-4 opacity-30" />
                    <h3 className="text-xl font-semibold mb-2">Ready for Security Assessment</h3>
                    <p>Enter a target URL and click "Start Assessment" to begin your security scan</p>
                  </div>
                </CardContent>
              </Card>
            )}
          </TabsContent>
        </Tabs>
      </div>
    </div>
  );
};

export default EnhancedSecurityScanner;
