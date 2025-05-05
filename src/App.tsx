import { useState } from 'react'
import './App.css'
import { Button } from './components/ui/button'
import { Input } from './components/ui/input'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from './components/ui/card'
import { Alert, AlertDescription } from './components/ui/alert'
import { Separator } from './components/ui/separator'
import { Shield, ShieldAlert, ShieldCheck } from 'lucide-react'

interface WhoisResult {
  domain_name?: string | string[];
  registrar?: string;
  whois_server?: string;
  referral_url?: string;
  updated_date?: string | string[];
  creation_date?: string | string[];
  expiration_date?: string | string[];
  name_servers?: string | string[];
  status?: string | string[];
  emails?: string | string[];
  dnssec?: string;
  name?: string;
  org?: string;
  address?: string;
  city?: string;
  state?: string;
  zipcode?: string;
  country?: string;
  [key: string]: any;
}

interface CertificateInfo {
  common_name?: string;
  issuer?: {
    common_name?: string;
    organization?: string;
    country?: string;
  };
  valid_from?: string;
  valid_to?: string;
  subject_alt_names?: string[];
  error?: string;
}

interface AnalysisResult {
  status: string;
  message: string;
  domain?: string;
  whois?: WhoisResult;
  threat?: boolean;
  threat_types?: string[];
  safety_error?: string;
  certificate?: CertificateInfo;
}

function App() {
  const [url, setUrl] = useState('')
  const [result, setResult] = useState<AnalysisResult | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    setError(null)
    
    try {
      const apiUrl = import.meta.env.VITE_API_URL || 'http://localhost:8000'
      const response = await fetch(`${apiUrl}/analyze`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ url }),
      })
      
      if (!response.ok) {
        throw new Error(`エラーが発生しました: ${response.status}`)
      }
      
      const data = await response.json()
      setResult(data)
    } catch (err) {
      setError(err instanceof Error ? err.message : '不明なエラーが発生しました')
    } finally {
      setLoading(false)
    }
  }

  const formatValue = (value: any): string => {
    if (Array.isArray(value)) {
      return value.join(', ')
    } else if (value === null || value === undefined) {
      return '情報なし'
    } else {
      return String(value)
    }
  }

  const translateThreatType = (threatType: string): string => {
    const threatTypes: Record<string, string> = {
      'MALWARE': 'マルウェア',
      'SOCIAL_ENGINEERING': 'ソーシャルエンジニアリング',
      'UNWANTED_SOFTWARE': '不要なソフトウェア',
      'POTENTIALLY_HARMFUL_APPLICATION': '潜在的に有害なアプリケーション'
    }
    return threatTypes[threatType] || threatType
  }

  const renderSafetyInfo = () => {
    if (result?.safety_error) {
      return (
        <Alert className="mt-4 bg-yellow-50 border-yellow-200">
          <Shield className="h-4 w-4 text-yellow-600" />
          <AlertDescription className="text-yellow-800">
            安全性の確認中にエラーが発生しました: {result.safety_error}
          </AlertDescription>
        </Alert>
      )
    }

    if (result?.threat === undefined) return null

    if (result.threat) {
      return (
        <Alert className="mt-4 bg-red-50 border-red-200">
          <ShieldAlert className="h-4 w-4 text-red-600" />
          <div className="ml-2">
            <h4 className="font-medium text-red-800">危険なサイトの可能性があります</h4>
            {result.threat_types && result.threat_types.length > 0 && (
              <div className="mt-1 text-sm text-red-700">
                <p>検出された脅威:</p>
                <ul className="list-disc pl-5 mt-1">
                  {result.threat_types.map((type, index) => (
                    <li key={index}>{translateThreatType(type)}</li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        </Alert>
      )
    } else {
      return (
        <Alert className="mt-4 bg-green-50 border-green-200">
          <ShieldCheck className="h-4 w-4 text-green-600" />
          <AlertDescription className="text-green-800">
            このサイトは安全です。脅威は検出されませんでした。
          </AlertDescription>
        </Alert>
      )
    }
  }

  const renderCertificateInfo = () => {
    if (!result?.certificate) return null
    
    const cert = result.certificate
    
    if (cert.error) {
      return (
        <div className="mt-4">
          <h3 className="font-medium mb-2">SSL/TLS証明書情報:</h3>
          <Alert className="bg-yellow-50 border-yellow-200">
            <AlertDescription className="text-yellow-800">
              {cert.error}
            </AlertDescription>
          </Alert>
        </div>
      )
    }
    
    const formatDate = (dateStr?: string) => {
      if (!dateStr) return '情報なし'
      try {
        const date = new Date(dateStr)
        return date.toLocaleString('ja-JP', {
          year: 'numeric',
          month: 'long',
          day: 'numeric',
          hour: '2-digit',
          minute: '2-digit'
        })
      } catch (e) {
        return dateStr
      }
    }
    
    return (
      <div className="mt-4">
        <h3 className="font-medium mb-2">SSL/TLS証明書情報:</h3>
        <div className="text-sm space-y-2">
          <div className="grid grid-cols-3 gap-2">
            <div className="font-medium">コモンネーム (CN):</div>
            <div className="col-span-2">{cert.common_name || '情報なし'}</div>
          </div>
          
          <div className="grid grid-cols-3 gap-2">
            <div className="font-medium">発行者:</div>
            <div className="col-span-2">
              {cert.issuer ? (
                <>
                  {cert.issuer.organization && <div>組織: {cert.issuer.organization}</div>}
                  {cert.issuer.common_name && <div>名前: {cert.issuer.common_name}</div>}
                  {cert.issuer.country && <div>国: {cert.issuer.country}</div>}
                </>
              ) : '情報なし'}
            </div>
          </div>
          
          <div className="grid grid-cols-3 gap-2">
            <div className="font-medium">有効期間開始:</div>
            <div className="col-span-2">{formatDate(cert.valid_from)}</div>
          </div>
          
          <div className="grid grid-cols-3 gap-2">
            <div className="font-medium">有効期間終了:</div>
            <div className="col-span-2">{formatDate(cert.valid_to)}</div>
          </div>
          
          {cert.subject_alt_names && cert.subject_alt_names.length > 0 && (
            <div className="grid grid-cols-3 gap-2">
              <div className="font-medium">代替名 (SANs):</div>
              <div className="col-span-2">
                {cert.subject_alt_names.join(', ')}
              </div>
            </div>
          )}
        </div>
      </div>
    )
  }

  const renderWhoisInfo = () => {
    if (!result?.whois) return null

    const whoisData = result.whois
    
    const mainFields = [
      { label: 'ドメイン名', key: 'domain_name' },
      { label: 'レジストラ', key: 'registrar' },
      { label: '作成日', key: 'creation_date' },
      { label: '有効期限', key: 'expiration_date' },
      { label: '最終更新日', key: 'updated_date' },
      { label: 'ネームサーバー', key: 'name_servers' },
      { label: 'ステータス', key: 'status' },
      { label: '組織名', key: 'org' },
      { label: '国', key: 'country' }
    ]

    return (
      <div className="mt-4">
        <h3 className="font-medium mb-2">WHOIS情報:</h3>
        <div className="text-sm space-y-2">
          {mainFields.map((field) => (
            whoisData[field.key] && (
              <div key={field.key} className="grid grid-cols-3 gap-2">
                <div className="font-medium">{field.label}:</div>
                <div className="col-span-2">{formatValue(whoisData[field.key])}</div>
              </div>
            )
          ))}
        </div>
      </div>
    )
  }

  return (
    <div className="container mx-auto py-10 px-4">
      <Card className="max-w-2xl mx-auto">
        <CardHeader>
          <CardTitle className="text-2xl">WebTrust URL分析</CardTitle>
          <CardDescription>分析したいURLを入力してください</CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="space-y-2">
              <Input
                type="url"
                placeholder="https://example.com"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                required
                className="w-full"
              />
            </div>
            <Button type="submit" className="w-full" disabled={loading}>
              {loading ? '分析中...' : 'チェック'}
            </Button>
          </form>
          
          {error && (
            <Alert variant="destructive" className="mt-4">
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          )}
          
          {result && (
            <div className="mt-4 p-4 border rounded-md bg-slate-50">
              <h3 className="font-medium mb-2">分析結果:</h3>
              <p>{result.message}</p>
              
              {result.domain && (
                <div className="mt-2">
                  <p><span className="font-medium">ドメイン:</span> {result.domain}</p>
                </div>
              )}
              
              {renderSafetyInfo()}
              
              {result.certificate && (
                <>
                  <Separator className="my-4" />
                  {renderCertificateInfo()}
                </>
              )}
              
              {result.whois && (
                <>
                  <Separator className="my-4" />
                  {renderWhoisInfo()}
                </>
              )}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}

export default App
