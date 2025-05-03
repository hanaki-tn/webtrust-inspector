import { useState } from 'react'
import './App.css'
import { Button } from './components/ui/button'
import { Input } from './components/ui/input'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from './components/ui/card'
import { Alert, AlertDescription } from './components/ui/alert'
import { Separator } from './components/ui/separator'

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

interface AnalysisResult {
  status: string;
  message: string;
  domain?: string;
  whois?: WhoisResult;
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
