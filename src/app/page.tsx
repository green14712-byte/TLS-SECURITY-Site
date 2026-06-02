'use client'

import { useState } from 'react'

type CertificateInfo = {
  subject?: Record<string, string | string[]>
  issuer?: Record<string, string | string[]>
  valid_from?: string
  valid_to?: string
  subjectaltname?: string
  fingerprint?: string
}

type CheckResult = {
  success: boolean
  url?: string
  hostname?: string
  message?: string
  certificate?: CertificateInfo
  analysis?: {
    score: number
    status: '안전' | '주의' | '위험'
    reasons: string[]
  }
}

export default function Home() {
  const [url, setUrl] = useState('')
  const [result, setResult] = useState<CheckResult | null>(null)
  const [loading, setLoading] = useState(false)

  const handleCheck = async () => {
    if (!url.trim()) {
      setResult({
        success: false,
        message: 'URL을 입력하세요.',
      })
      return
    }

    try {
      setLoading(true)

      const res = await fetch('/api/check', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ url }),
      })

      const data = await res.json()
      setResult(data)
    } catch (error) {
      console.error(error)

      setResult({
        success: false,
        message: '검사 중 오류가 발생했습니다.',
      })
    } finally {
      setLoading(false)
    }
  }

  const getStringValue = (value?: string | string[]) => {
    if (!value) return '정보 없음'
    if (Array.isArray(value)) return value.join(', ')
    return value
  }

  const getSanList = (subjectaltname?: string) => {
    if (!subjectaltname) return []

    return subjectaltname
      .split(',')
      .map((item) => item.trim().replace(/^DNS:/, ''))
      .filter(Boolean)
  }

  const formatDate = (date?: string) => {
    if (!date) return '정보 없음'

    const parsedDate = new Date(date)

    if (Number.isNaN(parsedDate.getTime())) {
      return date
    }

    return parsedDate.toLocaleString('ko-KR', {
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
    })
  }

  const getStatusColor = (status?: string) => {
    if (status === '안전') return 'text-green-400'
    if (status === '주의') return 'text-yellow-400'
    if (status === '위험') return 'text-red-400'
    return 'text-gray-300'
  }

  const certificate = result?.certificate
  const sanList = getSanList(certificate?.subjectaltname)
  const visibleSanList = sanList.slice(0, 8)

  return (
    <main className="min-h-screen bg-black px-6 py-10 text-white">
      <section className="mx-auto max-w-5xl">
        <h1 className="mb-4 text-4xl font-bold">
          TLS/인증서 기반 피싱 사이트 탐지 시스템
        </h1>

        <p className="mb-8 text-gray-300">
          검사할 웹사이트 URL을 입력하면 URL 구조와 TLS 인증서 정보를
          분석합니다.
        </p>

        <div className="rounded-2xl border border-zinc-700 bg-zinc-900 p-6">
          <label className="mb-2 block text-sm text-gray-300">검사할 URL</label>

          <input
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://example.com"
            className="w-full rounded-xl border border-zinc-600 bg-black px-4 py-3 text-white outline-none focus:ring-2 focus:ring-blue-500"
          />

          <button
            onClick={handleCheck}
            disabled={loading}
            className="mt-4 rounded-xl bg-blue-600 px-5 py-3 font-semibold text-white transition-all hover:scale-105 hover:bg-blue-700 active:scale-95 disabled:opacity-50"
          >
            {loading ? '검사 중...' : '검사하기'}
          </button>
        </div>

        <div className="mt-6 rounded-2xl border border-zinc-700 bg-zinc-900 p-6">
          <h2 className="mb-4 text-2xl font-bold">검사 결과</h2>

          {!result ? (
            <p className="text-gray-400">아직 검사 결과가 없습니다.</p>
          ) : (
            <div className="space-y-4">
              <p>
                성공 여부:{' '}
                <span
                  className={result.success ? 'text-green-400' : 'text-red-400'}
                >
                  {result.success ? '성공' : '실패'}
                </span>
              </p>

              {result.message && (
                <p className="text-gray-300">메시지: {result.message}</p>
              )}

              {result.url && <p>입력 URL: {result.url}</p>}

              {result.hostname && <p>호스트명: {result.hostname}</p>}

              {result.analysis && (
                <div className="rounded-xl border border-zinc-700 bg-black p-4">
                  <h3 className="mb-3 text-lg font-bold text-white">
                    위험도 분석 결과
                  </h3>

                  <p>
                    최종 판정:{' '}
                    <span
                      className={`font-bold ${getStatusColor(
                        result.analysis.status,
                      )}`}
                    >
                      {result.analysis.status}
                    </span>
                  </p>

                  <p>위험도 점수: {result.analysis.score}점</p>

                  <div className="mt-3">
                    <p className="mb-1 font-semibold">판단 이유</p>
                    <ul className="list-disc space-y-1 pl-5 text-gray-300">
                      {result.analysis.reasons.map((reason, index) => (
                        <li key={index}>{reason}</li>
                      ))}
                    </ul>
                  </div>
                </div>
              )}

              {certificate && (
                <div className="rounded-xl border border-zinc-700 bg-black p-5">
                  <h3 className="mb-4 text-xl font-bold text-white">
                    TLS 인증서 정보
                  </h3>

                  <div className="grid gap-4 md:grid-cols-2">
                    <InfoCard
                      title="인증서 대상"
                      value={getStringValue(certificate.subject?.CN)}
                      description="이 인증서가 발급된 도메인입니다."
                    />

                    <InfoCard
                      title="발급 기관"
                      value={getStringValue(certificate.issuer?.CN)}
                      description={getStringValue(certificate.issuer?.O)}
                    />

                    <InfoCard
                      title="유효 시작일"
                      value={formatDate(certificate.valid_from)}
                      description="인증서가 사용 가능해진 시점입니다."
                    />

                    <InfoCard
                      title="유효 만료일"
                      value={formatDate(certificate.valid_to)}
                      description="이 날짜가 지나면 인증서는 만료됩니다."
                    />

                    <InfoCard
                      title="SAN 도메인 개수"
                      value={`${sanList.length}개`}
                      description="인증서가 허용하는 도메인 목록 개수입니다."
                    />

                    <InfoCard
                      title="Fingerprint"
                      value={certificate.fingerprint || '정보 없음'}
                      description="인증서를 구분하는 고유 지문값입니다."
                    />
                  </div>

                  <div className="mt-5 rounded-xl border border-zinc-700 bg-zinc-950 p-4">
                    <h4 className="mb-3 font-bold text-white">
                      인증서에 포함된 주요 도메인
                    </h4>

                    {visibleSanList.length === 0 ? (
                      <p className="text-gray-400">SAN 정보가 없습니다.</p>
                    ) : (
                      <div className="flex flex-wrap gap-2">
                        {visibleSanList.map((name) => (
                          <span
                            key={name}
                            className="rounded-full border border-zinc-600 px-3 py-1 text-sm text-gray-300"
                          >
                            {name}
                          </span>
                        ))}
                      </div>
                    )}

                    {sanList.length > visibleSanList.length && (
                      <p className="mt-3 text-sm text-gray-400">
                        외 {sanList.length - visibleSanList.length}개 도메인이
                        더 포함되어 있습니다.
                      </p>
                    )}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      </section>
    </main>
  )
}

function InfoCard({
  title,
  value,
  description,
}: {
  title: string
  value: string
  description: string
}) {
  return (
    <div className="rounded-xl border border-zinc-700 bg-zinc-950 p-4">
      <p className="mb-1 text-sm text-gray-400">{title}</p>
      <p className="break-all text-lg font-semibold text-white">{value}</p>
      <p className="mt-2 text-sm text-gray-500">{description}</p>
    </div>
  )
}
