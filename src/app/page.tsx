'use client'

import { useEffect, useState } from 'react'

type RiskStatus = '낮은 위험' | '주의 필요' | '높은 위험' | '매우 위험'

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
  certificate?: CertificateInfo | null
  caChain?: {
    checked: boolean
    authorized: boolean
    error?: string
  }
  trustEvaluation?: {
    status: '신뢰 가능' | '주의 필요' | '위험'
    organization: string
    reason: string
  }
  analysis?: {
    score: number
    status: RiskStatus
    reasons: string[]
  }
  securityGrade?: {
    score: number
    grade: 'A+' | 'A' | 'B' | 'C' | 'D'
    status: RiskStatus
    summary: string
    details: string[]
    reasons: string[]
  }
}

type HistoryItem = {
  _id?: string
  url?: string
  hostname?: string
  checkedAt?: string
  analysis?: {
    score: number
    status: RiskStatus
  }
}

type ClassifiedSignals = {
  critical: string[]
  warning: string[]
  safe: string[]
  neutral: string[]
}

export default function Home() {
  const [url, setUrl] = useState('')
  const [result, setResult] = useState<CheckResult | null>(null)
  const [history, setHistory] = useState<HistoryItem[]>([])
  const [loading, setLoading] = useState(false)
  const [showDetails, setShowDetails] = useState(false)
  const [showAllSan, setShowAllSan] = useState(false)

  useEffect(() => {
    loadHistory()
  }, [])

  const loadHistory = async () => {
    try {
      const res = await fetch('/api/check')
      const data = await res.json()

      if (data.success && Array.isArray(data.history)) {
        setHistory(data.history)
      }
    } catch (error) {
      console.error(error)
    }
  }

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
      setShowDetails(false)
      setShowAllSan(false)

      await loadHistory()
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

  const certificate = result?.certificate
  const sanList = getSanList(certificate?.subjectaltname)
  const visibleSanList = showAllSan ? sanList : sanList.slice(0, 10)

  const riskStatus = result?.analysis?.status
  const riskScore = result?.analysis?.score ?? 0
  const reasons = result?.analysis?.reasons ?? []
  const signals = classifySignals(reasons)
  const mainRiskReasons = getMainRiskReasons(signals, riskStatus)

  return (
    <main className="min-h-screen bg-[#070A12] text-white">
      <section className="mx-auto max-w-7xl px-6 py-10">
        <div className="mb-8 rounded-3xl border border-white/10 bg-linear-to-br from-blue-950 via-zinc-950 to-black p-8 shadow-2xl">
          <p className="mb-4 inline-flex rounded-full border border-blue-400/30 bg-blue-500/10 px-4 py-2 text-sm text-blue-200">
            TLS Security Analyzer
          </p>

          <h1 className="text-4xl font-extrabold tracking-tight md:text-5xl">
            TLS/인증서 기반 피싱 사이트 탐지 시스템
          </h1>

          <p className="mt-4 max-w-3xl text-lg text-gray-300">
            URL 구조, 브랜드 위장, SSRF 방어, TLS 인증서, CA 체인, WHOIS/RDAP,
            Safe Browsing, 콘텐츠를 종합 분석하여 위험 신호를 평가합니다.
          </p>
        </div>

        <div className="grid gap-6 lg:grid-cols-[1.25fr_0.75fr]">
          <div className="rounded-3xl border border-white/10 bg-zinc-950 p-6 shadow-xl">
            <label className="mb-3 block text-sm font-semibold text-gray-300">
              검사할 URL
            </label>

            <div className="flex flex-col gap-3 md:flex-row">
              <input
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') handleCheck()
                }}
                placeholder="https://example.com"
                className="flex-1 rounded-2xl border border-zinc-700 bg-black px-5 py-4 text-white outline-none transition focus:border-blue-400 focus:ring-2 focus:ring-blue-500/40"
              />

              <button
                onClick={handleCheck}
                disabled={loading}
                className="rounded-2xl bg-blue-600 px-7 py-4 font-bold text-white shadow-lg shadow-blue-600/20 transition hover:bg-blue-500 disabled:cursor-not-allowed disabled:opacity-50"
              >
                {loading ? '분석 중...' : '검사하기'}
              </button>
            </div>

            <div className="mt-4 flex flex-wrap gap-2 text-sm">
              {[
                'https://www.google.com',
                'https://testsafebrowsing.appspot.com/s/malware.html',
                'https://g00gle.com',
                'https://wrong.host.badssl.com',
                'https://self-signed.badssl.com',
              ].map((sample) => (
                <button
                  key={sample}
                  onClick={() => setUrl(sample)}
                  className="rounded-full border border-zinc-700 px-3 py-1 text-gray-300 hover:border-blue-400 hover:text-blue-300"
                >
                  {sample}
                </button>
              ))}
            </div>
          </div>

          <div className="rounded-3xl border border-white/10 bg-zinc-950 p-6 shadow-xl">
            <h2 className="mb-4 text-xl font-bold">판정 기준</h2>

            <div className="space-y-3">
              <LegendItem
                color="bg-green-400"
                title="낮은 위험"
                range="0 ~ 19점"
              />
              <LegendItem
                color="bg-yellow-400"
                title="주의 필요"
                range="20 ~ 49점"
              />
              <LegendItem
                color="bg-orange-400"
                title="높은 위험"
                range="50 ~ 79점"
              />
              <LegendItem
                color="bg-red-500"
                title="매우 위험"
                range="80점 이상"
              />
            </div>
          </div>
        </div>

        <div className="mt-6 rounded-3xl border border-white/10 bg-zinc-950 p-6 shadow-xl">
          <h2 className="mb-5 text-2xl font-bold">검사 결과</h2>

          {!result ? (
            <div className="rounded-2xl border border-dashed border-zinc-700 bg-black p-10 text-center text-gray-400">
              아직 검사 결과가 없습니다. URL을 입력하고 검사하기를 눌러주세요.
            </div>
          ) : !result.success ? (
            <div className="rounded-3xl border border-red-500/30 bg-red-500/10 p-7 text-red-200">
              <p className="text-4xl font-extrabold">검사 실패</p>
              <p className="mt-3 text-gray-300">{result.message}</p>
            </div>
          ) : (
            <div className="space-y-6">
              <div
                className={`rounded-3xl border p-7 ${getRiskBoxStyle(riskStatus)}`}
              >
                <p className="text-sm font-medium opacity-80">최종 판정</p>

                <div className="mt-3 flex flex-col gap-4 md:flex-row md:items-end md:justify-between">
                  <div>
                    <p className="text-5xl font-extrabold">
                      {getRiskIcon(riskStatus)} {riskStatus || '분석 완료'}
                    </p>
                    <p className="mt-3 text-lg">
                      {getUserActionMessage(riskStatus)}
                    </p>
                  </div>

                  <div className="rounded-2xl bg-black/30 px-6 py-4 text-center">
                    <p className="text-sm opacity-80">위험도 점수</p>
                    <p className="text-4xl font-extrabold">{riskScore}점</p>
                  </div>
                </div>

                <div className="mt-6 h-4 overflow-hidden rounded-full bg-black/30">
                  <div
                    className="h-full rounded-full bg-current transition-all"
                    style={{ width: `${Math.min(riskScore, 100)}%` }}
                  />
                </div>
              </div>

              <ConclusionBox
                status={riskStatus}
                mainReasons={mainRiskReasons}
                safeCount={signals.safe.length}
              />

              {mainRiskReasons.length > 0 && (
                <Section title="한눈에 보는 주요 위험 원인">
                  <div className="grid gap-3">
                    {mainRiskReasons.map((reason, index) => (
                      <SignalItem
                        key={index}
                        icon="🚨"
                        color="border-red-500/30 bg-red-500/10 text-red-200"
                        text={reason}
                      />
                    ))}
                  </div>
                </Section>
              )}

              <div className="grid gap-4 md:grid-cols-3">
                <SummaryCard
                  title="보안 등급"
                  value={result.securityGrade?.grade || '정보 없음'}
                  description={
                    result.securityGrade?.summary || '평가 정보 없음'
                  }
                />

                <SummaryCard
                  title="호스트명"
                  value={result.hostname || '정보 없음'}
                  description="실제로 분석한 대상 도메인입니다."
                />

                <SummaryCard
                  title="CA 체인"
                  value={result.caChain?.authorized ? '검증 성공' : '검증 실패'}
                  description="인증서가 신뢰 가능한 경로인지 확인합니다."
                />
              </div>

              <div className="grid gap-6 lg:grid-cols-2">
                <Section title="⚠ 위험 신호">
                  {signals.critical.length === 0 &&
                  signals.warning.length === 0 ? (
                    <p className="rounded-2xl border border-green-500/20 bg-green-500/10 p-4 text-green-200">
                      강한 위험 신호는 발견되지 않았습니다.
                    </p>
                  ) : (
                    <div className="space-y-3">
                      {[...signals.critical, ...signals.warning].map(
                        (reason, index) => (
                          <SignalItem
                            key={index}
                            icon={
                              signals.critical.includes(reason) ? '🚨' : '⚠️'
                            }
                            color={
                              signals.critical.includes(reason)
                                ? 'border-red-500/30 bg-red-500/10 text-red-200'
                                : 'border-yellow-500/30 bg-yellow-500/10 text-yellow-200'
                            }
                            text={reason}
                          />
                        ),
                      )}
                    </div>
                  )}
                </Section>

                <Section title="✅ 안전 신호">
                  {signals.safe.length === 0 ? (
                    <p className="rounded-2xl border border-zinc-800 bg-zinc-950 p-4 text-gray-400">
                      표시할 안전 신호가 없습니다.
                    </p>
                  ) : (
                    <div className="space-y-3">
                      {signals.safe.map((reason, index) => (
                        <SignalItem
                          key={index}
                          icon="✅"
                          color="border-green-500/30 bg-green-500/10 text-green-200"
                          text={reason}
                        />
                      ))}
                    </div>
                  )}
                </Section>
              </div>

              <button
                onClick={() => setShowDetails((prev) => !prev)}
                className="w-full rounded-2xl border border-zinc-700 bg-black px-5 py-4 font-bold text-gray-200 hover:bg-zinc-900"
              >
                {showDetails ? '자세히 보기 접기' : '자세히 보기'}
              </button>

              {showDetails && (
                <div className="space-y-6">
                  <Section title="전체 판단 이유">
                    <div className="space-y-3">
                      {reasons.map((reason, index) => (
                        <SignalItem
                          key={index}
                          icon={getReasonIcon(reason)}
                          color={getReasonStyle(reason)}
                          text={reason}
                        />
                      ))}
                    </div>
                  </Section>

                  {signals.neutral.length > 0 && (
                    <Section title="ℹ 참고 정보">
                      <div className="space-y-3">
                        {signals.neutral.map((reason, index) => (
                          <SignalItem
                            key={index}
                            icon="ℹ️"
                            color="border-zinc-700 bg-zinc-950 text-gray-300"
                            text={reason}
                          />
                        ))}
                      </div>
                    </Section>
                  )}

                  {result.securityGrade && (
                    <Section title="종합 보안 평가 상세">
                      <div className="grid gap-4 md:grid-cols-3">
                        <InfoCard
                          title="보안 등급"
                          value={result.securityGrade.grade}
                          description={result.securityGrade.summary}
                        />

                        <InfoCard
                          title="보안 점수"
                          value={`${result.securityGrade.score}/100`}
                          description="100점에서 위험도 점수를 차감한 점수입니다."
                        />

                        <InfoCard
                          title="최종 판정"
                          value={result.securityGrade.status}
                          description="낮은 위험도 절대적 안전을 의미하지는 않습니다."
                        />
                      </div>

                      {result.securityGrade.details.length > 0 && (
                        <div className="mt-5 rounded-2xl border border-zinc-800 bg-zinc-950 p-5">
                          <h4 className="mb-3 font-bold">평가 기준 설명</h4>
                          <ul className="list-disc space-y-2 pl-5 text-gray-300">
                            {result.securityGrade.details.map(
                              (detail, index) => (
                                <li key={index}>{detail}</li>
                              ),
                            )}
                          </ul>
                        </div>
                      )}
                    </Section>
                  )}

                  <div className="grid gap-6 lg:grid-cols-2">
                    {result.trustEvaluation && (
                      <Section title="인증서 신뢰도 평가">
                        <div className="grid gap-4">
                          <InfoCard
                            title="신뢰도 판정"
                            value={result.trustEvaluation.status}
                            description={result.trustEvaluation.reason}
                          />

                          <InfoCard
                            title="확인된 발급기관"
                            value={result.trustEvaluation.organization}
                            description="인증서를 발급한 CA 기관입니다."
                          />
                        </div>
                      </Section>
                    )}

                    {result.caChain && (
                      <Section title="CA 체인 검증">
                        <div className="grid gap-4">
                          <InfoCard
                            title="체인 검증 결과"
                            value={
                              result.caChain.authorized
                                ? '검증 성공'
                                : '검증 실패'
                            }
                            description="Node.js/OpenSSL 신뢰 저장소 기준 검증 결과입니다."
                          />

                          <InfoCard
                            title="오류 사유"
                            value={result.caChain.error || '없음'}
                            description="검증 실패 시 TLS 오류 코드가 표시됩니다."
                          />
                        </div>
                      </Section>
                    )}
                  </div>

                  {certificate && (
                    <Section title="TLS 인증서 정보">
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

                      <div className="mt-5 rounded-2xl border border-zinc-800 bg-zinc-950 p-5">
                        <h4 className="mb-3 font-bold">
                          인증서에 포함된 도메인
                        </h4>

                        {visibleSanList.length === 0 ? (
                          <p className="text-gray-400">SAN 정보가 없습니다.</p>
                        ) : (
                          <div className="flex flex-wrap gap-2">
                            {visibleSanList.map((name) => (
                              <span
                                key={name}
                                className="rounded-full border border-zinc-700 bg-black px-3 py-1 text-sm text-gray-300"
                              >
                                {name}
                              </span>
                            ))}
                          </div>
                        )}

                        {sanList.length > 10 && (
                          <button
                            onClick={() => setShowAllSan((prev) => !prev)}
                            className="mt-4 rounded-xl border border-zinc-700 px-4 py-2 text-sm text-gray-200 hover:bg-zinc-800"
                          >
                            {showAllSan
                              ? 'SAN 목록 접기'
                              : `SAN 전체 보기 (${sanList.length}개)`}
                          </button>
                        )}
                      </div>
                    </Section>
                  )}
                </div>
              )}
            </div>
          )}
        </div>

        <div className="mt-6 rounded-3xl border border-white/10 bg-zinc-950 p-6 shadow-xl">
          <h2 className="mb-4 text-2xl font-bold">최근 검사 기록</h2>

          {history.length === 0 ? (
            <p className="text-gray-400">저장된 검사 기록이 없습니다.</p>
          ) : (
            <div className="grid gap-3 md:grid-cols-2">
              {history.map((item) => (
                <button
                  key={item._id || item.url}
                  onClick={() => setUrl(item.url || '')}
                  className="rounded-2xl border border-zinc-800 bg-black p-4 text-left hover:border-blue-400"
                >
                  <p className="break-all font-semibold">{item.url}</p>
                  <p className="mt-1 text-sm text-gray-400">
                    {item.hostname} · {formatDate(item.checkedAt)}
                  </p>
                  {item.analysis && (
                    <p
                      className={`mt-2 font-bold ${getStatusColor(
                        item.analysis.status,
                      )}`}
                    >
                      {item.analysis.status} / {item.analysis.score}점
                    </p>
                  )}
                </button>
              ))}
            </div>
          )}
        </div>
      </section>
    </main>
  )
}

function ConclusionBox({
  status,
  mainReasons,
  safeCount,
}: {
  status?: RiskStatus
  mainReasons: string[]
  safeCount: number
}) {
  return (
    <div className="rounded-3xl border border-white/10 bg-black p-6">
      <h3 className="mb-3 text-xl font-bold">결론</h3>

      <p className="text-gray-300">
        {getConclusionMessage(status, mainReasons, safeCount)}
      </p>
    </div>
  )
}

function Section({
  title,
  children,
}: {
  title: string
  children: React.ReactNode
}) {
  return (
    <div className="rounded-3xl border border-white/10 bg-black p-6">
      <h3 className="mb-4 text-xl font-bold">{title}</h3>
      {children}
    </div>
  )
}

function SummaryCard({
  title,
  value,
  description,
}: {
  title: string
  value: string
  description: string
}) {
  return (
    <div className="rounded-3xl border border-zinc-800 bg-black p-6">
      <p className="text-sm text-gray-400">{title}</p>
      <p className="mt-2 break-all text-3xl font-extrabold text-white">
        {value}
      </p>
      <p className="mt-3 text-sm text-gray-500">{description}</p>
    </div>
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
    <div className="rounded-2xl border border-zinc-800 bg-zinc-950 p-4">
      <p className="mb-1 text-sm text-gray-400">{title}</p>
      <p className="break-all text-lg font-bold text-white">{value}</p>
      <p className="mt-2 text-sm text-gray-500">{description}</p>
    </div>
  )
}

function SignalItem({
  icon,
  color,
  text,
}: {
  icon: string
  color: string
  text: string
}) {
  return (
    <div className={`flex gap-3 rounded-2xl border p-4 ${color}`}>
      <span className="shrink-0">{icon}</span>
      <span>{text}</span>
    </div>
  )
}

function LegendItem({
  color,
  title,
  range,
}: {
  color: string
  title: string
  range: string
}) {
  return (
    <div className="flex items-center justify-between rounded-2xl border border-zinc-800 bg-black p-4">
      <div className="flex items-center gap-3">
        <span className={`h-3 w-3 rounded-full ${color}`} />
        <span className="font-semibold">{title}</span>
      </div>
      <span className="text-sm text-gray-400">{range}</span>
    </div>
  )
}

function classifySignals(reasons: string[]): ClassifiedSignals {
  const critical: string[] = []
  const warning: string[] = []
  const safe: string[] = []
  const neutral: string[] = []

  for (const reason of reasons) {
    if (isCriticalReason(reason)) {
      critical.push(reason)
    } else if (isWarningReason(reason)) {
      warning.push(reason)
    } else if (isSafeReason(reason)) {
      safe.push(reason)
    } else {
      neutral.push(reason)
    }
  }

  return { critical, warning, safe, neutral }
}

function isCriticalReason(reason: string) {
  return (
    reason.includes('Safe Browsing에서 위험 URL로 탐지') ||
    reason.includes('매우 위험') ||
    reason.includes('Self-signed') ||
    reason.includes('신뢰되지 않은 인증서') ||
    reason.includes('인증서가 만료') ||
    reason.includes('CN/SAN 정보가 일치하지 않습니다') ||
    reason.includes('CA 체인 검증에 실패') ||
    reason.includes('비밀번호 입력창') ||
    reason.includes('신규 피싱 가능성이 높습니다') ||
    reason.includes('브랜드 위장 신호와 로그인') ||
    reason.includes('Malware') ||
    reason.includes('악성')
  )
}

function isWarningReason(reason: string) {
  return (
    reason.includes('브랜드') ||
    reason.includes('유사') ||
    reason.includes('위장') ||
    reason.includes('DNS 조회에 실패') ||
    reason.includes('도메인이 존재하지 않') ||
    reason.includes('Punycode') ||
    reason.includes('Homograph') ||
    reason.includes('의심') ||
    reason.includes('로그인') ||
    reason.includes('form 태그') ||
    reason.includes('iframe') ||
    reason.includes('생성된 지') ||
    reason.includes('매우 짧습니다') ||
    reason.includes('비교적 짧습니다') ||
    reason.includes('Safe Browsing에 등록된 위험 URL은 아니지만')
  )
}

function isSafeReason(reason: string) {
  return (
    reason.includes('정상으로 확인') ||
    reason.includes('CA 체인 검증에 성공') ||
    reason.includes('DNS 조회에 성공') ||
    reason.includes('공인 IP로 확인') ||
    reason.includes('신규 도메인 위험은 낮습니다') ||
    reason.includes('도메인 만료까지') ||
    reason.includes('공식 주요 서비스 도메인') ||
    reason.includes('위험 점수에 반영하지 않았습니다') ||
    reason.includes(
      '콘텐츠 분석에서 로그인/계정 탈취 의심 요소가 뚜렷하지 않습니다',
    )
  )
}

function getMainRiskReasons(signals: ClassifiedSignals, status?: RiskStatus) {
  const riskReasons = [...signals.critical, ...signals.warning]

  if (riskReasons.length > 0) {
    return riskReasons.slice(0, 3)
  }

  if (status === '낮은 위험') {
    return []
  }

  return signals.neutral.slice(0, 3)
}

function getReasonIcon(reason: string) {
  if (isCriticalReason(reason)) return '🚨'
  if (isWarningReason(reason)) return '⚠️'
  if (isSafeReason(reason)) return '✅'
  return 'ℹ️'
}

function getReasonStyle(reason: string) {
  if (isCriticalReason(reason)) {
    return 'border-red-500/30 bg-red-500/10 text-red-200'
  }

  if (isWarningReason(reason)) {
    return 'border-yellow-500/30 bg-yellow-500/10 text-yellow-200'
  }

  if (isSafeReason(reason)) {
    return 'border-green-500/30 bg-green-500/10 text-green-200'
  }

  return 'border-zinc-700 bg-zinc-950 text-gray-300'
}

function getConclusionMessage(
  status?: RiskStatus,
  mainReasons: string[] = [],
  safeCount = 0,
) {
  const firstReason = mainReasons[0]

  if (status === '매우 위험') {
    if (firstReason) {
      return `이 사이트는 매우 위험으로 판단됩니다. 가장 큰 이유는 "${firstReason}" 입니다. TLS 인증서가 정상이어도 사이트 자체가 위험 URL로 분류되거나 강한 피싱 신호가 있으면 접속을 권장하지 않습니다.`
    }

    return '이 사이트는 매우 위험으로 판단됩니다. 접속하지 않는 것을 권장합니다.'
  }

  if (status === '높은 위험') {
    if (firstReason) {
      return `이 사이트는 높은 위험으로 판단됩니다. 주요 원인은 "${firstReason}" 입니다. 로그인이나 개인정보 입력을 피하는 것이 좋습니다.`
    }

    return '이 사이트는 높은 위험으로 판단됩니다. 로그인이나 개인정보 입력을 피하는 것이 좋습니다.'
  }

  if (status === '주의 필요') {
    if (firstReason) {
      return `일부 주의 신호가 발견되었습니다. 특히 "${firstReason}" 항목을 확인해야 합니다.`
    }

    return '일부 주의 신호가 발견되었습니다. 주소와 인증서 정보를 다시 확인하세요.'
  }

  if (status === '낮은 위험') {
    return `현재 탐지된 주요 위험 신호는 낮습니다. 안전 신호 ${safeCount}개가 확인되었지만, 낮은 위험이 절대적 안전을 의미하지는 않습니다.`
  }

  return '분석 결과를 확인하세요.'
}

function getRiskIcon(status?: RiskStatus) {
  if (status === '낮은 위험') return '🟢'
  if (status === '주의 필요') return '🟡'
  if (status === '높은 위험') return '🟠'
  if (status === '매우 위험') return '🔴'
  return '🔍'
}

function getUserActionMessage(status?: RiskStatus) {
  if (status === '낮은 위험') {
    return '현재 탐지된 주요 위험 신호는 낮습니다. 그래도 개인정보 입력 전 주소를 확인하세요.'
  }

  if (status === '주의 필요') {
    return '일부 의심 신호가 있습니다. 주소와 인증서 정보를 다시 확인하세요.'
  }

  if (status === '높은 위험') {
    return '위험 신호가 강합니다. 로그인이나 개인정보 입력을 피하는 것이 좋습니다.'
  }

  if (status === '매우 위험') {
    return '매우 강한 위험 신호가 발견되었습니다. 접속하지 않는 것을 권장합니다.'
  }

  return '분석 결과를 확인하세요.'
}

function getStringValue(value?: string | string[]) {
  if (!value) return '정보 없음'
  if (Array.isArray(value)) return value.join(', ')
  return value
}

function getSanList(subjectaltname?: string) {
  if (!subjectaltname) return []

  return subjectaltname
    .split(',')
    .map((item) => item.trim().replace(/^DNS:/, ''))
    .filter(Boolean)
}

function formatDate(date?: string) {
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

function getStatusColor(status?: string) {
  if (status === '낮은 위험') return 'text-green-400'
  if (status === '주의 필요') return 'text-yellow-400'
  if (status === '높은 위험') return 'text-orange-400'
  if (status === '매우 위험') return 'text-red-400'
  return 'text-gray-300'
}

function getRiskBoxStyle(status?: string) {
  if (status === '낮은 위험') {
    return 'border-green-400/30 bg-green-500/10 text-green-300'
  }

  if (status === '주의 필요') {
    return 'border-yellow-400/30 bg-yellow-500/10 text-yellow-300'
  }

  if (status === '높은 위험') {
    return 'border-orange-400/30 bg-orange-500/10 text-orange-300'
  }

  if (status === '매우 위험') {
    return 'border-red-400/30 bg-red-500/10 text-red-300'
  }

  return 'border-zinc-700 bg-zinc-900 text-gray-300'
}
