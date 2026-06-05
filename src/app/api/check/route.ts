import { NextResponse } from 'next/server'
import https from 'https'
import tls, { TLSSocket } from 'tls'
import net from 'net'
import { lookup } from 'dns/promises'
import { domainToUnicode } from 'url'
import { parse } from 'tldts'
import { getDb } from '@/lib/mongodb'

export const runtime = 'nodejs'

type RiskStatus = '낮은 위험' | '주의 필요' | '높은 위험' | '매우 위험'

type CertificateField = Record<string, string | string[] | undefined>

type CertificateData = {
  subject?: CertificateField
  issuer?: CertificateField
  valid_from?: string
  valid_to?: string
  subjectaltname?: string
  fingerprint?: string
}

type AnalyzeResult = {
  score: number
  status: RiskStatus
  reasons: string[]
  flags?: string[]
}

type CaChainResult = {
  checked: boolean
  authorized: boolean
  error?: string
}

type TrustEvaluation = {
  status: '신뢰 가능' | '주의 필요' | '위험'
  organization: string
  reason: string
}

type SecurityGrade = {
  score: number
  grade: 'A+' | 'A' | 'B' | 'C' | 'D'
  status: RiskStatus
  summary: string
  details: string[]
  reasons: string[]
}

type ExtraAnalysis = {
  score: number
  reasons: string[]
  flags?: string[]
}

const BRAND_TARGETS = [
  { brand: 'google', officialDomains: ['google.com', 'google.co.kr'] },
  { brand: 'youtube', officialDomains: ['youtube.com', 'youtu.be'] },
  { brand: 'naver', officialDomains: ['naver.com'] },
  { brand: 'kakao', officialDomains: ['kakao.com'] },
  { brand: 'daum', officialDomains: ['daum.net'] },
  {
    brand: 'microsoft',
    officialDomains: ['microsoft.com', 'live.com', 'office.com'],
  },
  { brand: 'apple', officialDomains: ['apple.com', 'icloud.com'] },
  { brand: 'amazon', officialDomains: ['amazon.com'] },
  { brand: 'paypal', officialDomains: ['paypal.com'] },
  { brand: 'facebook', officialDomains: ['facebook.com'] },
  { brand: 'instagram', officialDomains: ['instagram.com'] },
  { brand: 'netflix', officialDomains: ['netflix.com'] },
  { brand: 'github', officialDomains: ['github.com'] },
]

const OFFICIAL_DOMAINS = BRAND_TARGETS.flatMap((item) => item.officialDomains)

export async function GET() {
  try {
    const db = await getDb()

    if (!db) {
      return NextResponse.json({
        success: true,
        history: [],
        message: 'MongoDB 설정이 없어 기록 조회를 생략했습니다.',
      })
    }

    const history = await db
      .collection('check_results')
      .find({})
      .sort({ checkedAt: -1 })
      .limit(10)
      .toArray()

    return NextResponse.json({
      success: true,
      history,
    })
  } catch (error) {
    console.error('MongoDB 기록 조회 실패:', error)

    return NextResponse.json({
      success: true,
      history: [],
      message: 'MongoDB 기록 조회에 실패했지만 서비스는 계속 동작합니다.',
    })
  }
}

export async function POST(req: Request) {
  try {
    const body = await req.json()
    const { url } = body

    if (!url) {
      return NextResponse.json(
        { success: false, message: 'URL이 없습니다.' },
        { status: 400 },
      )
    }

    const normalizedUrl = normalizeUrl(url)
    const parsed = new URL(normalizedUrl)
    const hostname = parsed.hostname

    const urlAnalysis = analyzeUrl(parsed)
    const dnsAnalysis = await analyzeDnsAndPublicIp(parsed)

    let certificate: CertificateData | null = null
    let certAnalysis: AnalyzeResult = {
      score: 0,
      status: '낮은 위험',
      reasons: ['DNS 조회 실패로 TLS 인증서 검사를 생략했습니다.'],
      flags: ['cert_skipped'],
    }

    let caChain: CaChainResult = {
      checked: false,
      authorized: false,
      error: 'DNS 조회 실패로 CA 체인 검증을 생략했습니다.',
    }

    let caChainAnalysis: ExtraAnalysis = {
      score: 0,
      reasons: ['DNS 조회 실패로 CA 체인 검증을 생략했습니다.'],
      flags: ['ca_chain_skipped'],
    }

    let whoisAnalysis: ExtraAnalysis = {
      score: 0,
      reasons: ['DNS 조회 실패와 관계없이 RDAP 분석을 생략했습니다.'],
      flags: ['rdap_skipped'],
    }

    let safeBrowsingAnalysis: ExtraAnalysis
    let contentAnalysis: ExtraAnalysis = {
      score: 0,
      reasons: ['DNS 조회 실패로 콘텐츠 분석을 생략했습니다.'],
      flags: ['content_skipped'],
    }

    if (!dnsAnalysis.flags?.includes('dns_not_found')) {
      try {
        certificate = await getCertificate(parsed)
        certAnalysis = analyzeCertificate(hostname, certificate)
        caChain = await verifyCaChain(hostname)
        caChainAnalysis = analyzeCaChain(caChain)
      } catch (error) {
        const message =
          error instanceof Error
            ? error.message
            : 'TLS 연결 또는 인증서 수집 실패'

        certAnalysis = {
          score: 65,
          status: getRiskStatus(65),
          reasons: [
            'TLS 연결 또는 인증서 수집에 실패했습니다.',
            `상세 오류: ${message}`,
          ],
          flags: ['tls_failed'],
        }

        caChain = {
          checked: false,
          authorized: false,
          error: '인증서 수집 실패로 CA 체인 검증을 생략했습니다.',
        }

        caChainAnalysis = analyzeCaChain(caChain)
      }

      whoisAnalysis = await analyzeWhois(hostname)
      contentAnalysis = await analyzeContent(normalizedUrl, hostname)
    }

    safeBrowsingAnalysis = await analyzeSafeBrowsing(normalizedUrl)

    const combinationAnalysis = analyzeCombinedRiskSignals({
      urlAnalysis,
      dnsAnalysis,
      certAnalysis,
      caChainAnalysis,
      whoisAnalysis,
      safeBrowsingAnalysis,
      contentAnalysis,
      caChain,
    })

    const rawScore =
      urlAnalysis.score +
      dnsAnalysis.score +
      certAnalysis.score +
      caChainAnalysis.score +
      whoisAnalysis.score +
      safeBrowsingAnalysis.score +
      contentAnalysis.score +
      combinationAnalysis.score

    const finalRiskScore = Math.min(100, rawScore)

    const reasons = [
      ...urlAnalysis.reasons,
      ...dnsAnalysis.reasons,
      ...certAnalysis.reasons,
      ...caChainAnalysis.reasons,
      ...whoisAnalysis.reasons,
      ...safeBrowsingAnalysis.reasons,
      ...contentAnalysis.reasons,
      ...combinationAnalysis.reasons,
    ]

    const trustEvaluation = evaluateCertificateTrust(certificate, caChain)
    const securityGrade = evaluateSecurityGrade(finalRiskScore, reasons)

    const result = {
      success: true,
      url: normalizedUrl,
      hostname,
      checkedAt: new Date().toISOString(),
      certificate,
      caChain,
      trustEvaluation,
      dnsAnalysis,
      whoisAnalysis,
      safeBrowsingAnalysis,
      contentAnalysis,
      combinationAnalysis,
      analysis: {
        score: finalRiskScore,
        status: getRiskStatus(finalRiskScore),
        reasons,
      },
      securityGrade,
    }

    await saveResultWithoutBreakingService(result)

    return NextResponse.json(result)
  } catch (error: unknown) {
    console.error(error)

    const message =
      error instanceof Error ? error.message : '서버 오류가 발생했습니다.'

    return NextResponse.json({
      success: false,
      message,
    })
  }
}

function normalizeUrl(input: string) {
  const trimmed = input.trim()

  if (trimmed.startsWith('http://') || trimmed.startsWith('https://')) {
    return trimmed
  }

  return `https://${trimmed}`
}

async function saveResultWithoutBreakingService(
  result: Record<string, unknown>,
) {
  try {
    const db = await getDb()

    if (!db) return

    await db.collection('check_results').updateOne(
      { url: result.url },
      {
        $set: result,
        $setOnInsert: {
          firstSeenAt: new Date().toISOString(),
        },
      },
      { upsert: true },
    )
  } catch (error) {
    console.error('MongoDB 저장 실패:', error)
  }
}

async function analyzeDnsAndPublicIp(parsed: URL): Promise<ExtraAnalysis> {
  const hostname = parsed.hostname.toLowerCase()

  if (!['http:', 'https:'].includes(parsed.protocol)) {
    throw new Error('http 또는 https URL만 검사할 수 있습니다.')
  }

  if (
    hostname === 'localhost' ||
    hostname.endsWith('.localhost') ||
    hostname.endsWith('.local') ||
    hostname.endsWith('.internal')
  ) {
    throw new Error('localhost 또는 내부망 주소는 검사할 수 없습니다.')
  }

  if (net.isIP(hostname)) {
    if (isPrivateIp(hostname)) {
      throw new Error('사설 IP 또는 내부 IP 주소는 검사할 수 없습니다.')
    }

    return {
      score: 20,
      reasons: ['도메인 대신 공인 IP 주소가 직접 입력되었습니다.'],
      flags: ['public_ip_direct'],
    }
  }

  try {
    const addresses = await lookup(hostname, { all: true })

    if (addresses.length === 0) {
      return {
        score: 40,
        reasons: [
          '도메인의 IP 주소를 확인할 수 없습니다. DNS 조회 결과가 없습니다.',
        ],
        flags: ['dns_not_found'],
      }
    }

    if (addresses.some((address) => isPrivateIp(address.address))) {
      throw new Error('내부망으로 해석되는 도메인은 검사할 수 없습니다.')
    }

    return {
      score: 0,
      reasons: ['DNS 조회에 성공했으며 공인 IP로 확인되었습니다.'],
      flags: ['dns_resolved'],
    }
  } catch (error) {
    const code =
      error instanceof Error && 'code' in error
        ? String((error as NodeJS.ErrnoException).code)
        : ''

    if (code === 'ENOTFOUND' || code === 'ENODATA') {
      return {
        score: 40,
        reasons: [
          '도메인이 존재하지 않거나 DNS 조회에 실패했습니다.',
          '브랜드와 유사한 미등록 도메인은 피싱 준비 단계 또는 오타 유도 도메인일 수 있습니다.',
        ],
        flags: ['dns_not_found'],
      }
    }

    throw error
  }
}

async function assertPublicUrl(parsed: URL) {
  const result = await analyzeDnsAndPublicIp(parsed)

  if (result.flags?.includes('dns_not_found')) {
    throw new Error('DNS 조회 실패')
  }
}

function isPrivateIp(ip: string) {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split('.').map(Number)

    if (a === 10) return true
    if (a === 127) return true
    if (a === 0) return true
    if (a === 169 && b === 254) return true
    if (a === 172 && b >= 16 && b <= 31) return true
    if (a === 192 && b === 168) return true
    if (a >= 224) return true

    return false
  }

  const lowerIp = ip.toLowerCase()

  if (lowerIp === '::1') return true
  if (lowerIp.startsWith('fc') || lowerIp.startsWith('fd')) return true
  if (lowerIp.startsWith('fe80')) return true
  if (lowerIp.startsWith('::ffff:')) {
    return isPrivateIp(lowerIp.replace('::ffff:', ''))
  }

  return false
}

async function getCertificate(parsed: URL): Promise<CertificateData> {
  try {
    return await getCertificateWithTls(parsed.hostname)
  } catch {
    return await getCertificateWithHttps(parsed)
  }
}

function getCertificateWithTls(hostname: string): Promise<CertificateData> {
  return new Promise((resolve, reject) => {
    const socket = tls.connect(
      {
        host: hostname,
        port: 443,
        servername: hostname,
        rejectUnauthorized: false,
        timeout: 10000,
        ALPNProtocols: ['http/1.1'],
      },
      () => {
        const cert = socket.getPeerCertificate()
        socket.end()

        if (!cert || Object.keys(cert).length === 0) {
          reject(new Error('인증서를 가져오지 못했습니다.'))
          return
        }

        resolve(formatCertificate(cert))
      },
    )

    socket.on('timeout', () => {
      socket.destroy()
      reject(new Error('TLS 연결 시간 초과'))
    })

    socket.on('error', (err) => {
      reject(err)
    })
  })
}

function getCertificateWithHttps(parsed: URL): Promise<CertificateData> {
  return new Promise((resolve, reject) => {
    const req = https.request(
      {
        host: parsed.hostname,
        port: 443,
        method: 'GET',
        path: '/',
        servername: parsed.hostname,
        rejectUnauthorized: false,
        timeout: 10000,
        headers: {
          'User-Agent': 'Mozilla/5.0 TLS-Security-Checker',
          Accept: '*/*',
          Connection: 'close',
        },
      },
      (res) => {
        const tlsSocket = res.socket as TLSSocket
        const cert = tlsSocket.getPeerCertificate()

        if (!cert || Object.keys(cert).length === 0) {
          reject(new Error('인증서를 가져오지 못했습니다.'))
          return
        }

        resolve(formatCertificate(cert))
        req.destroy()
      },
    )

    req.on('timeout', () => {
      req.destroy()
      reject(new Error('TLS 연결 시간 초과'))
    })

    req.on('error', (err) => {
      reject(err)
    })

    req.end()
  })
}

function formatCertificate(cert: tls.PeerCertificate): CertificateData {
  return {
    subject: cert.subject as CertificateField,
    issuer: cert.issuer as CertificateField,
    valid_from: cert.valid_from,
    valid_to: cert.valid_to,
    subjectaltname: cert.subjectaltname,
    fingerprint: cert.fingerprint,
  }
}

function verifyCaChain(hostname: string): Promise<CaChainResult> {
  return new Promise((resolve) => {
    const socket = tls.connect(
      {
        host: hostname,
        port: 443,
        servername: hostname,
        rejectUnauthorized: true,
        timeout: 10000,
        ALPNProtocols: ['http/1.1'],
      },
      () => {
        const result: CaChainResult = {
          checked: true,
          authorized: socket.authorized,
          error: socket.authorizationError
            ? String(socket.authorizationError)
            : undefined,
        }

        socket.end()
        resolve(result)
      },
    )

    socket.on('timeout', () => {
      socket.destroy()
      resolve({
        checked: true,
        authorized: false,
        error: 'TLS 연결 시간 초과',
      })
    })

    socket.on('error', (err: NodeJS.ErrnoException) => {
      resolve({
        checked: true,
        authorized: false,
        error: err.code || err.message,
      })
    })
  })
}

function analyzeUrl(parsed: URL): AnalyzeResult {
  let score = 0
  const reasons: string[] = []
  const flags: string[] = []

  const hostname = parsed.hostname.toLowerCase()
  const fullUrl = parsed.href.toLowerCase()
  const registeredDomain = getRegisteredDomain(hostname)
  const isOfficialDomain = OFFICIAL_DOMAINS.includes(registeredDomain)

  if (parsed.protocol === 'http:') {
    score += 70
    reasons.push('HTTP URL입니다. TLS 암호화가 적용되지 않았습니다.')
    flags.push('http_used')
  }

  const suspiciousKeywords = [
    'login',
    'verify',
    'account',
    'update',
    'password',
    'wallet',
    'signin',
    'otp',
  ]

  const keywordCount = suspiciousKeywords.filter((keyword) =>
    fullUrl.includes(keyword),
  ).length

  if (keywordCount > 0 && !isOfficialDomain) {
    score += Math.min(20, keywordCount * 8)
    reasons.push(
      'URL에 로그인, 계정 확인, 비밀번호 관련 의심 키워드가 포함되어 있습니다.',
    )
    flags.push('suspicious_keyword')
  }

  if (fullUrl.includes('secure') || fullUrl.includes('security')) {
    if (isOfficialDomain) {
      reasons.push(
        'security 관련 단어가 포함되어 있으나 공식 도메인이므로 낮은 위험으로 처리했습니다.',
      )
    } else {
      score += 5
      reasons.push('URL에 secure/security 단어가 포함되어 있습니다.')
      flags.push('security_keyword')
    }
  }

  if (/[0-9]/.test(hostname) && !isOfficialDomain) {
    score += 5
    reasons.push('도메인에 숫자가 포함되어 있어 문자 치환 가능성이 있습니다.')
    flags.push('number_in_domain')
  }

  if (hostname.length >= 35 && !isOfficialDomain) {
    score += 5
    reasons.push('도메인 길이가 비정상적으로 깁니다.')
    flags.push('long_domain')
  }

  const hyphenCount = (hostname.match(/-/g) || []).length

  if (hyphenCount >= 2 && !isOfficialDomain) {
    score += 5
    reasons.push('도메인에 하이픈이 과도하게 포함되어 있습니다.')
    flags.push('many_hyphens')
  }

  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) {
    score += 40
    reasons.push('도메인이 IP 주소 형태로 입력되었습니다.')
    flags.push('ip_domain')
  }

  if (hostname.includes('xn--')) {
    score += 40
    reasons.push(
      'Punycode 도메인이 사용되었습니다. 유사 문자 위장 가능성이 있습니다.',
    )
    flags.push('punycode')
  }

  const brandAnalysis = analyzeBrandImpersonation(hostname)
  score += brandAnalysis.score
  reasons.push(...brandAnalysis.reasons)

  if (brandAnalysis.flags) {
    flags.push(...brandAnalysis.flags)
  }

  if (reasons.length === 0) {
    reasons.push('URL 구조에서 뚜렷한 위장 패턴은 발견되지 않았습니다.')
  }

  return {
    score,
    status: getRiskStatus(score),
    reasons,
    flags,
  }
}

function analyzeBrandImpersonation(hostname: string): ExtraAnalysis {
  let score = 0
  const reasons: string[] = []
  const flags: string[] = []

  const registeredDomain = getRegisteredDomain(hostname)
  const parsedDomain = parse(hostname)
  const domainWithoutSuffix =
    parsedDomain.domainWithoutSuffix || registeredDomain.split('.')[0]
  const unicodeDomain = domainToUnicode(registeredDomain)
  const isOfficialDomain = OFFICIAL_DOMAINS.includes(registeredDomain)

  if (isOfficialDomain) {
    return {
      score: 0,
      reasons: [
        '공식 주요 서비스 도메인으로 확인되어 브랜드 위장 위험을 낮게 평가했습니다.',
      ],
      flags: ['official_domain'],
    }
  }

  if (unicodeDomain !== registeredDomain) {
    score += 40
    reasons.push(
      'Punycode/유니코드 변환 결과가 달라 Homograph 공격 가능성이 있습니다.',
    )
    flags.push('homograph')
  }

  if (containsSuspiciousUnicode(unicodeDomain)) {
    score += 40
    reasons.push(
      '도메인에 라틴 문자와 유사한 비ASCII 문자가 포함되어 있습니다.',
    )
    flags.push('unicode_lookalike')
  }

  const normalizedDomain = normalizeLookalikeText(domainWithoutSuffix)

  for (const item of BRAND_TARGETS) {
    const brand = item.brand

    if (domainWithoutSuffix.includes(brand)) {
      score += 25
      reasons.push(
        `도메인에 유명 브랜드명(${brand})이 포함되어 있으나 공식 도메인이 아닙니다.`,
      )
      flags.push('brand_in_non_official_domain')
      break
    }

    const rawDistance = levenshtein(domainWithoutSuffix, brand)
    const normalizedDistance = levenshtein(normalizedDomain, brand)

    if (rawDistance > 0 && rawDistance <= 2) {
      score += 30
      reasons.push(
        `도메인명이 ${brand}와 매우 유사하여 오타 위장 가능성이 있습니다.`,
      )
      flags.push('brand_typo')
      break
    }

    if (normalizedDistance <= 1 && normalizedDomain !== domainWithoutSuffix) {
      score += 35
      reasons.push(
        `숫자/문자 치환으로 ${brand}와 유사하게 보이도록 만든 도메인일 수 있습니다.`,
      )
      flags.push('brand_lookalike')
      break
    }
  }

  if (reasons.length === 0) {
    reasons.push('브랜드 위장 패턴은 뚜렷하게 발견되지 않았습니다.')
  }

  return {
    score,
    reasons,
    flags,
  }
}

function containsSuspiciousUnicode(value: string) {
  return /[^\u0000-\u007f]/.test(value)
}

function normalizeLookalikeText(value: string) {
  return value
    .toLowerCase()
    .replaceAll('0', 'o')
    .replaceAll('1', 'l')
    .replaceAll('3', 'e')
    .replaceAll('5', 's')
    .replaceAll('7', 't')
    .replaceAll('@', 'a')
}

function analyzeCertificate(
  hostname: string,
  certificate: CertificateData,
): AnalyzeResult {
  let score = 0
  const reasons: string[] = []
  const flags: string[] = []

  const now = new Date()

  if (!certificate.valid_from || !certificate.valid_to) {
    score += 50
    reasons.push('인증서 유효기간 정보를 확인할 수 없습니다.')
    flags.push('cert_validity_unknown')
  } else {
    const validFrom = new Date(certificate.valid_from)
    const validTo = new Date(certificate.valid_to)

    if (now < validFrom) {
      score += 70
      reasons.push('인증서가 아직 유효하지 않습니다.')
      flags.push('cert_not_yet_valid')
    }

    if (now > validTo) {
      score += 70
      reasons.push('인증서가 만료되었습니다.')
      flags.push('cert_expired')
    }
  }

  if (!checkDomainMatch(hostname, certificate)) {
    score += 70
    reasons.push('입력한 도메인과 인증서의 CN/SAN 정보가 일치하지 않습니다.')
    flags.push('cert_domain_mismatch')
  }

  const subjectCN = getFirstString(certificate.subject?.CN)
  const issuerCN = getFirstString(certificate.issuer?.CN)

  if (subjectCN && issuerCN && subjectCN === issuerCN) {
    score += 80
    reasons.push('Self-signed 인증서로 판단됩니다.')
    flags.push('self_signed')
  }

  if (score === 0) {
    reasons.push('인증서 유효기간과 도메인 정보가 정상으로 확인되었습니다.')
  }

  return {
    score,
    status: getRiskStatus(score),
    reasons,
    flags,
  }
}

function analyzeCaChain(caChain: CaChainResult): ExtraAnalysis {
  if (!caChain.checked) {
    return {
      score: 0,
      reasons: ['CA 체인 검증을 수행하지 못했습니다.'],
      flags: ['ca_chain_not_checked'],
    }
  }

  if (caChain.authorized) {
    return {
      score: 0,
      reasons: ['CA 체인 검증에 성공했습니다.'],
      flags: ['ca_chain_authorized'],
    }
  }

  const error = caChain.error || '알 수 없는 CA 체인 오류'

  if (
    error.includes('CERT_HAS_EXPIRED') ||
    error.includes('ERR_TLS_CERT_ALTNAME_INVALID')
  ) {
    return {
      score: 0,
      reasons: [`CA 체인 검증 실패 사유: ${error}`],
      flags: ['ca_chain_failed_known_cert_issue'],
    }
  }

  if (
    error.includes('SELF_SIGNED') ||
    error.includes('DEPTH_ZERO_SELF_SIGNED_CERT')
  ) {
    return {
      score: 80,
      reasons: [
        `Self-signed 또는 신뢰되지 않은 인증서 체인입니다. 사유: ${error}`,
      ],
      flags: ['ca_chain_self_signed'],
    }
  }

  return {
    score: 70,
    reasons: [`CA 체인 검증에 실패했습니다. 사유: ${error}`],
    flags: ['ca_chain_failed'],
  }
}

async function analyzeWhois(hostname: string): Promise<ExtraAnalysis> {
  const domain = getRegisteredDomain(hostname)

  try {
    const res = await fetch(`https://rdap.org/domain/${domain}`, {
      signal: AbortSignal.timeout(8000),
    })

    if (!res.ok) {
      return {
        score: 0,
        reasons: [
          'WHOIS/RDAP 정보를 조회하지 못했습니다. 보조 지표이므로 점수에는 반영하지 않았습니다.',
        ],
        flags: ['rdap_unavailable'],
      }
    }

    const data = await res.json()
    const events = Array.isArray(data.events) ? data.events : []

    const registrationEvent = events.find(
      (event: { eventAction?: string }) => event.eventAction === 'registration',
    )

    const expirationEvent = events.find(
      (event: { eventAction?: string }) => event.eventAction === 'expiration',
    )

    const createdAt = registrationEvent?.eventDate
    const expiresAt = expirationEvent?.eventDate

    let score = 0
    const reasons: string[] = []
    const flags: string[] = []

    if (createdAt) {
      const ageDays = Math.floor(
        (Date.now() - new Date(createdAt).getTime()) / (1000 * 60 * 60 * 24),
      )

      if (ageDays <= 30) {
        score += 30
        reasons.push(`도메인이 생성된 지 ${ageDays}일로 매우 짧습니다.`)
        flags.push('new_domain_30d')
      } else if (ageDays <= 180) {
        score += 15
        reasons.push(`도메인이 생성된 지 ${ageDays}일로 비교적 짧습니다.`)
        flags.push('new_domain_180d')
      } else {
        reasons.push(
          `도메인 생성 후 ${ageDays}일이 지나 신규 도메인 위험은 낮습니다.`,
        )
        flags.push('old_domain')
      }
    } else {
      reasons.push('도메인 생성일 정보를 확인하지 못했습니다.')
      flags.push('domain_age_unknown')
    }

    if (expiresAt) {
      const daysToExpire = Math.ceil(
        (new Date(expiresAt).getTime() - Date.now()) / (1000 * 60 * 60 * 24),
      )

      if (daysToExpire > 0 && daysToExpire <= 30) {
        score += 10
        reasons.push(`도메인 만료까지 ${daysToExpire}일밖에 남지 않았습니다.`)
        flags.push('domain_expiring_soon')
      } else if (daysToExpire > 30) {
        reasons.push(`도메인 만료까지 ${daysToExpire}일 남았습니다.`)
      }
    }

    return { score, reasons, flags }
  } catch {
    return {
      score: 0,
      reasons: [
        'WHOIS/RDAP 분석 중 오류가 발생하여 점수에는 반영하지 않았습니다.',
      ],
      flags: ['rdap_error'],
    }
  }
}

async function analyzeSafeBrowsing(url: string): Promise<ExtraAnalysis> {
  const apiKey = process.env.GOOGLE_SAFE_BROWSING_API_KEY

  if (!apiKey) {
    return {
      score: 0,
      reasons: [
        'Google Safe Browsing API 키가 없어 블랙리스트 검사를 생략했습니다.',
      ],
      flags: ['safe_browsing_skipped'],
    }
  }

  try {
    const res = await fetch(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        signal: AbortSignal.timeout(8000),
        body: JSON.stringify({
          client: {
            clientId: 'tls-phishing-checker',
            clientVersion: '1.0.0',
          },
          threatInfo: {
            threatTypes: [
              'MALWARE',
              'SOCIAL_ENGINEERING',
              'UNWANTED_SOFTWARE',
              'POTENTIALLY_HARMFUL_APPLICATION',
            ],
            platformTypes: ['ANY_PLATFORM'],
            threatEntryTypes: ['URL'],
            threatEntries: [{ url }],
          },
        }),
      },
    )

    const data = await res.json()

    if (data.matches && data.matches.length > 0) {
      return {
        score: 100,
        reasons: ['Google Safe Browsing에서 위험 URL로 탐지되었습니다.'],
        flags: ['safe_browsing_match'],
      }
    }

    return {
      score: 0,
      reasons: [
        'Google Safe Browsing에 등록된 위험 URL은 아니지만, 신규 피싱 사이트는 아직 등록되지 않았을 수 있습니다.',
      ],
      flags: ['safe_browsing_no_match'],
    }
  } catch {
    return {
      score: 0,
      reasons: [
        'Google Safe Browsing 검사 중 오류가 발생하여 점수에는 반영하지 않았습니다.',
      ],
      flags: ['safe_browsing_error'],
    }
  }
}

async function analyzeContent(
  url: string,
  hostname: string,
): Promise<ExtraAnalysis> {
  try {
    const registeredDomain = getRegisteredDomain(hostname)
    const isOfficialDomain = OFFICIAL_DOMAINS.includes(registeredDomain)

    const html = await safeFetchHtml(url)
    const lowerHtml = html.toLowerCase()

    const hasPasswordInput = /<input[^>]+type=["']?password/i.test(html)
    const hasForm = /<form/i.test(html)
    const hasLoginText =
      /login|sign in|password|verify|account|otp|인증|로그인/.test(lowerHtml)
    const hasIframe = /<iframe/i.test(html)

    if (isOfficialDomain) {
      return {
        score: 0,
        reasons: [
          '공식 주요 서비스 도메인이므로 form 태그나 로그인 문구는 일반 기능으로 간주하여 위험 점수에 반영하지 않았습니다.',
        ],
        flags: ['official_domain_content_ignored'],
      }
    }

    let score = 0
    const reasons: string[] = []
    const flags: string[] = []

    if (hasPasswordInput) {
      score += 25
      reasons.push('페이지에 비밀번호 입력창이 존재합니다.')
      flags.push('password_input')
    }

    if (hasForm) {
      score += 5
      reasons.push('사용자 입력을 받는 form 태그가 존재합니다.')
      flags.push('form_detected')
    }

    if (hasLoginText) {
      score += 5
      reasons.push('로그인 또는 계정 확인 관련 문구가 포함되어 있습니다.')
      flags.push('login_text')
    }

    if (hasIframe) {
      score += 5
      reasons.push('iframe이 포함되어 있어 외부 콘텐츠 삽입 가능성이 있습니다.')
      flags.push('iframe_detected')
    }

    if (score === 0) {
      reasons.push(
        '콘텐츠 분석에서 로그인/계정 탈취 의심 요소가 뚜렷하지 않습니다.',
      )
      flags.push('content_no_phishing_signal')
    }

    return { score, reasons, flags }
  } catch (error) {
    const message = error instanceof Error ? error.message : '콘텐츠 분석 실패'

    return {
      score: 0,
      reasons: [`콘텐츠 분석을 생략했습니다. 사유: ${message}`],
      flags: ['content_analysis_skipped'],
    }
  }
}

function analyzeCombinedRiskSignals({
  urlAnalysis,
  dnsAnalysis,
  certAnalysis,
  caChainAnalysis,
  whoisAnalysis,
  safeBrowsingAnalysis,
  contentAnalysis,
  caChain,
}: {
  urlAnalysis: AnalyzeResult
  dnsAnalysis: ExtraAnalysis
  certAnalysis: AnalyzeResult
  caChainAnalysis: ExtraAnalysis
  whoisAnalysis: ExtraAnalysis
  safeBrowsingAnalysis: ExtraAnalysis
  contentAnalysis: ExtraAnalysis
  caChain: CaChainResult
}): ExtraAnalysis {
  let score = 0
  const reasons: string[] = []

  const flags = new Set([
    ...(urlAnalysis.flags || []),
    ...(dnsAnalysis.flags || []),
    ...(certAnalysis.flags || []),
    ...(caChainAnalysis.flags || []),
    ...(whoisAnalysis.flags || []),
    ...(safeBrowsingAnalysis.flags || []),
    ...(contentAnalysis.flags || []),
  ])

  const hasBrandSignal =
    flags.has('brand_in_non_official_domain') ||
    flags.has('brand_typo') ||
    flags.has('brand_lookalike') ||
    flags.has('homograph') ||
    flags.has('unicode_lookalike') ||
    flags.has('punycode')

  const hasLoginSignal =
    flags.has('password_input') ||
    flags.has('form_detected') ||
    flags.has('login_text') ||
    flags.has('suspicious_keyword')

  const isNewDomain =
    flags.has('new_domain_30d') ||
    flags.has('new_domain_180d') ||
    flags.has('domain_age_unknown')

  const safeBrowsingNoMatch =
    flags.has('safe_browsing_no_match') ||
    flags.has('safe_browsing_skipped') ||
    flags.has('safe_browsing_error')

  if (flags.has('safe_browsing_match')) {
    reasons.push(
      'Safe Browsing에서 이미 위험 URL로 확인되어 추가 조합 분석 없이도 매우 위험합니다.',
    )
    return {
      score: 0,
      reasons,
      flags: ['combined_safe_browsing_confirmed'],
    }
  }

  if (flags.has('dns_not_found') && hasBrandSignal) {
    score += 35
    reasons.push(
      '브랜드와 유사한 도메인이지만 DNS 조회에 실패했습니다. 피싱 준비 단계, 오타 유도, 미등록 사칭 도메인 가능성이 있습니다.',
    )
  }

  if (hasBrandSignal && hasLoginSignal) {
    score += 40
    reasons.push(
      'Safe Browsing에 등록되지 않았더라도 브랜드 위장 신호와 로그인/계정 입력 신호가 함께 발견되어 신규 피싱 가능성이 높습니다.',
    )
  }

  if (isNewDomain && flags.has('password_input')) {
    score += 50
    reasons.push(
      '생성된 지 얼마 되지 않은 도메인에서 비밀번호 입력창이 발견되어 신규 피싱 사이트 가능성이 높습니다.',
    )
  }

  if (safeBrowsingNoMatch && isNewDomain && hasBrandSignal) {
    score += 30
    reasons.push(
      'Safe Browsing에 등록되지 않았지만 신규 도메인성과 브랜드 유사성이 함께 발견되어 블랙리스트 미등록 신규 피싱 가능성이 있습니다.',
    )
  }

  if (caChain.authorized && hasBrandSignal) {
    score += 30
    reasons.push(
      'HTTPS와 CA 체인이 정상이어도 공식 도메인이 아닌 브랜드 유사 도메인이므로 정상 인증서를 사용하는 피싱 가능성이 있습니다.',
    )
  }

  if (score === 0) {
    reasons.push(
      '위험 신호 조합 분석에서 추가적인 신규 피싱 의심 조합은 발견되지 않았습니다.',
    )
  }

  return {
    score: Math.min(100, score),
    reasons,
    flags:
      score > 0 ? ['combined_new_phishing_risk'] : ['combined_no_extra_risk'],
  }
}

async function safeFetchHtml(url: string, redirectCount = 0): Promise<string> {
  if (redirectCount > 2) {
    throw new Error('리다이렉트 횟수가 너무 많습니다.')
  }

  const parsed = new URL(url)
  await assertPublicUrl(parsed)

  const res = await fetch(url, {
    redirect: 'manual',
    signal: AbortSignal.timeout(8000),
    headers: {
      'User-Agent': 'Mozilla/5.0 TLS-Security-Checker',
    },
  })

  if ([301, 302, 303, 307, 308].includes(res.status)) {
    const location = res.headers.get('location')

    if (!location) {
      throw new Error('리다이렉트 Location 헤더가 없습니다.')
    }

    const nextUrl = new URL(location, url).toString()
    return safeFetchHtml(nextUrl, redirectCount + 1)
  }

  const contentType = res.headers.get('content-type') || ''

  if (!contentType.includes('text/html')) {
    throw new Error('HTML 페이지가 아닙니다.')
  }

  const text = await res.text()
  return text.slice(0, 300000)
}

function evaluateCertificateTrust(
  certificate: CertificateData | null,
  caChain: CaChainResult,
): TrustEvaluation {
  if (!certificate) {
    return {
      status: '위험',
      organization: '정보 없음',
      reason: '인증서를 수집하지 못했습니다.',
    }
  }

  const issuerCN = getFirstString(certificate.issuer?.CN) || '정보 없음'
  const issuerO = getFirstString(certificate.issuer?.O) || issuerCN

  if (caChain.authorized) {
    return {
      status: '신뢰 가능',
      organization: issuerO,
      reason:
        'Node.js/OpenSSL 신뢰 저장소 기준으로 CA 체인 검증에 성공했습니다.',
    }
  }

  return {
    status: '위험',
    organization: issuerO,
    reason: `CA 체인 검증에 실패했습니다. 사유: ${caChain.error || '알 수 없음'}`,
  }
}

function evaluateSecurityGrade(
  riskScore: number,
  reasons: string[],
): SecurityGrade {
  const score = Math.max(0, 100 - riskScore)

  return {
    score,
    grade: getSecurityGrade(score),
    status: getRiskStatus(riskScore),
    summary: getSecurityGradeSummary(score),
    details: [
      `위험도 점수는 ${riskScore}점입니다.`,
      '브라우저 차단급 TLS 오류는 높은 가중치로 반영했습니다.',
      'URL 키워드는 보조 지표로 낮은 가중치를 적용했습니다.',
      '브랜드 위장 탐지는 유사도, 문자 치환, Punycode/유니코드 여부를 함께 분석합니다.',
      'DNS에 존재하지 않는 브랜드 유사 도메인은 미등록 사칭 도메인 가능성으로 평가합니다.',
      'Safe Browsing에 없는 신규 피싱 가능성을 보완하기 위해 브랜드 위장, 신규 도메인, 로그인 폼, 정상 HTTPS 조합을 추가 분석합니다.',
      'MongoDB는 같은 URL 기준으로 최신 검사 결과를 갱신 저장합니다.',
    ],
    reasons,
  }
}

function getRegisteredDomain(hostname: string) {
  const parsed = parse(hostname)
  return parsed.domain || hostname
}

function checkDomainMatch(hostname: string, certificate: CertificateData) {
  const names: string[] = []

  const cnValue = getFirstString(certificate.subject?.CN)

  if (cnValue) names.push(cnValue)

  if (certificate.subjectaltname) {
    const sanList = certificate.subjectaltname
      .split(',')
      .map((item) => item.trim().replace(/^DNS:/, ''))

    names.push(...sanList)
  }

  return names.some((name) => matchHostname(hostname, name))
}

function getFirstString(value: string | string[] | undefined) {
  if (typeof value === 'string') return value
  if (Array.isArray(value)) return value[0]
  return undefined
}

function matchHostname(hostname: string, certName: string) {
  if (hostname === certName) return true

  if (certName.startsWith('*.')) {
    const baseDomain = certName.slice(2)
    const hostnameLabels = hostname.split('.')
    const baseLabels = baseDomain.split('.')

    return (
      hostname.endsWith(`.${baseDomain}`) &&
      hostnameLabels.length === baseLabels.length + 1
    )
  }

  return false
}

function levenshtein(a: string, b: string) {
  const dp = Array.from({ length: a.length + 1 }, () =>
    Array(b.length + 1).fill(0),
  )

  for (let i = 0; i <= a.length; i += 1) dp[i][0] = i
  for (let j = 0; j <= b.length; j += 1) dp[0][j] = j

  for (let i = 1; i <= a.length; i += 1) {
    for (let j = 1; j <= b.length; j += 1) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1

      dp[i][j] = Math.min(
        dp[i - 1][j] + 1,
        dp[i][j - 1] + 1,
        dp[i - 1][j - 1] + cost,
      )
    }
  }

  return dp[a.length][b.length]
}

function getRiskStatus(score: number): RiskStatus {
  if (score >= 80) return '매우 위험'
  if (score >= 50) return '높은 위험'
  if (score >= 20) return '주의 필요'
  return '낮은 위험'
}

function getSecurityGrade(score: number): SecurityGrade['grade'] {
  if (score >= 95) return 'A+'
  if (score >= 85) return 'A'
  if (score >= 70) return 'B'
  if (score >= 55) return 'C'
  return 'D'
}

function getSecurityGradeSummary(score: number) {
  if (score >= 95) return '탐지된 위험 신호가 매우 적습니다.'
  if (score >= 85) return '전반적으로 위험 신호가 낮습니다.'
  if (score >= 70) return '일부 보조 위험 신호가 있어 추가 확인이 필요합니다.'
  if (score >= 55) return '주의가 필요한 위험 신호가 발견되었습니다.'
  return '강한 위험 신호가 발견되어 접속에 주의가 필요합니다.'
}
