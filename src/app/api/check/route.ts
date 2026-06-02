import { NextResponse } from 'next/server'
import https from 'https'
import tls, { TLSSocket } from 'tls'

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
  status: '안전' | '주의' | '위험'
  reasons: string[]
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

    let certificate: CertificateData | null = null
    let certAnalysis: AnalyzeResult

    try {
      certificate = await getCertificate(parsed)
      certAnalysis = analyzeCertificate(hostname, certificate)
    } catch (error) {
      const message =
        error instanceof Error
          ? error.message
          : 'TLS 연결 또는 인증서 수집 실패'

      certAnalysis = {
        score: 40,
        status: '주의',
        reasons: [
          'TLS 연결 또는 인증서 수집에 실패했습니다.',
          `상세 오류: ${message}`,
        ],
      }
    }

    const totalScore = urlAnalysis.score + certAnalysis.score

    return NextResponse.json({
      success: true,
      url: normalizedUrl,
      hostname,
      certificate,
      analysis: {
        score: totalScore,
        status: getStatus(totalScore),
        reasons: [...urlAnalysis.reasons, ...certAnalysis.reasons],
      },
    })
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

        resolve({
          subject: cert.subject as CertificateField,
          issuer: cert.issuer as CertificateField,
          valid_from: cert.valid_from,
          valid_to: cert.valid_to,
          subjectaltname: cert.subjectaltname,
          fingerprint: cert.fingerprint,
        })
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

        resolve({
          subject: cert.subject as CertificateField,
          issuer: cert.issuer as CertificateField,
          valid_from: cert.valid_from,
          valid_to: cert.valid_to,
          subjectaltname: cert.subjectaltname,
          fingerprint: cert.fingerprint,
        })

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

function analyzeUrl(parsed: URL): AnalyzeResult {
  let score = 0
  const reasons: string[] = []

  const hostname = parsed.hostname.toLowerCase()
  const fullUrl = parsed.href.toLowerCase()

  const suspiciousKeywords = [
    'login',
    'verify',
    'secure',
    'account',
    'update',
    'password',
    'bank',
    'wallet',
    'signin',
    'security',
  ]

  const hasSuspiciousKeyword = suspiciousKeywords.some((keyword) =>
    fullUrl.includes(keyword),
  )

  if (hasSuspiciousKeyword) {
    score += 20
    reasons.push(
      'URL에 login, verify, secure 같은 의심 키워드가 포함되어 있습니다.',
    )
  }

  if (/[0-9]/.test(hostname)) {
    score += 20
    reasons.push(
      '도메인에 숫자가 포함되어 있어 문자 치환 위장 가능성이 있습니다.',
    )
  }

  if (hostname.length >= 30) {
    score += 15
    reasons.push('도메인 길이가 비정상적으로 깁니다.')
  }

  const hyphenCount = (hostname.match(/-/g) || []).length

  if (hyphenCount >= 2) {
    score += 10
    reasons.push('도메인에 하이픈이 과도하게 포함되어 있습니다.')
  }

  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) {
    score += 30
    reasons.push('도메인이 IP 주소 형태로 입력되었습니다.')
  }

  if (hostname.includes('xn--')) {
    score += 30
    reasons.push(
      'Punycode 도메인이 사용되었습니다. 유사 문자 위장 가능성이 있습니다.',
    )
  }

  if (reasons.length === 0) {
    reasons.push('URL 구조에서 뚜렷한 위장 패턴은 발견되지 않았습니다.')
  }

  return {
    score,
    status: getStatus(score),
    reasons,
  }
}

function analyzeCertificate(
  hostname: string,
  certificate: CertificateData,
): AnalyzeResult {
  let score = 0
  const reasons: string[] = []

  const now = new Date()

  if (!certificate.valid_from || !certificate.valid_to) {
    score += 40
    reasons.push('인증서 유효기간 정보를 확인할 수 없습니다.')
  } else {
    const validFrom = new Date(certificate.valid_from)
    const validTo = new Date(certificate.valid_to)

    if (now < validFrom) {
      score += 30
      reasons.push('인증서가 아직 유효하지 않습니다.')
    }

    if (now > validTo) {
      score += 30
      reasons.push('인증서가 만료되었습니다.')
    }
  }

  const domainMatched = checkDomainMatch(hostname, certificate)

  if (!domainMatched) {
    score += 30
    reasons.push('입력한 도메인과 인증서의 CN/SAN 정보가 일치하지 않습니다.')
  }

  const subjectCN = getFirstString(certificate.subject?.CN)
  const issuerCN = getFirstString(certificate.issuer?.CN)

  if (subjectCN && issuerCN && subjectCN === issuerCN) {
    score += 30
    reasons.push('Self-signed 인증서로 판단됩니다.')
  }

  if (score === 0) {
    reasons.push('인증서 유효기간과 도메인 정보가 정상으로 확인되었습니다.')
  }

  return {
    score,
    status: getStatus(score),
    reasons,
  }
}

function checkDomainMatch(hostname: string, certificate: CertificateData) {
  const names: string[] = []

  const subjectCN = certificate.subject?.CN
  const cnValue = getFirstString(subjectCN)

  if (cnValue) {
    names.push(cnValue)
  }

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
    return hostname.endsWith(`.${baseDomain}`)
  }

  return false
}

function getStatus(score: number): '안전' | '주의' | '위험' {
  if (score >= 60) return '위험'
  if (score >= 30) return '주의'
  return '안전'
}
