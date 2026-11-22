
import { useCallback, useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import './Dashboard.css'

interface Endpoint {
  endpoint_id: string
  platform: string
  status: string
  source_ip: string
  last_seen: string | null
  hostname: string | null
}

interface Case {
  case_id: string
  title: string
  description: string
  status: string
  created_at: string
}

interface EndpointsResponse {
  total: number
  endpoints: Endpoint[]
}

interface CasesResponse {
  success: boolean
  total: number
  cases: Case[]
}

interface Analysis {
  assessment_status: string
  investigation_priority: string
  summary: string
  generated_at: string
  metrics: {
    total_packets: number
    matched_packets: number
    unmatched_packets: number
    high_confidence_matches: number
    medium_confidence_matches: number
    verified_evidence: number
    modified_evidence: number
    missing_evidence: number
  }
  findings: {
    category: string
    status: string
    description: string
    recommendation?: string
  }[]
  classification_note: string
}

interface Integrity {
  integrity_status: string
  total_evidence: number
  verified: number
  modified: number
  missing: number
}

function formatDate(value: string | null) {
  if (!value) return 'Not available'

  const date = new Date(value)

  if (Number.isNaN(date.getTime())) return 'Not available'

  return date.toLocaleString()
}

function Dashboard() {
  const [endpoints, setEndpoints] = useState<Endpoint[]>([])
  const [cases, setCases] = useState<Case[]>([])
  const [analysis, setAnalysis] = useState<Analysis | null>(null)
  const [integrity, setIntegrity] = useState<Integrity | null>(null)

  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null)

  const loadDashboard = useCallback(async () => {
    try {
      setError('')

      const [endpointResponse, caseResponse] = await Promise.all([
        fetch('/api/endpoints'),
        fetch('/api/cases'),
      ])

      if (!endpointResponse.ok || !caseResponse.ok) {
        throw new Error('Unable to retrieve dashboard data.')
      }

      const endpointData: EndpointsResponse = await endpointResponse.json()
      const caseData: CasesResponse = await caseResponse.json()

      setEndpoints(endpointData.endpoints ?? [])
      setCases(caseData.cases ?? [])

      const latestCase = caseData.cases?.[0]

      if (latestCase) {
        const [analysisResponse, integrityResponse] = await Promise.all([
          fetch(`/api/cases/${latestCase.case_id}/analysis`),
          fetch(`/api/cases/${latestCase.case_id}/integrity`),
        ])

        if (!analysisResponse.ok || !integrityResponse.ok) {
          throw new Error('Unable to retrieve investigation details.')
        }

        const analysisData = await analysisResponse.json()
        const integrityData = await integrityResponse.json()

        setAnalysis(analysisData.analysis)
        setIntegrity(integrityData.integrity_report)
      } else {
        setAnalysis(null)
        setIntegrity(null)
      }

      setLastUpdated(new Date())
    } catch (err) {
      setError(
        err instanceof Error ? err.message : 'An unexpected error occurred.'
      )
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    void loadDashboard()

    const interval = window.setInterval(() => {
      void loadDashboard()
    }, 15000)

    return () => window.clearInterval(interval)
  }, [loadDashboard])

  const onlineCount = endpoints.filter(
    (endpoint) => endpoint.status === 'ONLINE'
  ).length

  const offlineCount = endpoints.filter(
    (endpoint) => endpoint.status === 'OFFLINE'
  ).length

  const metrics = analysis?.metrics

  return (
    <div className="dashboard-layout">

      {/* SIDEBAR */}
      <aside className="dashboard-sidebar">
        <Link to="/" className="dashboard-brand">
          <span className="dashboard-brand-icon">T</span>
          <span>TraceWeave</span>
        </Link>

        <div className="sidebar-section-label">WORKSPACE</div>

        <nav className="dashboard-nav">
          <a href="#overview" className="dashboard-nav-link active">
            <span>▦</span> Overview
          </a>

          <a href="#endpoints" className="dashboard-nav-link">
            <span>◉</span> Endpoints
          </a>

          <a href="#cases" className="dashboard-nav-link">
            <span>▤</span> Investigations
          </a>

          <a href="#network" className="dashboard-nav-link">
            <span>⌘</span> Network Analysis
          </a>

          <a href="#integrity" className="dashboard-nav-link">
            <span>◇</span> Evidence Integrity
          </a>
        </nav>

        <div className="sidebar-section-label">SYSTEM</div>

        <div className="dashboard-nav">
	 <Link to="/dashboard/reports" className="dashboard-nav-link">
	   <span>▧</span> Reports
	 </Link>
        </div>

        <div className="sidebar-bottom">
          <div className="sidebar-lab-card">
            <span className="lab-status-dot" />
            <div>
              <strong>Lab Environment</strong>
              <small>TraceWeave v1.0</small>
            </div>
          </div>

          <Link to="/" className="back-home-link">
            ← Back to Home
          </Link>
        </div>
      </aside>

      {/* MAIN CONTENT */}
      <main className="dashboard-main" id="overview">

        <header className="dashboard-topbar">
          <div>
            <div className="dashboard-breadcrumb">
              WORKSPACE / OVERVIEW
            </div>
            <h1>Investigation Overview</h1>
            <p>Monitor endpoints and review digital investigation evidence.</p>
          </div>

          <div className="dashboard-top-actions">
            <span className="connection-indicator">
              <span className="connection-dot" />
              API Connected
            </span>

            <button
              className="refresh-button"
              onClick={() => void loadDashboard()}
              disabled={loading}
            >
              ↻ {loading ? 'Loading...' : 'Refresh'}
            </button>
          </div>
        </header>

        {error && (
          <div className="dashboard-error">
            <strong>Dashboard update failed:</strong> {error}
            <button onClick={() => void loadDashboard()}>Try again</button>
          </div>
        )}

        {loading && !lastUpdated ? (
          <div className="dashboard-loading">
            <div className="loading-spinner" />
            <p>Loading investigation data...</p>
          </div>
        ) : (
          <>
            <div className="dashboard-welcome">
              <div>
                <span className="welcome-eyebrow">TRACEWEAVE MONITORING</span>
                <h2>Evidence at a glance.</h2>
                <p>
                  Your endpoint telemetry and investigation data in one place.
                </p>
              </div>

              <div className="welcome-decoration">T</div>
            </div>

            {/* SUMMARY CARDS */}
            <section className="dashboard-stats">

              <article className="stat-card">
                <div className="stat-card-top">
                  <span>Total Endpoints</span>
                  <span className="stat-icon">◉</span>
                </div>
                <strong>{endpoints.length}</strong>
                <small>
                  <span className="text-success">{onlineCount} online</span>
                  {' · '}
                  <span className="text-muted">{offlineCount} offline</span>
                </small>
              </article>

              <article className="stat-card">
                <div className="stat-card-top">
                  <span>Investigation Cases</span>
                  <span className="stat-icon">▤</span>
                </div>
                <strong>{cases.length}</strong>
                <small>Registered cases</small>
              </article>

              <article className="stat-card">
                <div className="stat-card-top">
                  <span>Network Packets</span>
                  <span className="stat-icon">⌘</span>
                </div>
                <strong>{metrics?.total_packets ?? '—'}</strong>
                <small>
                  {metrics
                    ? `${metrics.matched_packets} correlated packets`
                    : 'No analysis available'}
                </small>
              </article>

              <article className="stat-card">
                <div className="stat-card-top">
                  <span>Evidence Integrity</span>
                  <span className="stat-icon">◇</span>
                </div>
                <strong className="stat-integrity">
                  {integrity?.verified ?? '—'}
                  <span>/{integrity?.total_evidence ?? '—'}</span>
                </strong>
                <small>
                  {integrity?.integrity_status ?? 'Not available'}
                </small>
              </article>

            </section>

            {/* ENDPOINTS AND CASES */}
            <div className="dashboard-content-grid">

              <section className="dashboard-panel" id="endpoints">
                <div className="panel-header">
                  <div>
                    <span className="panel-eyebrow">MONITORING</span>
                    <h3>Endpoint Status</h3>
                  </div>
                  <span className="panel-count">
                    {endpoints.length} endpoints
                  </span>
                </div>

                {endpoints.length === 0 ? (
                  <p className="empty-state">No endpoints registered.</p>
                ) : (
                  <div className="endpoint-list">
                    {endpoints.map((endpoint) => (
                      <div className="endpoint-item" key={endpoint.endpoint_id}>
                        <div className="endpoint-avatar">
                          {endpoint.platform.toLowerCase().includes('windows')
                            ? 'W'
                            : 'L'}
                        </div>

                        <div className="endpoint-details">
                          <strong>{endpoint.endpoint_id}</strong>
                          <span>
                            {endpoint.platform} · {endpoint.source_ip}
                          </span>
                          <small>
                            Last seen: {formatDate(endpoint.last_seen)}
                          </small>
                        </div>

                        <span
                          className={`status-badge ${
                            endpoint.status === 'ONLINE'
                              ? 'status-online'
                              : 'status-offline'
                          }`}
                        >
                          <span />
                          {endpoint.status}
                        </span>
                      </div>
                    ))}
                  </div>
                )}
              </section>

              <section className="dashboard-panel" id="cases">
                <div className="panel-header">
                  <div>
                    <span className="panel-eyebrow">CASE MANAGEMENT</span>
                    <h3>Recent Investigations</h3>
                  </div>
                  <span className="panel-count">{cases.length} cases</span>
                </div>

                {cases.length === 0 ? (
                  <p className="empty-state">No investigation cases found.</p>
                ) : (
                  <div className="case-list">
                    {cases.map((item) => (
                      <div className="case-item" key={item.case_id}>
                        <div className="case-icon">▤</div>

                        <div className="case-details">
                          <strong>{item.title}</strong>
                          <span>{item.case_id}</span>
                          <small>{formatDate(item.created_at)}</small>
                        </div>

                        <span className="case-status">{item.status}</span>
                      </div>
                    ))}
                  </div>
                )}
              </section>

            </div>

            {/* NETWORK AND INTEGRITY */}
            <div className="dashboard-content-grid">

              <section className="dashboard-panel" id="network">
                <div className="panel-header">
                  <div>
                    <span className="panel-eyebrow">NETWORK FORENSICS</span>
                    <h3>Correlation Overview</h3>
                  </div>
                  <span className="panel-icon">⌘</span>
                </div>

                {metrics ? (
                  <>
                    <div className="correlation-total">
                      <strong>{metrics.matched_packets}</strong>
                      <span>of {metrics.total_packets} packets matched</span>
                    </div>

                    <div className="correlation-bar">
                      <div
                        style={{
                          width: `${
                            metrics.total_packets > 0
                              ? (metrics.matched_packets /
                                  metrics.total_packets) *
                                100
                              : 0
                          }%`,
                        }}
                      />
                    </div>

                    <div className="metric-row">
                      <span>Matched packets</span>
                      <strong>{metrics.matched_packets}</strong>
                    </div>

                    <div className="metric-row">
                      <span>Unmatched packets</span>
                      <strong>{metrics.unmatched_packets}</strong>
                    </div>

                    <div className="metric-row">
                      <span>High-confidence matches</span>
                      <strong>{metrics.high_confidence_matches}</strong>
                    </div>

                    <div className="metric-row">
                      <span>Medium-confidence matches</span>
                      <strong>{metrics.medium_confidence_matches}</strong>
                    </div>
                  </>
                ) : (
                  <p className="empty-state">
                    No correlation analysis available.
                  </p>
                )}
              </section>

              <section className="dashboard-panel" id="integrity">
                <div className="panel-header">
                  <div>
                    <span className="panel-eyebrow">EVIDENCE PROTECTION</span>
                    <h3>Evidence Integrity</h3>
                  </div>
                  <span className="panel-icon">◇</span>
                </div>

                {integrity ? (
                  <>
                    <div className="integrity-status">
                      <span className="integrity-check">✓</span>
                      <div>
                        <strong>{integrity.integrity_status}</strong>
                        <small>SHA-256 verification result</small>
                      </div>
                    </div>

                    <div className="integrity-counts">
                      <div>
                        <strong>{integrity.verified}</strong>
                        <span>Verified</span>
                      </div>

                      <div>
                        <strong>{integrity.modified}</strong>
                        <span>Modified</span>
                      </div>

                      <div>
                        <strong>{integrity.missing}</strong>
                        <span>Missing</span>
                      </div>
                    </div>

                    <div className="integrity-total">
                      Total evidence files: {integrity.total_evidence}
                    </div>
                  </>
                ) : (
                  <p className="empty-state">
                    No integrity report available.
                  </p>
                )}
              </section>

            </div>

            {/* FINDINGS */}
            <section className="dashboard-panel findings-panel">
              <div className="panel-header">
                <div>
                  <span className="panel-eyebrow">INVESTIGATION RESULTS</span>
                  <h3>Latest Findings</h3>
                </div>

                {analysis && (
                  <span className="priority-badge">
                    Priority: {analysis.investigation_priority}
                  </span>
                )}
              </div>

              {analysis ? (
                <>
                  <p className="analysis-summary">{analysis.summary}</p>

                  <div className="findings-list">
                    {analysis.findings.map((finding, index) => (
                      <div className="finding-item" key={`${finding.category}-${index}`}>
                        <div className="finding-check">✓</div>

                        <div>
                          <strong>
                            {finding.category.replaceAll('_', ' ')}
                          </strong>
                          <span>
                            {finding.description}
                          </span>
                        </div>

                        <span className="finding-status">
                          {finding.status}
                        </span>
                      </div>
                    ))}
                  </div>

                  <p className="classification-note">
                    {analysis.classification_note}
                  </p>
                </>
              ) : (
                <p className="empty-state">
                  No investigation findings available.
                </p>
              )}
            </section>

            {/* FOOTER */}
            <footer className="dashboard-footer" id="reports">
              <span>
                TraceWeave · An Integrity-Verified Investigation Platform
              </span>

              <span>
                Last updated:{' '}
                {lastUpdated ? lastUpdated.toLocaleTimeString() : '—'}
              </span>
            </footer>
          </>
        )}
      </main>
    </div>
  )
}

export default Dashboard
