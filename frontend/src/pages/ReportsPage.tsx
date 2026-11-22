
import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import './ReportsPage.css'

interface InvestigationCase {
  case_id: string
  title: string
  description: string
  status: string
  created_at: string
}

interface CasesResponse {
  success: boolean
  total: number
  cases: InvestigationCase[]
}

interface AnalysisResponse {
  success: boolean
  analysis: {
    assessment_status: string
    investigation_priority: string
    generated_at: string
    summary: string
  }
}

function formatDate(value?: string) {
  if (!value) return 'Not available'

  const date = new Date(value)

  return Number.isNaN(date.getTime())
    ? 'Not available'
    : date.toLocaleString()
}

function ReportsPage() {
  const [cases, setCases] = useState<InvestigationCase[]>([])
  const [selectedCaseId, setSelectedCaseId] = useState('')
  const [analysis, setAnalysis] =
    useState<AnalysisResponse['analysis'] | null>(null)

  const [loadingCases, setLoadingCases] = useState(true)
  const [loadingAnalysis, setLoadingAnalysis] = useState(false)
  const [error, setError] = useState('')

  useEffect(() => {
    async function loadCases() {
      try {
        setError('')

        const response = await fetch('/api/cases')

        if (!response.ok) {
          throw new Error('Could not retrieve investigation cases.')
        }

        const data: CasesResponse = await response.json()
        const availableCases = data.cases ?? []

        setCases(availableCases)

        if (availableCases.length > 0) {
          setSelectedCaseId(availableCases[0].case_id)
        }
      } catch (err) {
        setError(
          err instanceof Error ? err.message : 'An unexpected error occurred.'
        )
      } finally {
        setLoadingCases(false)
      }
    }

    void loadCases()
  }, [])

  useEffect(() => {
    if (!selectedCaseId) {
      setAnalysis(null)
      return
    }

    const controller = new AbortController()

    async function loadAnalysis() {
      try {
        setLoadingAnalysis(true)
        setError('')
        setAnalysis(null)

        const response = await fetch(
          `/api/cases/${selectedCaseId}/analysis`,
          { signal: controller.signal }
        )

        if (!response.ok) {
          throw new Error('Could not retrieve the selected case analysis.')
        }

        const data: AnalysisResponse = await response.json()
        setAnalysis(data.analysis)
      } catch (err) {
        if (err instanceof Error && err.name === 'AbortError') return

        setError(
          err instanceof Error ? err.message : 'Unable to load report details.'
        )
      } finally {
        if (!controller.signal.aborted) {
          setLoadingAnalysis(false)
        }
      }
    }

    void loadAnalysis()

    return () => controller.abort()
  }, [selectedCaseId])

  const selectedCase = cases.find(
    (item) => item.case_id === selectedCaseId
  )

  const reportUrl = selectedCaseId
    ? `/api/cases/${selectedCaseId}/reports`
    : ''

  return (
    <div className="reports-layout">
      <aside className="reports-sidebar">
        <Link to="/" className="reports-brand">
          <span className="reports-brand-icon">T</span>
          TraceWeave
        </Link>

        <span className="reports-nav-label">WORKSPACE</span>

        <nav className="reports-navigation">
          <Link to="/dashboard" className="reports-nav-link">
            <span>▦</span> Overview
          </Link>

          <Link
            to="/dashboard/reports"
            className="reports-nav-link active"
          >
            <span>▧</span> Reports
          </Link>
        </nav>

        <div className="reports-sidebar-bottom">
          <span className="reports-lab-dot" />
          <div>
            <strong>Lab Environment</strong>
            <small>TraceWeave v1.0</small>
          </div>
        </div>
      </aside>

      <main className="reports-main">
        <header className="reports-header">
          <div>
            <div className="reports-breadcrumb">
              WORKSPACE / REPORTS
            </div>
            <h1>Investigation Reports</h1>
            <p>
              Generate and download reports from your investigation cases.
            </p>
          </div>

          <Link to="/dashboard" className="reports-back-button">
            ← Dashboard
          </Link>
        </header>

        {error && (
          <div className="reports-error">
            {error}
          </div>
        )}

        <section className="reports-intro">
          <div>
            <span>TRACEWEAVE REPORT CENTER</span>
            <h2>Evidence, organized and documented.</h2>
            <p>
              Export investigation findings, network correlation results,
              case metadata, and SHA-256 integrity information.
            </p>
          </div>

          <div className="reports-intro-icon">▤</div>
        </section>

        <section className="reports-panel">
          <div className="reports-panel-heading">
            <div>
              <span className="reports-eyebrow">REPORT CONFIGURATION</span>
              <h2>Select an investigation case</h2>
            </div>

            <span className="reports-case-count">
              {cases.length} cases available
            </span>
          </div>

          {loadingCases ? (
            <p className="reports-message">Loading investigation cases...</p>
          ) : cases.length === 0 ? (
            <p className="reports-message">
              No investigation cases are available yet.
            </p>
          ) : (
            <>
              <label htmlFor="report-case-select" className="reports-label">
                Investigation case
              </label>

              <select
                id="report-case-select"
                className="reports-select"
                value={selectedCaseId}
                onChange={(event) => setSelectedCaseId(event.target.value)}
              >
                {cases.map((item) => (
                  <option key={item.case_id} value={item.case_id}>
                    {item.title} — {item.case_id}
                  </option>
                ))}
              </select>

              {selectedCase && (
                <div className="selected-case-card">
                  <div className="selected-case-icon">▤</div>

                  <div className="selected-case-details">
                    <span>SELECTED INVESTIGATION</span>
                    <h3>{selectedCase.title}</h3>
                    <p>{selectedCase.description}</p>
                    <small>{selectedCase.case_id}</small>
                  </div>

                  <span className="selected-case-status">
                    {selectedCase.status}
                  </span>
                </div>
              )}
            </>
          )}
        </section>

        {selectedCase && (
          <>
            <section className="reports-panel reports-metadata">
              <div className="reports-panel-heading">
                <div>
                  <span className="reports-eyebrow">CASE INFORMATION</span>
                  <h2>Report metadata</h2>
                </div>
              </div>

              <div className="reports-metadata-grid">
                <div>
                  <span>Case ID</span>
                  <strong>{selectedCase.case_id}</strong>
                </div>

                <div>
                  <span>Case status</span>
                  <strong>{selectedCase.status}</strong>
                </div>

                <div>
                  <span>Case created</span>
                  <strong>{formatDate(selectedCase.created_at)}</strong>
                </div>

                <div>
                  <span>Latest analysis</span>
                  <strong>
                    {loadingAnalysis
                      ? 'Loading...'
                      : formatDate(analysis?.generated_at)}
                  </strong>
                </div>

                <div>
                  <span>Investigation priority</span>
                  <strong>
                    {analysis?.investigation_priority ?? 'Not available'}
                  </strong>
                </div>

                <div>
                  <span>Assessment status</span>
                  <strong>
                    {analysis?.assessment_status ?? 'Not available'}
                  </strong>
                </div>
              </div>

              {analysis && (
                <p className="reports-summary">
                  {analysis.summary}
                </p>
              )}
            </section>

            <section className="reports-download-section">
              <div className="reports-section-heading">
                <span className="reports-eyebrow">EXPORT INVESTIGATION</span>
                <h2>Download your reports</h2>
                <p>
                  Reports are generated by the backend when you request a
                  download.
                </p>
              </div>

              <div className="report-download-grid">
                <article className="report-download-card">
                  <div className="report-file-icon pdf-icon">PDF</div>

                  <h3>PDF Investigation Report</h3>

                  <p>
                    A formatted A4 report containing case information,
                    investigation findings, correlation statistics, and
                    evidence integrity results.
                  </p>

                  <a
                    className="report-download-button pdf-button"
                    href={`${reportUrl}/pdf`}
                  >
                    ↓ Download PDF
                  </a>
                </article>

                <article className="report-download-card">
                  <div className="report-file-icon json-icon">JSON</div>

                  <h3>JSON Investigation Report</h3>

                  <p>
                    Structured investigation data suitable for further
                    analysis, processing, and integration with other tools.
                  </p>

                  <a
                    className="report-download-button json-button"
                    href={`${reportUrl}/json`}
                  >
                    ↓ Download JSON
                  </a>
                </article>
              </div>
            </section>
          </>
        )}

        <footer className="reports-footer">
          TraceWeave · Integrity-Verified Investigation Platform
        </footer>
      </main>
    </div>
  )
}

export default ReportsPage
