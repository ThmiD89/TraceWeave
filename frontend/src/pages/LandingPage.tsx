
import '../App.css'
import { Link } from 'react-router-dom'

function LandingPage() {
  return (
    <main>
      {/* Navigation and Hero */}
      <section className="hero-section">
        <nav className="navbar">
          <a href="#" className="brand">
            <span className="brand-icon">T</span>
            TraceWeave
          </a>

          <div className="nav-links">
            <a href="#platform">Platform</a>
            <a href="#features">Features</a>
            <a href="#about">About</a>
          </div>

          <Link to="/dashboard" className="nav-button">
            Explore Platform
          </Link>
        </nav>

        <div className="hero-content">
          <span className="eyebrow">
            CYBERSECURITY INVESTIGATION PLATFORM
          </span>

          <h1>
            Connect the evidence.
            <br />
            <span>Reveal the story.</span>
          </h1>

          <p>
            An integrity-verified platform for correlating endpoint
            telemetry and network evidence across Windows and Linux
            environments.
          </p>

          <div className="hero-actions">
            <Link to="/dashboard" className="primary-button">
              Explore TraceWeave <span>→</span>
            </Link>

            <a href="#features" className="secondary-button">
              Discover Features
            </a>
          </div>

          <div className="hero-visual">
            <div className="visual-window">
              <div className="window-header">
                <div className="window-dots">
                  <span />
                  <span />
                  <span />
                </div>
                <span>TRACEWEAVE / INVESTIGATION OVERVIEW</span>
                <span className="window-status">LAB ENVIRONMENT</span>
              </div>

              <div className="visual-content">
                <div className="visual-sidebar">
                  <div className="sidebar-logo">T</div>
                  <span>Overview</span>
                  <span>Endpoints</span>
                  <span>Investigations</span>
                  <span>Evidence</span>
                </div>

                <div className="visual-main">
                  <div className="visual-heading">
                    <div>
                      <small>INVESTIGATION OVERVIEW</small>
                      <h3>Evidence at a glance</h3>
                    </div>
                    <span className="live-indicator">● LAB ACTIVE</span>
                  </div>

                  <div className="visual-stats">
                    <div className="visual-stat">
                      <small>ENDPOINTS</small>
                      <strong>02</strong>
                      <span>Windows & Ubuntu</span>
                    </div>

                    <div className="visual-stat">
                      <small>NETWORK EVIDENCE</small>
                      <strong>PCAP</strong>
                      <span>Packet analysis</span>
                    </div>

                    <div className="visual-stat">
                      <small>INTEGRITY</small>
                      <strong>SHA-256</strong>
                      <span>Evidence verification</span>
                    </div>
                  </div>

                  <div className="visual-timeline">
                    <div className="timeline-line" />
                    <span>Endpoint telemetry received</span>
                    <span>Network event correlated</span>
                    <span>Evidence integrity verified</span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Platform Introduction */}
      <section className="intro-section" id="platform">
        <div className="section-heading">
          <span className="eyebrow coral-text">INTRODUCING TRACEWEAVE</span>
          <h2>
            Making digital investigations
            <br />
            <span>more connected.</span>
          </h2>
          <p>
            TraceWeave brings endpoint telemetry, network traffic and
            digital evidence together in one investigation environment.
          </p>
        </div>

        <div className="feature-grid" id="features">
          <article className="feature-card">
            <div className="feature-icon coral-icon">⌘</div>
            <span className="feature-number">01 / MONITOR</span>
            <h3>Endpoint Telemetry</h3>
            <p>
              Monitor Windows and Linux endpoints through structured
              heartbeat and system information collection.
            </p>
            <a href="#about">Explore capability →</a>
          </article>

          <article className="feature-card">
            <div className="feature-icon blue-icon">⌁</div>
            <span className="feature-number">02 / ANALYZE</span>
            <h3>Network Forensics</h3>
            <p>
              Analyze packet captures and connect network activity
              with corresponding endpoint events.
            </p>
            <a href="#about">Explore capability →</a>
          </article>

          <article className="feature-card">
            <div className="feature-icon purple-icon">◎</div>
            <span className="feature-number">03 / INVESTIGATE</span>
            <h3>Case Management</h3>
            <p>
              Organize investigation evidence and build chronological
              event timelines for analysis.
            </p>
            <a href="#about">Explore capability →</a>
          </article>

          <article className="feature-card">
            <div className="feature-icon green-icon">✓</div>
            <span className="feature-number">04 / VERIFY</span>
            <h3>Evidence Integrity</h3>
            <p>
              Use SHA-256 hashes and evidence manifests to detect
              changes to collected investigation artifacts.
            </p>
            <a href="#about">Explore capability →</a>
          </article>
        </div>
      </section>

      {/* Dark Feature Section */}
      <section className="workflow-section" id="about">
        <div className="workflow-content">
          <span className="eyebrow">THE TRACEWEAVE APPROACH</span>

          <h2>
            Every event has a story.
            <br />
            <span>Every piece of evidence matters.</span>
          </h2>

          <p>
            A heartbeat tells us what an endpoint reported.
            A packet capture tells us what happened across the network.
            TraceWeave helps investigators connect those two perspectives
            and examine the integrity of the evidence.
          </p>

          <Link to="/dashboard" className="workflow-button">
            Explore the dashboard →
          </Link>
        </div>

        <div className="workflow-steps">
          <div className="workflow-step">
            <span>01</span>
            <div>
              <h3>Collect</h3>
              <p>Gather endpoint telemetry and network evidence.</p>
            </div>
          </div>

          <div className="workflow-step">
            <span>02</span>
            <div>
              <h3>Correlate</h3>
              <p>Connect related events using timestamps and identifiers.</p>
            </div>
          </div>

          <div className="workflow-step">
            <span>03</span>
            <div>
              <h3>Verify</h3>
              <p>Check evidence against its SHA-256 manifest.</p>
            </div>
          </div>
        </div>
      </section>

      {/* Technology Section */}
      <section className="technology-section">
        <span className="eyebrow coral-text">BUILT FOR INVESTIGATION</span>
        <h2>One platform. Multiple evidence sources.</h2>
        <p>
          Designed around a controlled cross-platform cybersecurity
          laboratory.
        </p>

        <div className="technology-list">
          <span>Windows</span>
          <span>Ubuntu Linux</span>
          <span>Kali Linux</span>
          <span>FastAPI</span>
          <span>Wireshark</span>
          <span>SHA-256</span>
        </div>
      </section>

      {/* Footer */}
      <footer className="footer">
        <div>
          <a href="#" className="brand footer-brand">
            <span className="brand-icon">T</span>
            TraceWeave
          </a>
          <p>
            An Integrity-Verified Platform for Correlating
            Endpoint Telemetry and Network Evidence.
          </p>
        </div>

        <div className="footer-right">
          <span>CYBERSECURITY ENGINEERING PROJECT</span>
          <span>© 2026 TraceWeave</span>
        </div>
      </footer>
    </main>
  )
}

export default LandingPage
