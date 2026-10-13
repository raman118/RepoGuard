"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import {
  ArrowUpRight,
  Check,
  ChevronRight,
  CircleDot,
  GitBranch,
  GitFork as Github,
  History,
  LoaderCircle,
  LockKeyhole,
  Play,
  ShieldCheck,
  Terminal,
  TriangleAlert,
} from "lucide-react";
import { api, ApiError, type Repository, type Scan } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { ProposalCard } from "@/components/proposal-card";

export default function Dashboard() {
  const [token, setToken] = useState("");
  const [input, setInput] = useState("");
  const [repositories, setRepositories] = useState<Repository[]>([]);
  const [repository, setRepository] = useState<Repository | null>(null);
  const [scans, setScans] = useState<Scan[]>([]);
  const [scan, setScan] = useState<Scan | null>(null);
  const [fixtures, setFixtures] = useState<{ id: string; sha: string }[]>([]);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [filter, setFilter] = useState("all");
  const [remote, setRemote] = useState({
    owner: "",
    name: "",
    installation: "",
  });
  const session = useRef(0);

  const action = useCallback(async (work: () => Promise<void>) => {
    const generation = session.current;
    setBusy(true);
    setError("");
    try {
      await work();
    } catch (e) {
      if (generation === session.current)
        setError(
          e instanceof ApiError
            ? e.message
            : "Request failed. Please try again.",
        );
    } finally {
      if (generation === session.current) setBusy(false);
    }
  }, []);

  useEffect(() => {
    if (!token) return;
    const controller = new AbortController();
    async function load() {
      setBusy(true);
      setError("");
      try {
        const rows = await api<Repository[]>(
          token,
          "/v1/repositories",
          undefined,
          controller.signal,
        );
        const catalog = await api<{ id: string; sha: string }[]>(
          token,
          "/v1/fixtures",
          undefined,
          controller.signal,
        ).catch(() => []);
        if (controller.signal.aborted) return;
        setRepositories(rows);
        setRepository(rows[0] ?? null);
        setFixtures(catalog);
      } catch (e) {
        if (!controller.signal.aborted)
          setError(e instanceof ApiError ? e.message : "API unavailable");
      } finally {
        if (!controller.signal.aborted) setBusy(false);
      }
    }
    void load();
    return () => controller.abort();
  }, [token]);

  useEffect(() => {
    if (!token || !repository) return;
    const controller = new AbortController();
    api<Scan[]>(
      token,
      `/v1/repositories/${repository.id}/scans`,
      undefined,
      controller.signal,
    )
      .then((rows) => {
        if (!controller.signal.aborted) {
          setScans(rows);
          setScan(rows[0] ?? null);
        }
      })
      .catch((e) => {
        if (!controller.signal.aborted)
          setError(e instanceof ApiError ? e.message : "History unavailable");
      });
    return () => controller.abort();
  }, [token, repository]);

  useEffect(() => {
    if (!token || !scan || !["queued", "running"].includes(scan.state)) return;
    const controller = new AbortController();
    const timer = setInterval(() => {
      api<Scan>(token, `/v1/scans/${scan.id}`, undefined, controller.signal)
        .then((row) => {
          if (!controller.signal.aborted) {
            setScan(row);
            setScans((rows) => [row, ...rows.filter((s) => s.id !== row.id)]);
          }
        })
        .catch((e) => {
          if (!controller.signal.aborted)
            setError(
              e instanceof ApiError ? e.message : "Scan status unavailable",
            );
        });
    }, 1500);
    return () => {
      clearInterval(timer);
      controller.abort();
    };
  }, [token, scan]);

  function disconnect() {
    session.current++;
    setToken("");
    setInput("");
    setRepositories([]);
    setRepository(null);
    setScans([]);
    setScan(null);
    setFixtures([]);
    setError("");
    setBusy(false);
  }
  async function connect(fixture?: string) {
    const generation = session.current;
    const row = await api<Repository>(
      token,
      "/v1/repositories",
      fixture
        ? { owner: "fixture", name: fixture, fixture_id: fixture }
        : {
            owner: remote.owner,
            name: remote.name,
            installation_id: Number(remote.installation),
          },
    );
    if (generation !== session.current) return;
    setRepositories((rows) => [row, ...rows]);
    setScan(null);
    setRepository(row);
  }
  async function startScan() {
    if (!repository) return;
    const generation = session.current;
    const head = await api<{ sha: string }>(
      token,
      `/v1/repositories/${repository.id}/head`,
    );
    const row = await api<Scan>(
      token,
      `/v1/repositories/${repository.id}/scans`,
      { sha: head.sha, idempotency_key: crypto.randomUUID() },
    );
    if (generation !== session.current) return;
    setScan(row);
    setScans((rows) => [row, ...rows]);
  }

  const score = scan?.result?.score;
  const active = scan && ["queued", "running"].includes(scan.state);
  const findings =
    scan?.findings.filter((f) => filter === "all" || f.category === filter) ??
    [];

  return (
    <div className="shell">
      <aside className="sidebar">
        <a href="#overview" className="brand">
          <span className="brand-icon">
            <ShieldCheck size={23} />
          </span>
          repo<span>guard</span>
        </a>
        <div className="workspace">
          <span className="avatar">RG</span>
          <div>
            Engineering workspace<small>Repository readiness</small>
          </div>
        </div>
        <p className="nav-caption">WORKSPACE</p>
        <a href="#overview" className="nav-item selected">
          <CircleDot size={18} /> Overview
        </a>
        <a href="#risks" className="nav-item">
          <ShieldCheck size={18} /> Findings{" "}
          <span className="nav-count">{scan?.findings.length ?? 0}</span>
        </a>
        <a href="#history" className="nav-item">
          <History size={18} /> Scan history
        </a>
        <p className="nav-caption repo-caption">REPOSITORIES</p>
        {repositories.map((row) => (
          <button
            key={row.id}
            className={`repo-nav ${row.id === repository?.id ? "current" : ""}`}
            onClick={() => {
              setScan(null);
              setRepository(row);
            }}
          >
            <GitBranch size={15} />
            <span>{row.name}</span>
            <ChevronRight size={14} />
          </button>
        ))}
        {!repositories.length && (
          <p className="sidebar-empty">Connect a repository to begin.</p>
        )}
        <div className="sidebar-footer">
          <LockKeyhole size={17} />
          <div>
            Human approval required
            <small>Fixes never merge automatically</small>
          </div>
        </div>
      </aside>
      <main id="overview">
        <header className="topbar">
          <div className="breadcrumbs">
            Workspace <ChevronRight size={13} />
            <span>Overview</span>
          </div>
          <div className="session-label">
            <span className="status-dot" />
            {token ? "Authenticated session" : "Local development"}
            {token && <button onClick={disconnect}>Disconnect</button>}
          </div>
        </header>
        <div className="content">
          <div className="page-title">
            <div>
              <div className="eyebrow">KNOW BEFORE YOU SHIP</div>
              <h1>Repository readiness</h1>
              <p>
                Find the risks. Understand the evidence. Ship with confidence.
              </p>
            </div>
            <span className="policy-tag">
              <ShieldCheck size={15} /> Policy v1
            </span>
          </div>
          {error && (
            <div
              className="error-banner"
              role="alert"
              aria-label="Workspace error"
            >
              <TriangleAlert size={18} />
              {error}
            </div>
          )}
          {!token ? (
            <section className="auth-card">
              <div className="auth-art">
                <ShieldCheck size={48} />
                <h2>
                  Your next release,
                  <br />
                  with fewer unknowns.
                </h2>
                <p>
                  Deterministic analysis. Explainable scores.
                  <br />A clear path from finding to reviewed fix.
                </p>
                <div className="auth-note">
                  <Check size={16} /> Source is treated as untrusted data
                </div>
              </div>
              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  session.current++;
                  setToken(input.trim());
                }}
              >
                <span className="eyebrow">CONNECT YOUR WORKSPACE</span>
                <h2>Start with a secure session</h2>
                <p>
                  Use your operator-provisioned RepoGuard token. It stays in
                  this tab’s memory.
                </p>
                <label htmlFor="token">Access token</label>
                <input
                  id="token"
                  type="password"
                  autoComplete="off"
                  value={input}
                  onChange={(e) => setInput(e.target.value)}
                  placeholder="Enter your bearer token"
                  required
                />
                <Button type="submit">
                  Open workspace <ArrowUpRight size={16} />
                </Button>
                <div className="form-help">
                  <Terminal size={15} />
                  <span>
                    Create a local identity with the documented setup command.
                  </span>
                </div>
              </form>
            </section>
          ) : (
            <>
              <section className="connection panel">
                <div>
                  <h2>
                    <Github size={20} /> Connected repositories
                  </h2>
                  <p>
                    Select a repository or connect an installed GitHub App
                    repository.
                  </p>
                </div>
                <form
                  onSubmit={(e) => {
                    e.preventDefault();
                    void action(() => connect());
                  }}
                  className="connection-form"
                >
                  <input
                    aria-label="GitHub owner"
                    placeholder="owner"
                    value={remote.owner}
                    required
                    onChange={(e) =>
                      setRemote({ ...remote, owner: e.target.value })
                    }
                  />
                  <input
                    aria-label="GitHub repository"
                    placeholder="repository"
                    value={remote.name}
                    required
                    onChange={(e) =>
                      setRemote({ ...remote, name: e.target.value })
                    }
                  />
                  <input
                    aria-label="Installation ID"
                    placeholder="Installation ID"
                    type="number"
                    min="1"
                    required
                    value={remote.installation}
                    onChange={(e) =>
                      setRemote({ ...remote, installation: e.target.value })
                    }
                  />
                  <Button variant="outline" disabled={busy}>
                    Connect GitHub
                  </Button>
                </form>
                {fixtures.length > 0 && (
                  <div className="fixture-row">
                    <span className="fixture-label">OFFLINE FIXTURES</span>
                    {fixtures
                      .filter(
                        (f) => !repositories.some((r) => r.fixture_id === f.id),
                      )
                      .map((f) => (
                        <Button
                          key={f.id}
                          variant="outline"
                          disabled={busy}
                          onClick={() => void action(() => connect(f.id))}
                        >
                          Connect {f.id} fixture
                        </Button>
                      ))}
                    <small>
                      Real local analysis · content-pinned snapshots
                    </small>
                  </div>
                )}
              </section>
              {repository ? (
                <>
                  <div className="repository-heading">
                    <div>
                      <div className="repo-path">
                        <Github size={21} />
                        <h2>
                          {repository.owner}
                          <span>/</span>
                          {repository.name}
                        </h2>
                        <span className="badge">
                          {repository.fixture_id
                            ? "Local fixture"
                            : "GitHub App"}
                        </span>
                      </div>
                      <p>
                        <GitBranch size={14} />
                        {scan ? scan.sha.slice(0, 12) : "Immutable snapshot"}
                        {scan && (
                          <>
                            {" "}
                            · {new Date(scan.created_at).toLocaleString()}{" "}
                            <span className={`job-state ${scan.state}`}>
                              {scan.state}
                            </span>
                          </>
                        )}
                      </p>
                    </div>
                    <Button
                      onClick={() => void action(startScan)}
                      disabled={busy || !!active}
                    >
                      {busy ? (
                        <LoaderCircle size={16} className="spin" />
                      ) : (
                        <Play size={15} />
                      )}{" "}
                      Run scan
                    </Button>
                  </div>
                  <section className="summary-grid">
                    <div className="score-panel panel">
                      <div className="score-heading">
                        <span>READINESS SCORE</span>
                        <ShieldCheck size={19} />
                      </div>
                      <div className="score-body">
                        <div
                          className="score-ring"
                          style={
                            {
                              "--score": `${(score?.value ?? 0) * 3.6}deg`,
                            } as React.CSSProperties
                          }
                        >
                          <div>
                            <strong>{score?.value ?? "—"}</strong>
                            <small>OUT OF 100</small>
                          </div>
                        </div>
                        <div>
                          <h2>
                            {active
                              ? "Analysis in progress"
                              : score
                                ? score.value >= 80
                                  ? "Review remaining risks"
                                  : "A clear path to improve"
                                : "Ready for your first scan"}
                          </h2>
                          <p>
                            {active
                              ? `Job ${scan?.state}. Attempt ${scan?.job?.attempts ?? 0} of 3.`
                              : score
                                ? `${score.coverage_points}/100 weighted coverage points. Unknown controls earn zero.`
                                : "Run a scan to see evidence-backed results."}
                          </p>
                          {active && (
                            <Button
                              variant="outline"
                              disabled={busy}
                              onClick={() =>
                                void action(async () => {
                                  const row = await api<Scan>(
                                    token,
                                    `/v1/scans/${scan.id}/cancel`,
                                    {},
                                  );
                                  setScan(row);
                                })
                              }
                            >
                              Cancel scan
                            </Button>
                          )}
                          {scan?.state === "failed" && (
                            <p className="failure-code">
                              {scan.job?.error_code ?? "Scan failed"}
                            </p>
                          )}
                        </div>
                      </div>
                      <div className="score-footer">
                        {score?.policy_version ?? "readiness/1"}{" "}
                        <span>
                          Supported controls only · no safety certification
                        </span>
                      </div>
                    </div>
                    <div className="stat-panel panel">
                      <span className="stat-icon risk">
                        <TriangleAlert size={20} />
                      </span>
                      <strong>{scan?.findings.length ?? "—"}</strong>
                      <h3>Findings to review</h3>
                      <p>
                        {scan?.findings.filter((f) => f.severity === "high")
                          .length ?? 0}{" "}
                        high severity · exact file evidence
                      </p>
                    </div>
                    <div className="stat-panel panel">
                      <span className="stat-icon coverage">
                        <Check size={20} />
                      </span>
                      <strong>
                        {score
                          ? Object.values(scan?.result?.coverage ?? {}).filter(
                              (c) => c.status === "scanned",
                            ).length
                          : "—"}
                        <small> / 7</small>
                      </strong>
                      <h3>Controls scanned</h3>
                      <p>Coverage gaps stay visible</p>
                    </div>
                  </section>
                  <section className="panel category-panel">
                    <div className="section-heading">
                      <h2>Readiness by category</h2>
                      <span>Versioned weights, visible deductions</span>
                    </div>
                    <div className="categories">
                      {Object.entries(
                        score?.categories ?? {
                          security: null,
                          reliability: null,
                          deployment: null,
                          dependencies: null,
                          maintainability: null,
                        },
                      ).map(([name, category]) => (
                        <div className="category" key={name}>
                          <div>
                            <span>{name}</span>
                            <span
                              className={`category-status ${category?.status ?? "unknown"}`}
                            >
                              {category?.status ?? "unknown"}
                            </span>
                          </div>
                          <strong>
                            {category?.earned_points ?? "—"}
                            <small> / {category?.weight ?? "—"}</small>
                          </strong>
                          <div className="progress-track">
                            <span
                              style={{
                                width: `${category ? (category.earned_points / category.weight) * 100 : 0}%`,
                              }}
                            />
                          </div>
                          <small>
                            {category
                              ? `${category.rules_scanned}/${category.rules_total} controls · ${category.deductions.length} deductions`
                              : "Awaiting analysis"}
                          </small>
                        </div>
                      ))}
                    </div>
                  </section>
                  <section className="panel findings-panel" id="risks">
                    <div className="section-heading">
                      <div>
                        <h2>
                          Findings & evidence{" "}
                          <span className="count-pill">{findings.length}</span>
                        </h2>
                        <p>
                          Every finding has a reason, a location, and a
                          recommended next step.
                        </p>
                      </div>
                      <label className="filter">
                        Category
                        <select
                          aria-label="Filter findings"
                          value={filter}
                          onChange={(e) => setFilter(e.target.value)}
                        >
                          {[
                            "all",
                            "security",
                            "reliability",
                            "deployment",
                            "dependencies",
                            "maintainability",
                          ].map((value) => (
                            <option key={value}>{value}</option>
                          ))}
                        </select>
                      </label>
                    </div>
                    {findings.map((finding) => (
                      <details className="finding" key={finding.id}>
                        <summary>
                          <span className={`severity ${finding.severity}`}>
                            {finding.severity}
                          </span>
                          <div>
                            <strong>{finding.explanation}</strong>
                            <small>
                              {finding.rule_id} <span>·</span> {finding.path}:
                              {finding.line}
                            </small>
                          </div>
                          <ChevronRight size={17} />
                        </summary>
                        <div className="finding-detail">
                          <span className="eyebrow">EVIDENCE</span>
                          <pre>{finding.evidence}</pre>
                          <span className="eyebrow">
                            RECOMMENDED REMEDIATION
                          </span>
                          <p>{finding.remediation}</p>
                          <ProposalCard
                            key={`${scan?.id}-${finding.id}`}
                            token={token}
                            scanId={scan!.id}
                            finding={finding}
                          />
                        </div>
                      </details>
                    ))}
                    {!findings.length && (
                      <div className="empty-state">
                        <ShieldCheck size={28} />
                        <h3>
                          {score
                            ? "No findings in this view"
                            : "Your evidence will appear here"}
                        </h3>
                        <p>
                          {score
                            ? "Review rule coverage before interpreting this result."
                            : "Run a scan to inspect supported controls."}
                        </p>
                      </div>
                    )}
                  </section>
                  {scan?.result && (
                    <section className="panel coverage-panel">
                      <div className="section-heading">
                        <h2>Rule coverage</h2>
                        <span>Unknown is never a pass</span>
                      </div>
                      {Object.entries(scan.result.coverage).map(
                        ([rule, item]) => (
                          <div key={rule} className="coverage-row">
                            <code>{rule}</code>
                            <span className={`category-status ${item.status}`}>
                              {item.status}
                            </span>
                            <span>{item.reason.replaceAll("_", " ")}</span>
                          </div>
                        ),
                      )}
                    </section>
                  )}
                  <section className="panel history-panel" id="history">
                    <div className="section-heading">
                      <h2>Scan history</h2>
                      <span>{scans.length} recent scans</span>
                    </div>
                    {scans.map((row) => (
                      <button
                        key={row.id}
                        className={`history-row ${row.id === scan?.id ? "active-history" : ""}`}
                        onClick={() => setScan(row)}
                      >
                        <GitBranch size={16} />
                        <code>{row.sha.slice(0, 12)}</code>
                        <span>{new Date(row.created_at).toLocaleString()}</span>
                        <span className={`job-state ${row.state}`}>
                          {row.state}
                        </span>
                        <strong>{row.result?.score.value ?? "—"}</strong>
                        <ChevronRight size={16} />
                      </button>
                    ))}
                    {!scans.length && (
                      <p className="history-empty">
                        No scans yet. Start your first immutable snapshot scan.
                      </p>
                    )}
                  </section>
                </>
              ) : (
                <section className="empty-state panel">
                  <GitBranch size={35} />
                  <h2>Connect your first repository</h2>
                  <p>
                    Use a provisioned GitHub App installation or a labeled
                    offline fixture above.
                  </p>
                </section>
              )}
            </>
          )}
          <footer>
            REPOGUARD{" "}
            <span>
              Evidence before automation. Human review before pull requests.
            </span>
          </footer>
        </div>
      </main>
    </div>
  );
}
