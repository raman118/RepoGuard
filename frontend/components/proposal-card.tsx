"use client";

import { useState } from "react";
import { GitPullRequest, LoaderCircle } from "lucide-react";
import { api, ApiError, type Finding } from "@/lib/api";
import { Button } from "@/components/ui/button";

export type Proposal = {
  id: string;
  digest: string;
  validation: string;
  approved_by: string | null;
  pull_request_url: string | null;
  artifact: {
    diff: string;
    base_sha: string;
    rule_id: string;
    policy_version: string;
  };
};

export function ProposalCard({
  token,
  scanId,
  finding,
}: {
  token: string;
  scanId: string;
  finding: Finding;
}) {
  const [proposal, setProposal] = useState<Proposal | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  if (!["RG-CI-PERMISSIONS", "RG-CI-TIMEOUT"].includes(finding.rule_id))
    return <p className="manual-fix">Manual review required for this rule.</p>;
  async function create() {
    setBusy(true);
    setError("");
    try {
      setProposal(
        await api<Proposal>(token, `/v1/scans/${scanId}/proposals`, {
          finding_id: finding.id,
        }),
      );
    } catch (error) {
      setError(
        error instanceof ApiError ? error.message : "Proposal unavailable",
      );
    } finally {
      setBusy(false);
    }
  }
  async function transition(step: "validate" | "approve" | "pull-request") {
    if (!proposal) return;
    setBusy(true);
    setError("");
    try {
      setProposal(
        await api<Proposal>(
          token,
          `/v1/proposals/${proposal.id}/${step}`,
          step === "validate" ? {} : { digest: proposal.digest },
        ),
      );
    } catch (error) {
      setError(
        error instanceof ApiError ? error.message : "Action unavailable",
      );
      setProposal(
        await api<Proposal>(token, `/v1/proposals/${proposal.id}`).catch(
          () => proposal,
        ),
      );
    } finally {
      setBusy(false);
    }
  }
  return (
    <div className="proposal-card">
      {!proposal ? (
        <Button variant="outline" disabled={busy} onClick={() => void create()}>
          {busy ? (
            <LoaderCircle size={15} className="spin" />
          ) : (
            <GitPullRequest size={15} />
          )}
          Propose fix
        </Button>
      ) : (
        <>
          <div className="proposal-heading">
            <strong>Proposed change</strong>
            <span className="category-status unknown">
              {proposal.validation}
            </span>
          </div>
          <pre>{proposal.artifact.diff}</pre>
          <p>
            Rule {proposal.artifact.rule_id} · base{" "}
            {proposal.artifact.base_sha.slice(0, 12)} · policy{" "}
            {proposal.artifact.policy_version}
          </p>
          <p>
            Validation is required before you can approve this exact change.
          </p>
          <div className="proposal-actions">
            {!proposal.approved_by && (
              <Button
                variant="outline"
                disabled={busy}
                onClick={() => void transition("validate")}
              >
                {busy ? <LoaderCircle size={15} className="spin" /> : null}
                Validate in isolation
              </Button>
            )}
            {proposal.validation === "passed" && !proposal.approved_by && (
              <Button
                disabled={busy}
                onClick={() => void transition("approve")}
              >
                Approve this exact patch
              </Button>
            )}
            {proposal.approved_by && !proposal.pull_request_url && (
              <Button
                disabled={busy}
                onClick={() => void transition("pull-request")}
              >
                Create approved GitHub PR
              </Button>
            )}
            {proposal.pull_request_url && (
              <a
                href={proposal.pull_request_url}
                target="_blank"
                rel="noopener noreferrer"
              >
                Open GitHub pull request
              </a>
            )}
          </div>
          <details>
            <summary>Patch identity</summary>
            <code className="digest">{proposal.digest}</code>
          </details>
        </>
      )}
      {error && (
        <p role="alert" aria-label="Proposal error">
          {error}
        </p>
      )}
    </div>
  );
}
