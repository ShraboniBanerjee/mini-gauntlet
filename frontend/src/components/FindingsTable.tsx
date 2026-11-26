import type { AccountScore, Finding } from "../api/types";
import { providerLabel } from "../lib/format";
import { FindingStatusBadge, SeverityBadge } from "./Badges";

/**
 * Every string here comes from a customer's cloud, so it is only ever rendered as
 * React text, which escapes it. Nothing is rendered as HTML.
 */
export function FindingsTable({
  findings,
  accounts,
}: {
  findings: Finding[];
  accounts: AccountScore[];
}) {
  const accountNames = new Map(accounts.map((account) => [account.account_id, account.name]));

  return (
    <div className="table-wrap">
      <table className="table findings-table">
        <thead>
          <tr>
            <th scope="col">Status</th>
            <th scope="col">Severity</th>
            <th scope="col">Check</th>
            <th scope="col">Resource</th>
            <th scope="col">Account</th>
            <th scope="col">Details</th>
          </tr>
        </thead>
        <tbody>
          {findings.map((finding) => (
            <tr
              key={finding.id}
              className={`row-${finding.status.toLowerCase().replace("_", "-")}`}
              data-severity={finding.severity.toLowerCase()}
            >
              <td>
                <FindingStatusBadge status={finding.status} />
              </td>
              <td>
                <SeverityBadge severity={finding.severity} />
              </td>
              <td>
                <span className="code">{finding.check_id}</span>
                <span className="sub">{finding.title}</span>
              </td>
              <td className="resource wrap">
                {finding.resource_id === null ? (
                  <span className="muted">Whole collection</span>
                ) : (
                  <span className="code">{finding.resource_id}</span>
                )}
                {finding.region && <span className="sub">{finding.region}</span>}
              </td>
              <td className="wrap">
                <span>{accountNames.get(finding.account_id) ?? finding.account_id}</span>
                <span className="sub">{providerLabel(finding.provider)}</span>
              </td>
              <td className="details wrap">{finding.details}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
