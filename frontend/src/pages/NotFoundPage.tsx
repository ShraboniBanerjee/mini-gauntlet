import { Link } from "react-router-dom";

import { EmptyState } from "../components/States";

export function NotFoundPage() {
  return (
    <EmptyState title="There's no page here">
      <p>
        <Link to="/">Go to all scans</Link>
      </p>
    </EmptyState>
  );
}
