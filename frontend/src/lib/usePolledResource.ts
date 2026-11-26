import { useCallback, useEffect, useState } from "react";

import { ApiError } from "../api/client";

export const POLL_INTERVAL_MS = 1500;
export const RETRY_INTERVAL_MS = 5000;

export interface Resource<T> {
  data: T | undefined;
  error: Error | undefined;
  loading: boolean;
  reload: () => void;
}

/** Network failures and 5xx responses are worth retrying; a 404 or 422 won't change. */
function isRetryable(error: Error): boolean {
  return !(error instanceof ApiError) || error.status === null || error.status >= 500;
}

/**
 * Load a resource, then keep polling it while `shouldPoll(data)` is true.
 *
 * `load` and `shouldPoll` must be stable (useCallback or module-level), because a new
 * function starts a new request. While the API is unreachable the hook keeps retrying,
 * and the last good data stays on screen next to the error.
 */
export function usePolledResource<T>(
  load: (signal: AbortSignal) => Promise<T>,
  shouldPoll: (data: T) => boolean,
): Resource<T> {
  const [data, setData] = useState<T>();
  const [error, setError] = useState<Error>();
  const [loading, setLoading] = useState(true);
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    setLoading(true);

    const tick = async (): Promise<void> => {
      try {
        const next = await load(controller.signal);
        if (controller.signal.aborted) return;
        setData(next);
        setError(undefined);
        setLoading(false);
        if (shouldPoll(next)) timer = setTimeout(() => void tick(), POLL_INTERVAL_MS);
      } catch (caught) {
        if (controller.signal.aborted) return;
        const failure = caught instanceof Error ? caught : new Error(String(caught));
        setError(failure);
        setLoading(false);
        if (isRetryable(failure)) timer = setTimeout(() => void tick(), RETRY_INTERVAL_MS);
      }
    };

    void tick();
    return () => {
      controller.abort();
      clearTimeout(timer);
    };
  }, [load, shouldPoll, attempt]);

  const reload = useCallback(() => setAttempt((count) => count + 1), []);
  return { data, error, loading, reload };
}
