import { useCallback, useEffect, useReducer, useRef } from 'react';
import { api, socketUrl } from '../api';
import { dashboardReducer, initialState, parseFrame } from '../dashboardState';
import type { AlertStatus } from '../types';

const FIRST_RETRY_MS = 1000;
const MAX_RETRY_MS = 15000;

/**
 * Owns the live connection to the analyzer: one REST snapshot to paint the first frame, then a
 * WebSocket that reconnects with exponential backoff for everything after it.
 */
export function useDashboard() {
  const [state, dispatch] = useReducer(dashboardReducer, initialState);
  const socketRef = useRef<WebSocket | null>(null);
  const retryRef = useRef(FIRST_RETRY_MS);
  const timerRef = useRef<number | undefined>(undefined);
  const closedByUsRef = useRef(false);

  useEffect(() => {
    let cancelled = false;

    void (async () => {
      try {
        const [alerts, events, stats] = await Promise.all([
          api.recentAlerts(),
          api.recentEvents(),
          api.stats(),
        ]);
        if (!cancelled) {
          dispatch({ type: 'seed', alerts, events, stats });
        }
      } catch (error) {
        if (!cancelled) {
          dispatch({
            type: 'seed-failed',
            message: error instanceof Error ? error.message : 'Analyzer unreachable',
          });
        }
      }
    })();

    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    closedByUsRef.current = false;

    const connect = () => {
      const socket = new WebSocket(socketUrl());
      socketRef.current = socket;

      socket.onopen = () => {
        retryRef.current = FIRST_RETRY_MS;
        dispatch({ type: 'link', link: 'live' });
      };

      socket.onmessage = (message: MessageEvent<string>) => {
        const frame = parseFrame(message.data);
        if (frame) {
          dispatch({ type: 'frame', frame });
        }
      };

      socket.onerror = () => socket.close();

      socket.onclose = () => {
        if (closedByUsRef.current) {
          return;
        }
        dispatch({ type: 'link', link: 'lost' });
        timerRef.current = window.setTimeout(connect, retryRef.current);
        retryRef.current = Math.min(retryRef.current * 2, MAX_RETRY_MS);
      };
    };

    connect();

    return () => {
      closedByUsRef.current = true;
      window.clearTimeout(timerRef.current);
      socketRef.current?.close();
    };
  }, []);

  /** The server echoes the change back over the socket, so nothing is written locally here. */
  const setAlertStatus = useCallback(async (id: string, status: AlertStatus) => {
    await api.setAlertStatus(id, status);
  }, []);

  const markSettled = useCallback((id: string) => dispatch({ type: 'settled', id }), []);

  return { state, setAlertStatus, markSettled };
}
