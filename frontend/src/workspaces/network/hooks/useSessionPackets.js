/**
 * useSessionPackets.js — packet-loading hook for SessionDetail.
 *
 * Manages pkts, ld (loading), showHex, expandedPkts state and the
 * on-demand fetch. Resets all state when sessionId changes.
 *
 * Returns: { pkts, ld, showHex, setShowHex, expandedPkts, setExpandedPkts, loadP }
 */

import { useState, useEffect, useCallback } from 'react';
import { fetchSessionDetail } from '../../../api';

export function useSessionPackets(sessionId) {
  const [pkts, setPkts] = useState([]);
  const [ld, setLd] = useState(false);
  const [showHex, setShowHex] = useState(false);
  const [expandedPkts, setExpandedPkts] = useState(new Set());

  // Reset packet state when the viewed session changes
  useEffect(() => {
    setPkts([]);
    setLd(false);
    setShowHex(false);
    setExpandedPkts(new Set());
  }, [sessionId]);

  const loadP = useCallback(async () => {
    if (ld || pkts.length) return;
    setLd(true);
    try {
      const d = await fetchSessionDetail(sessionId);
      setPkts(d.packets || []);
    } catch (e) {
      console.error('Session detail error:', e);
    }
    setLd(false);
  }, [sessionId, ld, pkts.length]);

  return { pkts, ld, showHex, setShowHex, expandedPkts, setExpandedPkts, loadP };
}
