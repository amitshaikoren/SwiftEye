/**
 * useAnimationMode — animation playback state, decoupled from useCapture.
 *
 * Manages: active flag, spotlight nodes, events from API, frame index,
 * play/pause, speed, animation options, and derived frame state.
 *
 * Entry: startAnimation(nodeIds) — called from MultiSelectPanel.
 * Exit:  stopAnimation() — restores main canvas.
 */

import { useState, useRef, useCallback, useEffect, useMemo } from 'react';
import { fetchNodeAnimation } from '../api';

const SPEED_MS = { 0.5: 2000, 1: 1000, 2: 500, 5: 200 };

export function useAnimationMode() {
  const [animActive, setAnimActive] = useState(false);
  const [animNodes, setAnimNodes] = useState([]);          // spotlight IPs
  const [rawEvents, setRawEvents] = useState([]);          // unfiltered events from API
  const [animNodeMeta, setAnimNodeMeta] = useState({});    // {ip: {is_spotlight, is_private, ...}}
  const [animFrame, setAnimFrame] = useState(0);           // 0..N (0 = before first event)
  const [animPlaying, setAnimPlaying] = useState(false);
  const [animSpeed, setAnimSpeed] = useState(1);
  const [animLoading, setAnimLoading] = useState(false);
  const [animError, setAnimError] = useState(null);
  const [isIsolated, setIsIsolated] = useState(false);     // filter timeline to spotlight↔spotlight events
  const [animOpts, setAnimOpts] = useState({
    endedMode: 'fade',     // 'disappear' | 'fade' | 'color'
    endedColor: '#555555',
    showInactive: true,    // show greyed neighbours with no active session
    edgeLabels: 'protocol', // 'protocol' | 'bytes' | 'off'
  });

  // Effective events: when isolated, only events where both endpoints are spotlight nodes.
  // This is the single source of truth for the timeline — frames, play loop, history,
  // frame state, and slider all derive from it.
  const animEvents = useMemo(() => {
    if (!isIsolated || animNodes.length === 0) return rawEvents;
    const spot = new Set(animNodes);
    return rawEvents.filter(ev => spot.has(ev.src) && spot.has(ev.dst));
  }, [rawEvents, isIsolated, animNodes]);

  const playTimerRef = useRef(null);
  const eventsRef = useRef([]);
  useEffect(() => { eventsRef.current = animEvents; }, [animEvents]);

  // Clamp animFrame whenever the effective event list shrinks (e.g. toggling isolate on).
  useEffect(() => {
    setAnimFrame(prev => Math.min(prev, animEvents.length));
  }, [animEvents.length]);

  // ── Start / Stop ──────────────────────────────────────────────────

  const startAnimation = useCallback(async (nodeIds, protocols) => {
    setAnimLoading(true);
    setAnimError(null);
    try {
      const resp = await fetchNodeAnimation(nodeIds, protocols);
      setAnimNodes(nodeIds);
      setRawEvents(resp.events || []);
      setAnimNodeMeta(resp.nodes || {});
      setAnimFrame(0);
      setAnimPlaying(false);
      setIsIsolated(false);
      setAnimActive(true);
    } catch (err) {
      setAnimError(err.message || 'Failed to load animation data');
    } finally {
      setAnimLoading(false);
    }
  }, []);

  const stopAnimation = useCallback(() => {
    setAnimActive(false);
    setAnimPlaying(false);
    setAnimFrame(0);
    setRawEvents([]);
    setAnimNodeMeta({});
    setAnimNodes([]);
    setIsIsolated(false);
    setAnimError(null);
    if (playTimerRef.current) {
      clearInterval(playTimerRef.current);
      playTimerRef.current = null;
    }
  }, []);

  // ── Playback timer ────────────────────────────────────────────────

  useEffect(() => {
    if (playTimerRef.current) {
      clearInterval(playTimerRef.current);
      playTimerRef.current = null;
    }
    if (!animPlaying || !animActive) return;

    const ms = SPEED_MS[animSpeed] || 1000;
    playTimerRef.current = setInterval(() => {
      setAnimFrame(prev => {
        if (prev >= eventsRef.current.length) {
          // Reached end — stop playing
          setAnimPlaying(false);
          return prev;
        }
        return prev + 1;
      });
    }, ms);

    return () => {
      if (playTimerRef.current) {
        clearInterval(playTimerRef.current);
        playTimerRef.current = null;
      }
    };
  }, [animPlaying, animActive, animSpeed]);

  // ── Transport controls ────────────────────────────────────────────

  const togglePlay = useCallback(() => {
    setAnimPlaying(prev => {
      if (!prev && eventsRef.current.length > 0) {
        // If at end, rewind to start
        setAnimFrame(f => f >= eventsRef.current.length ? 0 : f);
      }
      return !prev;
    });
  }, []);

  const goToFrame = useCallback((f) => {
    const clamped = Math.max(0, Math.min(f, eventsRef.current.length));
    setAnimFrame(clamped);
  }, []);

  const stepForward = useCallback(() => {
    setAnimFrame(prev => Math.min(prev + 1, eventsRef.current.length));
  }, []);

  const stepBackward = useCallback(() => {
    setAnimFrame(prev => Math.max(prev - 1, 0));
  }, []);

  const goToStart = useCallback(() => { setAnimFrame(0); }, []);
  const goToEnd = useCallback(() => { setAnimFrame(eventsRef.current.length); }, []);

  // ── Derived frame state ───────────────────────────────────────────
  // getStateAtFrame(f) returns { active: Set<sid>, ended: Set<sid> }

  const frameState = useMemo(() => {
    const active = new Set();
    const ended = new Set();
    for (let i = 0; i < animFrame && i < animEvents.length; i++) {
      const ev = animEvents[i];
      if (ev.type === 'start') {
        active.add(ev.session_id);
        ended.delete(ev.session_id);
      } else {
        active.delete(ev.session_id);
        ended.add(ev.session_id);
      }
    }
    return { active, ended };
  }, [animFrame, animEvents]);

  // Current event (the one that just happened at this frame)
  const currentEvent = animFrame > 0 && animFrame <= animEvents.length
    ? animEvents[animFrame - 1]
    : null;

  // Time range of all events
  const animTimeRange = useMemo(() => {
    if (animEvents.length === 0) return { min: 0, max: 0 };
    return {
      min: animEvents[0].time,
      max: animEvents[animEvents.length - 1].time,
    };
  }, [animEvents]);

  return {
    // State
    animActive,
    animNodes,
    animEvents,
    animNodeMeta,
    animFrame,
    animPlaying,
    animSpeed,
    animLoading,
    animError,
    animOpts,
    isIsolated,

    // Derived
    frameState,
    currentEvent,
    animTimeRange,
    totalFrames: animEvents.length,

    // Actions
    startAnimation,
    stopAnimation,
    togglePlay,
    goToFrame,
    stepForward,
    stepBackward,
    goToStart,
    goToEnd,
    setAnimSpeed,
    setAnimOpts,
    setIsIsolated,
  };
}
