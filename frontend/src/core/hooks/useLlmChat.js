/**
 * useLlmChat — state management for the LLM interpretation panel.
 *
 * Manages:
 *   - message list (turns)
 *   - in-flight stream state
 *   - send / cancel / clear
 *   - context snapshot tracking
 *   - error state
 *
 * Each turn: { role, content, streamingContent, contextEvent, tags, done, error }
 */

import { useState, useRef, useCallback } from 'react';
import { streamLlmChat } from '../api';

export function useLlmChat() {
  const [turns, setTurns] = useState([]);
  const [streaming, setStreaming] = useState(false);
  const [error, setError] = useState(null);
  // snapshot_id of the last completed turn — used for context-changed detection
  const [lastSnapshotId, setLastSnapshotId] = useState(null);

  const abortRef = useRef(null);

  /**
   * Send a question.
   *
   * @param {string} question   - User question text
   * @param {object} requestBody - Full ChatRequest body (scope, viewer_state, selection, provider, options)
   */
  const send = useCallback(async (question, requestBody) => {
    if (streaming) return;

    setError(null);

    const userTurn = { role: 'user', content: question, done: true };
    const assistantTurn = {
      role: 'assistant',
      content: '',
      streamingContent: '',
      contextEvent: null,
      tags: [],
      done: false,
      error: null,
    };

    setTurns(prev => [...prev, userTurn, assistantTurn]);
    setStreaming(true);

    const controller = new AbortController();
    abortRef.current = controller;

    // Inject the question into the messages array
    const fullRequest = {
      ...requestBody,
      messages: [{ role: 'user', content: question }],
    };

    try {
      await streamLlmChat(
        fullRequest,
        (event) => {
          switch (event.type) {
            case 'meta':
              // No UI update needed — provider/model logged for debugging
              break;

            case 'context':
              setTurns(prev => {
                const next = [...prev];
                const last = next[next.length - 1];
                if (last?.role === 'assistant') {
                  next[next.length - 1] = {
                    ...last,
                    contextEvent: event,
                    tags: event.tags || [],
                  };
                }
                return next;
              });
              if (event.snapshot_id) {
                setLastSnapshotId(event.snapshot_id);
              }
              break;

            case 'delta':
              setTurns(prev => {
                const next = [...prev];
                const last = next[next.length - 1];
                if (last?.role === 'assistant') {
                  next[next.length - 1] = {
                    ...last,
                    streamingContent: (last.streamingContent || '') + (event.text || ''),
                  };
                }
                return next;
              });
              break;

            case 'final':
              setTurns(prev => {
                const next = [...prev];
                const last = next[next.length - 1];
                if (last?.role === 'assistant') {
                  next[next.length - 1] = {
                    ...last,
                    content: event.answer_markdown || last.streamingContent || '',
                    streamingContent: '',
                    done: true,
                  };
                }
                return next;
              });
              break;

            case 'error':
              setTurns(prev => {
                const next = [...prev];
                const last = next[next.length - 1];
                if (last?.role === 'assistant') {
                  next[next.length - 1] = {
                    ...last,
                    error: event.message || 'Unknown error',
                    done: true,
                  };
                }
                return next;
              });
              setError(event.message || 'Unknown error');
              break;

            default:
              break;
          }
        },
        controller.signal,
      );
    } catch (err) {
      if (err.name === 'AbortError') {
        // User cancelled — mark last assistant turn as done
        setTurns(prev => {
          const next = [...prev];
          const last = next[next.length - 1];
          if (last?.role === 'assistant' && !last.done) {
            next[next.length - 1] = { ...last, done: true, error: 'Cancelled' };
          }
          return next;
        });
      } else {
        const msg = err.message || 'Stream error';
        setTurns(prev => {
          const next = [...prev];
          const last = next[next.length - 1];
          if (last?.role === 'assistant') {
            next[next.length - 1] = { ...last, error: msg, done: true };
          }
          return next;
        });
        setError(msg);
      }
    } finally {
      setStreaming(false);
      abortRef.current = null;
    }
  }, [streaming]);

  const cancel = useCallback(() => {
    if (abortRef.current) {
      abortRef.current.abort();
    }
  }, []);

  const clear = useCallback(() => {
    cancel();
    setTurns([]);
    setError(null);
    setLastSnapshotId(null);
  }, [cancel]);

  return {
    turns,
    streaming,
    error,
    lastSnapshotId,
    send,
    cancel,
    clear,
  };
}
