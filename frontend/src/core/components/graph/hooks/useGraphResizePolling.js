import { useEffect } from 'react';
import * as d3 from 'd3';

export default function useGraphResizePolling({ containerRef, simRef, renRef, rafRef }) {
  useEffect(() => {
    // Poll for size changes. When the container resizes (e.g. right panel opens,
    // scrollbar appears/disappears, window resizes), update the center force so
    // nodes drift toward the new center on their next natural tick.
    //
    // IMPORTANT: do NOT restart the simulation with any alpha heat here.
    // The previous code used alpha(0.01).restart() which caused nodes to visibly
    // pull away every time a node was clicked (clicking opens the detail panel,
    // which changes the layout slightly, which changes clientWidth by a pixel
    // or two, which triggered the restart). Even alpha=0.01 with alphaDecay=0.02
    // produces visible movement for several frames.
    //
    // Fix: update the center force only. If the sim is still warm (alpha > 0),
    // it will naturally incorporate the new center on its next tick. If it has
    // cooled (alpha <= alphaMin), don't restart — just trigger a single re-render
    // so the canvas redraws at the correct size.
    const el = containerRef?.current;
    if (!el) return;
    let prevW = el.clientWidth, prevH = el.clientHeight;

    const interval = setInterval(() => {
      const w = el.clientWidth, h = el.clientHeight;
      if (w !== prevW || h !== prevH) {
        prevW = w;
        prevH = h;
        if (simRef.current) {
          // Update the centering force for the new dimensions
          simRef.current.force('center', d3.forceCenter(w / 2, h / 2).strength(0.04));
          simRef.current.force('x', d3.forceX(w / 2).strength(0.015));
          simRef.current.force('y', d3.forceY(h / 2).strength(0.015));
          // Only restart if the simulation is still warm — let a cooled sim stay still.
          if (simRef.current.alpha() > 0.001) {
            simRef.current.restart();
          } else if (renRef.current) {
            cancelAnimationFrame(rafRef.current);
            rafRef.current = requestAnimationFrame(renRef.current);
          }
        } else if (renRef.current) {
          cancelAnimationFrame(rafRef.current);
          rafRef.current = requestAnimationFrame(renRef.current);
        }
      }
    }, 200);

    return () => clearInterval(interval);
  }, []);
}
