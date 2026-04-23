import * as force from './forceLayout.js';
import * as circular from './circularLayout.js';

export const LAYOUTS = [force, circular];

export function getLayout(id) {
  return LAYOUTS.find(l => l.LAYOUT_ID === id) ?? force;
}

export function getAvailableLayouts(workspace) {
  return LAYOUTS.filter(l => !l.LAYOUT_WORKSPACE || l.LAYOUT_WORKSPACE === workspace);
}
