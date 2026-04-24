import * as force from './forceLayout.js';
import * as radial from './radialLayout.js';
import * as hierarchical from './hierarchicalLayout.js';

export const LAYOUTS = [force, radial, hierarchical];

export function getLayout(id) {
  return LAYOUTS.find(l => l.LAYOUT_ID === id) ?? force;
}

export function getAvailableLayouts(workspace) {
  return LAYOUTS.filter(l => !l.LAYOUT_WORKSPACE || l.LAYOUT_WORKSPACE === workspace);
}
