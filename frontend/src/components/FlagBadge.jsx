import React from 'react';
import Tag from './Tag';
import { FLAG_COLORS, FLAG_TIPS } from '../utils';

export default function FlagBadge({ f }) {
  return <Tag color={FLAG_COLORS[f] || '#8b949e'} small tip={FLAG_TIPS[f]}>{f}</Tag>;
}
