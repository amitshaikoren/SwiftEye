import React from 'react';
import Tag from '../../core/components/Tag';
import { FLAG_COLORS, FLAG_TIPS } from '../../core/utils';

export default function FlagBadge({ f }) {
  return <Tag color={FLAG_COLORS[f] || '#8b949e'} small tip={FLAG_TIPS[f]}>{f}</Tag>;
}
