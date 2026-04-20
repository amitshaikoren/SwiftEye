/**
 * Recipe — ordered step list with drag-to-reorder.
 *
 * Steps are added by the classic QueryBuilder ("+ Add step" button). Recipe
 * handles reorder, edit, enable/disable, remove. Parent owns the steps array
 * and passes `setSteps` down.
 */
import React, { useState } from 'react';
import {
  DndContext, closestCenter, KeyboardSensor, PointerSensor, useSensor, useSensors,
} from '@dnd-kit/core';
import {
  arrayMove, SortableContext, sortableKeyboardCoordinates, verticalListSortingStrategy,
} from '@dnd-kit/sortable';
import RecipeStep from './RecipeStep';

export default function Recipe({ steps, onStepsChange, schema }) {
  const [editingId, setEditingId] = useState(null);

  const sensors = useSensors(
    useSensor(PointerSensor, { activationConstraint: { distance: 4 } }),
    useSensor(KeyboardSensor, { coordinateGetter: sortableKeyboardCoordinates })
  );

  function handleDragEnd(ev) {
    const { active, over } = ev;
    if (!over || active.id === over.id) return;
    const from = steps.findIndex(s => s.id === active.id);
    const to = steps.findIndex(s => s.id === over.id);
    if (from < 0 || to < 0) return;
    onStepsChange(arrayMove(steps, from, to));
  }

  function patchStep(id, patch) {
    onStepsChange(steps.map(s => s.id === id ? { ...s, ...patch } : s));
  }

  function removeStep(id) {
    onStepsChange(steps.filter(s => s.id !== id));
    if (editingId === id) setEditingId(null);
  }

  if (steps.length === 0) {
    return (
      <div style={{ padding: 16, textAlign: 'center', color: 'var(--txD)', fontSize: 11,
        border: '1px dashed var(--bd)', borderRadius: 5 }}>
        Click <strong>+ Add step</strong> above to append the current query as a pipeline step.
      </div>
    );
  }

  return (
    <DndContext sensors={sensors} collisionDetection={closestCenter} onDragEnd={handleDragEnd}>
      <SortableContext items={steps.map(s => s.id)} strategy={verticalListSortingStrategy}>
        <div style={{ maxHeight: '40vh', overflowY: 'auto' }}>
          {steps.map((step, i) => (
            <RecipeStep
              key={step.id}
              step={step}
              index={i}
              editing={editingId === step.id}
              schema={schema}
              onToggleEdit={() => setEditingId(editingId === step.id ? null : step.id)}
              onPatch={patch => patchStep(step.id, patch)}
              onToggleEnabled={() => patchStep(step.id, { enabled: step.enabled === false })}
              onRemove={() => removeStep(step.id)}
            />
          ))}
        </div>
      </SortableContext>
    </DndContext>
  );
}
