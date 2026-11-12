/* Escape undoes the newest pending answer, wherever focus is. Each answer
   in its undo window registers its undo here and releases it when the
   window closes; one capture listener serves them all. */

const pendingUndos: Array<() => void> = []

function onEscapeUndo(event: KeyboardEvent) {
  if (event.key !== 'Escape' || event.defaultPrevented) return
  const undo = pendingUndos[pendingUndos.length - 1]
  if (!undo) return
  event.preventDefault()
  undo()
}

/* Registers an undo; returns the release. */
export function pushPendingUndo(undo: () => void): () => void {
  if (!pendingUndos.length) document.addEventListener('keydown', onEscapeUndo, true)
  pendingUndos.push(undo)
  return () => {
    const i = pendingUndos.lastIndexOf(undo)
    if (i >= 0) pendingUndos.splice(i, 1)
    if (!pendingUndos.length) document.removeEventListener('keydown', onEscapeUndo, true)
  }
}
