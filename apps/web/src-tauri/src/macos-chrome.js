// Injected at document start by the macOS shell only. This is a visual marker,
// not engine status or a permission grant. No UA sniffing or browser padding.
;(() => {
  const apply = () => {
    if (!document.documentElement) return false
    document.documentElement.dataset.windowChrome = 'macos'
    return true
  }
  if (!apply()) {
    const observer = new MutationObserver(() => {
      if (apply()) observer.disconnect()
    })
    observer.observe(document, { childList: true })
  }
})()
