import { Link, createFileRoute } from '@tanstack/react-router'

export const Route = createFileRoute('/')({
  component: Home,
})

/* The desk, empty. The app screens graduate here from oneiron-mocks
   (FLOWS.md carries the ruling ledger); until then this route only
   proves the material: film black, the mark, serif voice, mono data. */
function Home() {
  return (
    <main
      style={{
        minHeight: '100dvh',
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        gap: 14,
        background: 'var(--bg)',
      }}
    >
      <svg width="34" height="34" viewBox="0 0 120 120" fill="none" aria-hidden="true">
        <mask id="oneiron-cut-web">
          <rect width="120" height="120" fill="white" />
          <circle cx="60" cy="60" r="22" fill="black" />
        </mask>
        <rect
          x="17.5"
          y="17.5"
          width="85"
          height="85"
          rx="10"
          fill="var(--silver-1)"
          transform="rotate(45 60 60)"
          mask="url(#oneiron-cut-web)"
        />
      </svg>
      <p
        style={{
          fontFamily: 'var(--serif)',
          fontSize: 16,
          color: 'var(--silver-2)',
        }}
      >
        The web surface develops here.
      </p>
      <p
        style={{
          fontFamily: 'var(--mono)',
          fontSize: 11.5,
          color: 'var(--silver-4)',
        }}
      >
        oneiron-web · graduated from oneiron-mocks
      </p>
      <p
        style={{
          display: 'flex',
          gap: 14,
          fontFamily: 'var(--mono)',
          fontSize: 11.5,
          color: 'var(--silver-3)',
        }}
      >
        <Link to="/app/inbox">inbox</Link>
        <Link to="/app/vault">vault</Link>
      </p>
    </main>
  )
}
