import * as React from 'react'

/* The gallery's frame: one section per component, one figure per state. */

export function Section({ title, children }: { title: string; children: React.ReactNode }) {
  const id = `lib-${title.toLowerCase().replace(/[^a-z0-9]+/g, '-')}`
  return (
    <section className="lib-section" aria-labelledby={id}>
      <h2 id={id} className="lib-section-head">
        {title}
      </h2>
      <div className="lib-specimens">{children}</div>
    </section>
  )
}

export function Specimen({
  name,
  tall,
  wide,
  full,
  children,
}: {
  name: string
  tall?: number
  wide?: number
  /* A whole row of the section, up to the reading width. */
  full?: boolean
  children: React.ReactNode
}) {
  return (
    <figure className="lib-specimen" data-tall={tall} data-wide={wide} data-full={full ? '' : undefined}>
      <div className="lib-stage">{children}</div>
      <figcaption className="lib-caption">{name}</figcaption>
    </figure>
  )
}
