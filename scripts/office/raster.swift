// PDFKit reference rasterizer. No network or image synthesis fallback.
import AppKit
import PDFKit
import Foundation

let args = CommandLine.arguments
if args.count != 3 { fputs("usage: swift raster.swift input.pdf output-dir\n", stderr); exit(2) }
guard let doc = PDFDocument(url: URL(fileURLWithPath: args[1])), doc.pageCount > 0 else {
    fputs("PDFKit could not load pages\n", stderr); exit(2)
}
for index in 0..<doc.pageCount {
    guard let page = doc.page(at: index) else { exit(2) }
    let bounds = page.bounds(for: .mediaBox)
    let width = Int(ceil(bounds.width * 2))
    let height = Int(ceil(bounds.height * 2))
    guard width > 0 && height > 0 && width <= 12000 && height <= 12000,
          let image = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: width,
              pixelsHigh: height, bitsPerSample: 8, samplesPerPixel: 4,
              hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB,
              bytesPerRow: 0, bitsPerPixel: 0),
          let context = NSGraphicsContext(bitmapImageRep: image) else { exit(2) }
    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = context
    context.imageInterpolation = .high
    context.cgContext.setFillColor(NSColor.white.cgColor)
    context.cgContext.fill(CGRect(x: 0, y: 0, width: width, height: height))
    context.cgContext.scaleBy(x: 2, y: 2)
    page.draw(with: .mediaBox, to: context.cgContext)
    context.flushGraphics()
    NSGraphicsContext.restoreGraphicsState()
    guard let png = image.representation(using: .png, properties: [:]), !png.isEmpty else { exit(2) }
    let path = URL(fileURLWithPath: args[2]).appendingPathComponent(String(format: "page-%04d.png", index + 1))
    do { try png.write(to: path, options: .atomic) } catch { fputs("PNG write failed: \(error)\n", stderr); exit(2) }
}
print("pages=\(doc.pageCount)")
