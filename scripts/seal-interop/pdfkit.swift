import Foundation
import PDFKit

for path in CommandLine.arguments.dropFirst() {
    let url = URL(fileURLWithPath: path)
    guard let document = PDFDocument(url: url) else {
        fputs("PDFDocument(url:) returned nil: \(path)\n", stderr)
        exit(1)
    }
    guard document.pageCount > 0 else {
        fputs("PDFKit returned zero pages: \(path)\n", stderr)
        exit(1)
    }
    print("file=\(url.lastPathComponent) loaded=true pages=\(document.pageCount)")
    var annotationCount = 0
    var signatureWidgetCount = 0
    for pageIndex in 0..<document.pageCount {
        guard let page = document.page(at: pageIndex) else {
            fputs("missing page \(pageIndex + 1): \(path)\n", stderr)
            exit(1)
        }
        for (annotationIndex, annotation) in page.annotations.enumerated() {
            annotationCount += 1
            let isSignature = annotation.widgetFieldType == .signature
            if isSignature { signatureWidgetCount += 1 }
            print("  page=\(pageIndex + 1) annotation=\(annotationIndex) type=\(String(describing: annotation.type)) field=\(String(describing: annotation.fieldName)) widgetFieldType=\(annotation.widgetFieldType) isSignature=\(isSignature)")
        }
    }
    print("  annotationCount=\(annotationCount) signatureWidgetCount=\(signatureWidgetCount)")
    guard signatureWidgetCount > 0 else {
        fputs("no signature widget found: \(path)\n", stderr)
        exit(1)
    }
}
