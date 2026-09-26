package sealinterop;
import java.io.File;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.Collection;
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.util.Version;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;

public final class PdfBoxReader {
  static String esc(String s) { return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", " "); }
  public static void main(String[] args) {
    String version = Version.getVersion();
    try {
    if (args.length != 1) { out(version,"fail","usage: seal-pdfbox PDF"); System.exit(2); }
    byte[] pdf = Files.readAllBytes(new File(args[0]).toPath());
    try (PDDocument doc = Loader.loadPDF(pdf)) {
      var sigs = doc.getSignatureDictionaries();
      if (sigs.isEmpty()) { out(version, "fail", "no embedded signature"); System.exit(1); }
      int checked=0;
      long latestSignedEnd=0;
      for (PDSignature sig : sigs) {
        int[] range = sig.getByteRange();
        if (range == null || range.length != 4 || range[0] != 0 || range[1] < 0 || range[2] < range[1] || range[3] < 0 || (long)range[2] + range[3] > pdf.length)
          throw new IllegalStateException("signature ByteRange does not cover the complete PDF revision");
        checkSignedRevision(pdf, range);
        latestSignedEnd=Math.max(latestSignedEnd, (long)range[2] + range[3]);
        byte[] cms = sig.getContents(pdf);
        byte[] signed = sig.getSignedContent(pdf);
        CMSSignedData data = new CMSSignedData(new org.bouncycastle.cms.CMSProcessableByteArray(signed), cms);
        Collection<SignerInformation> signers = data.getSignerInfos().getSigners();
        if (signers.isEmpty()) throw new IllegalStateException("CMS has no signers");
        for (SignerInformation signer : signers) {
          Collection<X509CertificateHolder> certs = data.getCertificates().getMatches(signer.getSID());
          if (certs.isEmpty()) throw new IllegalStateException("CMS signer certificate missing");
          X509CertificateHolder cert = certs.iterator().next();
          if (!signer.verify(new JcaSimpleSignerInfoVerifierBuilder().build(new JcaX509CertificateConverter().getCertificate(cert))))
            throw new IllegalStateException("CMS digest/signature invalid");
          checked++;
        }
      }
      boolean finalCoverage = latestSignedEnd == pdf.length;
      out(version, "pass", "pages="+doc.getNumberOfPages()+"; signatures="+sigs.size()+"; CMS signers verified="+checked+"; each ByteRange covers its signed revision; final_document_coverage="+finalCoverage+"; later revisions are not a permitted-change assessment; certificate trust not evaluated");
    } catch (Exception e) { out(version, "fail", e.getClass().getSimpleName()+": "+e.getMessage()); System.exit(1); }
    } catch(Throwable e) { out(version,"fail",e.getClass().getSimpleName()+": "+e.getMessage()); System.exit(1); }
  }
  static void checkSignedRevision(byte[] pdf, int[] range) throws Exception {
    int end = range[2] + range[3];
    int tail = end - 1;
    while (tail >= 0 && (pdf[tail] == 0 || pdf[tail] == 9 || pdf[tail] == 10
        || pdf[tail] == 12 || pdf[tail] == 13 || pdf[tail] == 32)) tail--;
    if (tail < 4 || pdf[tail-4] != '%' || pdf[tail-3] != '%'
        || pdf[tail-2] != 'E' || pdf[tail-1] != 'O' || pdf[tail] != 'F')
      throw new IllegalStateException("signed revision has no PDF EOF marker");
    // Parse the signed prefix as a PDF and require its own signature dictionary.
    // A later incremental revision need not be signed by this earlier signature.
    try (PDDocument revision = Loader.loadPDF(Arrays.copyOf(pdf, end))) {
      boolean found = false;
      for (PDSignature signed : revision.getSignatureDictionaries()) {
        if (Arrays.equals(signed.getByteRange(), range)) found = true;
      }
      if (!found) throw new IllegalStateException("signature ByteRange does not end at its signed revision");
    }
  }
  static void out(String v, String s, String d) { System.out.println("{\"reader\":\"pdfbox\",\"version\":\""+esc(v)+"\",\"mode\":\"verify\",\"status\":\""+s+"\",\"detail\":\""+esc(d)+"\"}"); }
}
