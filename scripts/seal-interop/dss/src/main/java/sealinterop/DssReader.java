package sealinterop;
import java.io.File;
import java.nio.file.Files;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collection;
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;

public final class DssReader {
  static String esc(String s) { return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", " "); }
  public static void main(String[] args) {
    String version="6.5";
    try {
    if (args.length != 1) { out(version,"fail","usage: seal-dss PDF","ERROR","ERROR"); System.exit(2); }

    byte[] pdf=Files.readAllBytes(new File(args[0]).toPath());
    CommonTrustedCertificateSource trusted = new CommonTrustedCertificateSource();
    boolean cryptographicPass=true;
    int verifiedSigners=0;
    try (PDDocument doc=Loader.loadPDF(pdf)) {
      var sigs=doc.getSignatureDictionaries();
      if(sigs.isEmpty()){out(version,"fail","no embedded signature","no_signature","no_signature");System.exit(1);}
      for(PDSignature sig:sigs){
        int[] range=sig.getByteRange();
        if(range==null || range.length!=4 || range[0]!=0 || range[1]<0 || range[2]<range[1] || range[3]<0 || (long)range[2]+range[3]!=pdf.length)
          throw new IllegalStateException("signature ByteRange does not cover the complete PDF revision");
        byte[] paddedContents=sig.getContents(pdf);
        byte[] cmsBytes;
        try(ASN1InputStream asn1=new ASN1InputStream(paddedContents)){
          var contentInfo=asn1.readObject();
          if(contentInfo==null) throw new IllegalStateException("empty PDF /Contents");
          cmsBytes=contentInfo.getEncoded(ASN1Encoding.DER); // Ignore permitted zero-padding after the DER ContentInfo.
        }
        CMSSignedData cms=new CMSSignedData(new CMSProcessableByteArray(sig.getSignedContent(pdf)),cmsBytes);
        Collection<SignerInformation> signers=cms.getSignerInfos().getSigners();
        Collection<X509CertificateHolder> holders=cms.getCertificates().getMatches(null);
        for(X509CertificateHolder h:holders){X509Certificate x=(X509Certificate)new JcaX509CertificateConverter().getCertificate(h);trusted.addCertificate(new CertificateToken(x));}
        if(signers.isEmpty()) throw new IllegalStateException("CMS has no signers");
        for(SignerInformation signer:signers){
          Collection<X509CertificateHolder> signerCerts=cms.getCertificates().getMatches(signer.getSID());
          if(signerCerts.isEmpty()) throw new IllegalStateException("CMS signer certificate missing");
          X509CertificateHolder cert=signerCerts.iterator().next();
          if(!signer.verify(new org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder().build(cert)))
            cryptographicPass=false;
          verifiedSigners++;
        }
      }
    }
    CommonCertificateVerifier verifier=new CommonCertificateVerifier();
    // This local oracle trusts certificates carried in the PDF to make the DSS result
    // reproducible without external trust stores. Output states this trust override.
    verifier.setTrustedCertSources(trusted);
    SignedDocumentValidator validator=SignedDocumentValidator.fromDocument(new FileDocument(new File(args[0])));
    validator.setCertificateVerifier(verifier);
    Reports reports=validator.validateDocument();
    SimpleReport simple=reports.getSimpleReport();
    DetailedReport detailed=reports.getDetailedReport();
    var ids=simple.getSignatureIdList();
    if(ids.isEmpty()){out(version,"fail","DSS found no signature","no_signature","no_signature");System.exit(1);}
    StringBuilder info=new StringBuilder("CMS cryptographic signers verified=").append(verifiedSigners)
        .append("; trust override=embedded CMS certificate(s) treated as local anchors");
    String indication="";
    String subindication="";
    boolean dssAcceptsIntegrity=true;
    for(String id:ids){
      var basic=detailed.getBasicBuildingBlocksIndication(id);
      var basicSub=detailed.getBasicBuildingBlocksSubIndication(id);
      var basicValidation=detailed.getBasicValidationIndication(id);
      var basicValidationSub=detailed.getBasicValidationSubIndication(id);
      var full=simple.getIndication(id);
      var fullSub=simple.getSubIndication(id);
      info.append("; ").append(id).append(":dss_bbb=").append(basic).append('/').append(basicSub==null?"":basicSub)
          .append(",dss_basic_validation=").append(basicValidation).append('/').append(basicValidationSub==null?"":basicValidationSub)
          .append(",dss_ades=").append(full).append('/').append(fullSub==null?"":fullSub);
      indication=full==null?"":full.toString(); subindication=fullSub==null?"":fullSub.toString();
      dssAcceptsIntegrity &= compatibleIndication(basic, basicSub)
          && compatibleIndication(basicValidation, basicValidationSub)
          && compatibleIndication(full, fullSub);
    }
    // The status requires both an independent CMS integrity check and a DSS
    // result that is not crypto/format failure. Explicit trust-only uncertainty
    // is disclosed in the DSS indications and does not become crypto invalid.
    boolean pass=cryptographicPass && dssAcceptsIntegrity;
    out(version,pass?"pass":"fail",info.append("; CMS_integrity=").append(cryptographicPass?"PASS":"FAIL").toString(),indication,subindication);
    if(!pass)System.exit(1);
    } catch(Throwable e) {
      out(version,"fail",e.getClass().getSimpleName()+": "+String.valueOf(e.getMessage()),"ERROR","ERROR");
      System.exit(1);
    }
  }
  static boolean compatibleIndication(Object indication,Object subindication){
    String i=String.valueOf(indication), s=String.valueOf(subindication).toUpperCase();
    if("TOTAL_PASSED".equals(i) || "PASSED".equals(i)) return true;
    if("TOTAL_FAILED".equals(i) || "FAILED".equals(i)) return s.contains("TRUST") || s.contains("CERTIFICATE") && !s.contains("CRYPTO");
    if("INDETERMINATE".equals(i)) return s.contains("TRUST") || s.contains("NO_CERTIFICATE") || s.contains("NO_SIGNING_CERTIFICATE");
    return false;
  }
  static void out(String v,String status,String detail,String indication,String sub){
    System.out.println("{\"reader\":\"dss\",\"version\":\""+esc(v)+"\",\"mode\":\"verify\",\"status\":\""+status+"\",\"detail\":\""+esc(detail)+"\",\"dss_ades_indication\":\""+esc(indication)+"\",\"dss_ades_subindication\":\""+esc(sub)+"\"}");
  }
}
