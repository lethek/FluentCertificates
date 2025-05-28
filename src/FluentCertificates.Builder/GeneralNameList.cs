namespace FluentCertificates;

public class GeneralNameList(IEnumerable<GeneralName> constraints) : List<GeneralName>(constraints);
