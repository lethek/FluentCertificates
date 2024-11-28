namespace FluentCertificates;

public class GeneralSubtree(IEnumerable<GeneralNameConstraint> constraints) : List<GeneralNameConstraint>(constraints);
