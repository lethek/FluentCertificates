namespace FluentCertificates;

public class GeneralSubtree : List<GeneralNameConstraint>
{
    public GeneralSubtree(IEnumerable<GeneralNameConstraint> constraints) : base(constraints) { }
}