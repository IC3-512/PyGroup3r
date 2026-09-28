"""Port of Group3r/Assessment/SddlAnalyser.cs

Turns a parsed SDDL into the flat `SimpleAce` list that every analyser consumes.
The large commented-out `AssessSimpleAC` method in the original is left
commented out here too, since enabling it would change findings.
"""

from typing import List, Optional

from ..ad.trustee import Trustee
from .finding import ACEType, SimpleAce


class SddlAnalyser:
    """Port of Group3r.Assessment.SddlAnalyser."""

    def __init__(self, assessment_options):
        self.assessment_options = assessment_options

    def analyse_sddl(self, sddl) -> List[SimpleAce]:
        """Port of SddlAnalyser.AnalyseSddl."""
        # simplify it once
        simple_ac = self.simplify_ac(sddl)
        return simple_ac

    def simplify_ac(self, sddl) -> List[SimpleAce]:
        """Port of SddlAnalyser.SimplifyAC.

        Note the owner is emitted as a synthetic ACE with the single right
        `"Owner"` and no SID -- `FsAclAnalyser` and several analysers rely on that
        exact shape and on the literal right name.
        """
        simple_acl: List[SimpleAce] = []

        if getattr(sddl, "owner", None) is not None:
            alias = getattr(sddl.owner, "alias", None)
            if alias is not None and alias.strip():
                simple_acl.append(
                    SimpleAce(
                        ace_type=ACEType.Allow,
                        rights=["Owner"],
                        trustee=Trustee(display_name=alias),
                    )
                )

        dacl = getattr(sddl, "dacl", None)
        if dacl is not None:
            # PORT NOTE: deliberately NOT defensive. The C# reads
            # `sddl.Dacl.Aces.Length`, so an SDDL with an empty DACL section
            # (`...D:`), which parses to Dacl != null but Aces == null, throws a
            # NullReferenceException upstream. That propagates to GroupCon's
            # handler, so the setting (or, for a GPO's own descriptor, the whole
            # GPO) yields NO output. Substituting an empty list here would make
            # this port emit findings the original cannot, so we let the
            # equivalent TypeError escape.
            aces = dacl.aces
            if len(aces) > 0:
                for ace in aces:
                    simple_ace = SimpleAce(
                        trustee=Trustee(
                            display_name=getattr(ace.ace_sid, "alias", None),
                            sid=getattr(ace.ace_sid, "raw", None),
                        )
                    )
                    if ace.ace_type == "OBJECT_ACCESS_ALLOWED":
                        simple_ace.ace_type = ACEType.Allow
                    elif ace.ace_type == "OBJECT_ACCESS_DENIED":
                        simple_ace.ace_type = ACEType.Deny
                    else:
                        # The original's switch has no other cases and leaves the
                        # default enum value (Allow) in place.
                        pass

                    simple_ace.rights = self.simplify_rights(ace.rights)
                    simple_acl.append(simple_ace)

        return simple_acl

    def simplify_rights(self, rights) -> List[str]:
        """Port of SddlAnalyser.SimplifyRights."""
        # TODO actually simplify these? does it matter?
        return list(rights or [])

    # The original also contains a large commented-out `AssessSimpleAC` method
    # that scores ACEs against TrusteeOptions and attaches AceFindings. It is
    # commented out upstream, so it stays disabled here -- enabling it would add
    # findings the original does not produce.
